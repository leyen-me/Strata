"""serve/accounts.py - who may use this server: accounts, API keys and what each key used (opt-in).

The server has carried one shared API key since the first release (several, if the owner lists them), but a key belongs
to nobody and nothing records what it did.  This module adds the small amount of state a team needs instead: an account
per person, any number of keys per account, and one row per finished request, so the Keys tab of the web page can answer "this
is my key, this is what it used, and these are the others I made".

It is deliberately small: SQLite for the state, hashlib.scrypt for the password, and an HMAC-signed token (the same
claims a JWT carries, written here so that serving a model never needs another package).  Nothing here is on unless the
run config has an "accounts" block; without it the server behaves exactly as it did before.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}$")
MIN_PASSWORD = 8
KEY_PREFIX = "sk-strata-"
TOKEN_DAYS = 7
SCRYPT = (2 ** 14, 8, 1)          # n, r, p: ~16 MiB and ~40 ms on the machines this serves; enough for a shared key page


class AuthError(Exception):
    """A refused request: `status` is the HTTP code, `message` is what the page shows."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def default_db_path() -> Path:
    """Where the accounts live when the config names no "db": Strata's per-user state folder."""
    try:
        from strata_control import paths
        return paths.state_base() / "accounts.db"
    except Exception:                                   # noqa: BLE001 - serve must not fail over a path
        return Path.home() / ".local" / "state" / "strata" / "accounts.db"


class Accounts:
    """The whole store: users, keys, usage.  One SQLite file, one connection per operation (the server is threaded)."""

    def __init__(self, db_path: str | os.PathLike, *, allow_register: bool = True,
                 admins: tuple[str, ...] | list[str] = (), token_days: int = TOKEN_DAYS,
                 secret: str | None = None):
        self.path = Path(db_path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.allow_register = bool(allow_register)
        self.admins = {str(a).strip().lower() for a in admins if str(a).strip()}
        self.token_days = max(1, int(token_days))
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id         INTEGER PRIMARY KEY,
                    email      TEXT NOT NULL UNIQUE,
                    pw         TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    is_admin   INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS keys (
                    id           INTEGER PRIMARY KEY,
                    user_id      INTEGER NOT NULL REFERENCES users(id),
                    name         TEXT NOT NULL,
                    prefix       TEXT NOT NULL,
                    hash         TEXT NOT NULL UNIQUE,
                    created_at   REAL NOT NULL,
                    last_used_at REAL,
                    revoked_at   REAL,
                    secret       TEXT);
                CREATE TABLE IF NOT EXISTS usage (
                    id                INTEGER PRIMARY KEY,
                    key_id            INTEGER NOT NULL,
                    user_id           INTEGER NOT NULL,
                    ts                REAL NOT NULL,
                    path              TEXT,
                    model             TEXT,
                    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    ms                INTEGER,
                    status            INTEGER);
                CREATE INDEX IF NOT EXISTS usage_user_ts ON usage(user_id, ts);
                CREATE INDEX IF NOT EXISTS usage_key_ts  ON usage(key_id, ts);
                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            """)
        self.secret = secret or self._secret()
        self._last_seen: dict[int, float] = {}
        with self._conn() as c:                      # a database made before the text was kept grows one column
            if "secret" not in {r["name"] for r in c.execute("PRAGMA table_info(keys)")}:
                c.execute("ALTER TABLE keys ADD COLUMN secret TEXT")
        try:
            if os.name != "nt":
                os.chmod(self.path, 0o600)           # the file holds the keys' text now: its owner only
        except OSError:
            pass

    # ---- config ----------------------------------------------------------------------------------------------
    @classmethod
    def from_config(cls, block) -> Accounts | None:
        """The config's "accounts": true, or a block with "db", "allow_register", "admins", "token_days", "jwt_secret"."""
        if block is None or block is False:
            return None
        if block is True:
            block = {}
        if not isinstance(block, dict):
            raise AuthError(400, 'the config\'s "accounts" must be true or an object')
        if block.get("enabled") is False:
            return None
        return cls(block.get("db") or os.environ.get("STRATA_ACCOUNTS_DB") or default_db_path(),
                   allow_register=block.get("allow_register", True),
                   admins=block.get("admins") or (),
                   token_days=block.get("token_days") or TOKEN_DAYS,
                   secret=block.get("jwt_secret") or os.environ.get("STRATA_ACCOUNTS_SECRET"))

    # ---- storage ---------------------------------------------------------------------------------------------
    @contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=5000")
            yield c
            c.commit()
        finally:
            c.close()

    def _secret(self) -> str:
        """The token signing key: one made once and kept beside the accounts."""
        with self._conn() as c:
            row = c.execute("SELECT v FROM meta WHERE k='jwt_secret'").fetchone()
            if row:
                return row["v"]
            made = secrets.token_urlsafe(48)
            c.execute("INSERT INTO meta(k, v) VALUES('jwt_secret', ?)", (made,))
            return made

    # ---- passwords and tokens ---------------------------------------------------------------------------------
    def _hash_password(self, password: str) -> str:
        n, r, p = SCRYPT
        salt = secrets.token_bytes(16)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024)
        return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"

    def _verify_password(self, password: str, stored: str) -> bool:
        try:
            kind, n, r, p, salt, want = stored.split("$")
            if kind != "scrypt":
                return False
            dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                                dklen=len(bytes.fromhex(want)), maxmem=64 * 1024 * 1024)
            return hmac.compare_digest(dk.hex(), want)
        except (ValueError, TypeError):
            return False

    def token(self, user: dict) -> str:
        """A signed token for the page: {"sub", "email", "iat", "exp"}, HS256, the JWT shape without the package."""
        header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        now = int(time.time())
        claims = _b64e(json.dumps({"sub": str(user["id"]), "email": user["email"], "iat": now,
                                   "exp": now + self.token_days * 86400}, separators=(",", ":")).encode())
        sig = hmac.new(self.secret.encode(), f"{header}.{claims}".encode(), hashlib.sha256).digest()
        return f"{header}.{claims}.{_b64e(sig)}"

    def user_from_token(self, token: str) -> dict | None:
        try:
            header, claims, sig = (token or "").split(".")
            want = hmac.new(self.secret.encode(), f"{header}.{claims}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(_b64d(sig), want):
                return None
            data = json.loads(_b64d(claims))
            if int(data.get("exp") or 0) < time.time():
                return None
            return self._user(int(data["sub"]))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def _user(self, user_id: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT id, email, created_at, is_admin FROM users WHERE id=?", (user_id,)).fetchone()
            return self._user_dict(row) if row else None

    def _user_dict(self, row) -> dict:
        return {"id": row["id"], "email": row["email"], "created_at": row["created_at"],
                "is_admin": bool(row["is_admin"]) or row["email"] in self.admins}

    # ---- accounts ---------------------------------------------------------------------------------------------
    def register(self, email: str, password: str) -> tuple[dict, str]:
        email = (email or "").strip().lower()
        if not EMAIL.match(email):
            raise AuthError(400, "that is not an email address")
        if len(password or "") < MIN_PASSWORD:
            raise AuthError(400, f"the password needs at least {MIN_PASSWORD} characters")
        if not self.allow_register:
            raise AuthError(403, "this server does not take new accounts; ask its owner for a key")
        now = time.time()
        with self._conn() as c:
            try:
                cur = c.execute("INSERT INTO users(email, pw, created_at, is_admin) VALUES(?,?,?,?)",
                                (email, self._hash_password(password), now, 1 if email in self.admins else 0))
            except sqlite3.IntegrityError:
                raise AuthError(409, "an account already uses that email") from None
            user = {"id": cur.lastrowid, "email": email, "created_at": now, "is_admin": email in self.admins}
        return user, self.token(user)

    def login(self, email: str, password: str) -> tuple[dict, str]:
        email = (email or "").strip().lower()
        with self._conn() as c:
            row = c.execute("SELECT id, email, pw, created_at, is_admin FROM users WHERE email=?", (email,)).fetchone()
        if not row or not self._verify_password(password or "", row["pw"]):
            raise AuthError(401, "wrong email or password")
        user = self._user_dict(row)
        return user, self.token(user)

    # ---- keys -------------------------------------------------------------------------------------------------
    def issue_key(self, user_id: int, name: str = "") -> dict:
        plain = KEY_PREFIX + secrets.token_urlsafe(32)
        now = time.time()
        with self._conn() as c:
            cur = c.execute("INSERT INTO keys(user_id, name, prefix, hash, created_at, secret) VALUES(?,?,?,?,?,?)",
                            (user_id, (name or "").strip()[:64], plain[:16], hashlib.sha256(plain.encode()).hexdigest(),
                             now, plain))
            key_id = cur.lastrowid
        return {"id": key_id, "name": (name or "").strip()[:64], "prefix": plain[:16],
                "created_at": now, "key": plain}

    def keys(self, user_id: int) -> list[dict]:
        """This account's keys, each with its text: the page shows them to the owner who is signed in here.

        The hash in `hash` is what /v1 checks; `secret` is kept so that Copy and Use work in any browser, not only the
        one that made the key. A key made before the column existed has no text and shows only its prefix."""
        with self._conn() as c:
            rows = c.execute("""SELECT id, name, prefix, created_at, last_used_at, revoked_at, secret
                                FROM keys WHERE user_id=? ORDER BY id""", (user_id,)).fetchall()
        return [{"id": r["id"], "name": r["name"], "prefix": r["prefix"] + "…", "created_at": r["created_at"],
                 "last_used_at": r["last_used_at"], "revoked": bool(r["revoked_at"]), "key": r["secret"]}
                for r in rows]

    def revoke(self, user_id: int, key_id: int) -> bool:
        with self._conn() as c:
            cur = c.execute("UPDATE keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL",
                            (time.time(), int(key_id), user_id))
        return cur.rowcount > 0

    def check_key(self, plain: str) -> dict | None:
        """The key's owner, or None: what every /v1 request asks before it reaches the model."""
        if not plain:
            return None
        digest = hashlib.sha256(plain.encode()).hexdigest()
        with self._conn() as c:
            row = c.execute("""SELECT k.id, k.user_id, u.email, u.is_admin, k.revoked_at
                               FROM keys k JOIN users u ON u.id = k.user_id WHERE k.hash=?""", (digest,)).fetchone()
            if not row or row["revoked_at"]:
                return None
            now = time.time()
            if now - self._last_seen.get(row["id"], 0.0) > 5:      # one write per key per 5 s, not per request
                c.execute("UPDATE keys SET last_used_at=? WHERE id=?", (now, row["id"]))
                self._last_seen[row["id"]] = now
        return {"key_id": row["id"], "user_id": row["user_id"], "email": row["email"],
                "is_admin": bool(row["is_admin"]) or row["email"] in self.admins}

    # ---- usage ------------------------------------------------------------------------------------------------
    def note_usage(self, key_id: int, user_id: int, *, path: str = "", model: str = "",
                   prompt_tokens: int | None = None, completion_tokens: int | None = None,
                   ms: int | None = None, status: int = 200) -> None:
        """One row per finished request.  Missing counts are stored as 0: a request that died still happened."""
        with self._conn() as c:
            c.execute("""INSERT INTO usage(key_id, user_id, ts, path, model, prompt_tokens, completion_tokens, ms, status)
                         VALUES(?,?,?,?,?,?,?,?,?)""",
                      (key_id, user_id, time.time(), path[:64], (model or "")[:128],
                       max(0, int(prompt_tokens or 0)), max(0, int(completion_tokens or 0)),
                       int(ms) if ms is not None else None, int(status)))

    def usage(self, user_id: int, days: int = 30) -> dict:
        since = time.time() - max(1, int(days)) * 86400
        with self._conn() as c:
            totals = c.execute("""SELECT COUNT(*) n, COALESCE(SUM(prompt_tokens),0) p, COALESCE(SUM(completion_tokens),0) c
                                  FROM usage WHERE user_id=? AND ts>=?""", (user_id, since)).fetchone()
            keys = c.execute("""SELECT k.id, k.name, k.prefix, k.created_at, k.last_used_at, k.revoked_at,
                                       COUNT(u.id) n, COALESCE(SUM(u.prompt_tokens),0) p, COALESCE(SUM(u.completion_tokens),0) c
                                FROM keys k LEFT JOIN usage u ON u.key_id=k.id AND u.ts>=?
                                WHERE k.user_id=? GROUP BY k.id ORDER BY k.id""", (since, user_id)).fetchall()
            days_rows = c.execute("""SELECT date(ts,'unixepoch','localtime') d, COUNT(*) n,
                                            COALESCE(SUM(prompt_tokens),0) p, COALESCE(SUM(completion_tokens),0) c
                                     FROM usage WHERE user_id=? AND ts>=? GROUP BY d ORDER BY d""",
                                  (user_id, since)).fetchall()
        return {
            "since": since, "days": int(days),
            "totals": {"requests": totals["n"], "prompt_tokens": totals["p"], "completion_tokens": totals["c"]},
            "keys": [{"id": r["id"], "name": r["name"], "prefix": r["prefix"] + "…", "created_at": r["created_at"],
                      "last_used_at": r["last_used_at"], "revoked": bool(r["revoked_at"]), "requests": r["n"],
                      "prompt_tokens": r["p"], "completion_tokens": r["c"]} for r in keys],
            "by_day": [{"day": r["d"], "requests": r["n"], "prompt_tokens": r["p"],
                        "completion_tokens": r["c"]} for r in days_rows],
        }

    def overview(self) -> dict:
        """The owner's view: every account and what it used (the page shows it to "admins" only)."""
        since = time.time() - 30 * 86400
        with self._conn() as c:
            rows = c.execute("""SELECT u.id, u.email, u.created_at,
                                       (SELECT COUNT(*) FROM keys k WHERE k.user_id=u.id AND k.revoked_at IS NULL) keys,
                                       (SELECT COUNT(*) FROM usage z WHERE z.user_id=u.id AND z.ts>=?) reqs,
                                       (SELECT COALESCE(SUM(prompt_tokens),0) FROM usage z WHERE z.user_id=u.id AND z.ts>=?) p,
                                       (SELECT COALESCE(SUM(completion_tokens),0) FROM usage z WHERE z.user_id=u.id AND z.ts>=?) c
                                FROM users u ORDER BY u.id""", (since, since, since)).fetchall()
        return {"users": [{"id": r["id"], "email": r["email"], "created_at": r["created_at"], "keys": r["keys"],
                           "requests": r["reqs"], "prompt_tokens": r["p"], "completion_tokens": r["c"]}
                          for r in rows]}


def usage_tokens(item) -> tuple[int | None, int | None]:
    """(prompt, completion) from one streamed or non-streamed item of any of the three APIs, or (None, None).

    OpenAI says prompt_tokens/completion_tokens; Anthropic and the Responses API say input_tokens/output_tokens; a
    streamed Responses item keeps its usage inside "response".  An item that carries neither is not a usage event."""
    if not isinstance(item, dict):
        return None, None
    usage = item.get("usage")
    if not isinstance(usage, dict) and isinstance(item.get("response"), dict):
        usage = item["response"].get("usage")
    if not isinstance(usage, dict):
        return None, None
    prompt = usage.get("prompt_tokens", usage.get("input_tokens"))
    completion = usage.get("completion_tokens", usage.get("output_tokens"))
    if prompt is None and completion is None:
        return None, None
    return (int(prompt) if prompt is not None else None), (int(completion) if completion is not None else None)

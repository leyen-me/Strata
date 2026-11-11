"""serve/test_accounts.py - the opt-in account page: sign up, make a key, and what the key used.

    python -m unittest serve.test_accounts -v
"""
from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from serve.accounts import Accounts, AuthError, usage_tokens
from serve.frontend import ChatTemplate
from serve.server import ByteTokenizer, MockEngine, Service, serve

ROOT = Path(__file__).resolve().parents[1]


class Store(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.accounts = Accounts(Path(self.dir.name) / "accounts.db", admins=["boss@example.com"])

    def tearDown(self):
        self.dir.cleanup()

    def test_register_login_and_token(self):
        user, token = self.accounts.register("a@example.com", "longenough")
        self.assertEqual(user["email"], "a@example.com")
        self.assertFalse(user["is_admin"])
        self.assertEqual(self.accounts.user_from_token(token)["id"], user["id"])
        same, token2 = self.accounts.login("A@Example.com ", "longenough")
        self.assertEqual(same["id"], user["id"])
        self.assertEqual(self.accounts.user_from_token(token2)["id"], user["id"])

    def test_password_and_email_rules(self):
        with self.assertRaises(AuthError) as e:
            self.accounts.register("not-an-email", "longenough")
        self.assertEqual(e.exception.status, 400)
        with self.assertRaises(AuthError) as e:
            self.accounts.register("b@example.com", "short")
        self.assertEqual(e.exception.status, 400)
        self.accounts.register("b@example.com", "longenough")
        with self.assertRaises(AuthError) as e:
            self.accounts.register("B@example.com", "longenough")
        self.assertEqual(e.exception.status, 409)
        with self.assertRaises(AuthError) as e:
            self.accounts.login("b@example.com", "wrongones")
        self.assertEqual(e.exception.status, 401)

    def test_the_owner_is_an_admin_from_the_config(self):
        user, _ = self.accounts.register("boss@example.com", "longenough")
        self.assertTrue(user["is_admin"])
        user, _ = self.accounts.register("other@example.com", "longenough")
        self.assertFalse(user["is_admin"])

    def test_tokens_expire_and_tampering_is_refused(self):
        user, token = self.accounts.register("c@example.com", "longenough")
        head, claims, sig = token.split(".")
        self.assertIsNone(self.accounts.user_from_token(f"{head}.{claims}.{'A' * len(sig)}"))
        self.assertIsNone(self.accounts.user_from_token("not a token"))
        self.assertIsNone(self.accounts.user_from_token(""))
        short = Accounts(self.accounts.path, token_days=1)
        self.assertIsNotNone(short.user_from_token(token))           # the same secret file signs both

    def test_keys_can_be_read_again_by_their_owner(self):
        user, _ = self.accounts.register("d@example.com", "longenough")
        made = self.accounts.issue_key(user["id"], "laptop")
        self.assertTrue(made["key"].startswith("sk-strata-"))
        self.assertEqual(self.accounts.check_key(made["key"])["user_id"], user["id"])
        listed = self.accounts.keys(user["id"])
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["key"], made["key"])             # Copy and Use work in any browser
        self.assertEqual(listed[0]["prefix"], made["key"][:16] + "…")
        self.assertTrue(self.accounts.revoke(user["id"], made["id"]))
        self.assertIsNone(self.accounts.check_key(made["key"]))
        self.assertFalse(self.accounts.revoke(user["id"], made["id"]))   # already revoked
        self.assertIsNone(self.accounts.check_key("sk-strata-nope"))

    def test_one_account_never_sees_another_accounts_keys(self):
        one, _ = self.accounts.register("g1@example.com", "longenough")
        two, _ = self.accounts.register("g2@example.com", "longenough")
        made = self.accounts.issue_key(one["id"], "mine")
        self.assertEqual(self.accounts.keys(two["id"]), [])
        self.assertEqual(self.accounts.keys(one["id"])[0]["key"], made["key"])

    def test_another_account_cannot_revoke_my_key(self):
        one, _ = self.accounts.register("e@example.com", "longenough")
        two, _ = self.accounts.register("f@example.com", "longenough")
        made = self.accounts.issue_key(one["id"], "mine")
        self.assertFalse(self.accounts.revoke(two["id"], made["id"]))
        self.assertIsNotNone(self.accounts.check_key(made["key"]))

    def test_usage_adds_up_per_key_and_per_day(self):
        user, _ = self.accounts.register("g@example.com", "longenough")
        key = self.accounts.issue_key(user["id"], "ci")
        other = self.accounts.issue_key(user["id"], "laptop")
        self.accounts.note_usage(key["id"], user["id"], path="/v1/chat/completions", model="m",
                                 prompt_tokens=100, completion_tokens=20, ms=500)
        self.accounts.note_usage(key["id"], user["id"], prompt_tokens=50, completion_tokens=5)
        self.accounts.note_usage(other["id"], user["id"], prompt_tokens=7, completion_tokens=3)
        usage = self.accounts.usage(user["id"], 30)
        self.assertEqual(usage["totals"], {"requests": 3, "prompt_tokens": 157, "completion_tokens": 28})
        self.assertEqual([k["requests"] for k in usage["keys"]], [2, 1])
        self.assertEqual(sum(d["requests"] for d in usage["by_day"]), 3)
        self.assertEqual(usage["by_day"][-1]["completion_tokens"], 28)

    def test_the_owner_sees_every_account(self):
        one, _ = self.accounts.register("h@example.com", "longenough")
        self.accounts.issue_key(one["id"], "x")
        self.accounts.note_usage(1, one["id"], prompt_tokens=5, completion_tokens=6)
        rows = {u["email"]: u for u in self.accounts.overview()["users"]}
        self.assertEqual(rows["h@example.com"]["keys"], 1)
        self.assertEqual(rows["h@example.com"]["requests"], 1)
        self.assertEqual(rows["h@example.com"]["prompt_tokens"], 5)

    def test_usage_of_the_three_apis(self):
        self.assertEqual(usage_tokens({"usage": {"prompt_tokens": 3, "completion_tokens": 4}}), (3, 4))
        self.assertEqual(usage_tokens({"usage": {"input_tokens": 5, "output_tokens": 6}}), (5, 6))
        self.assertEqual(usage_tokens({"response": {"usage": {"input_tokens": 7, "output_tokens": 8}}}), (7, 8))
        self.assertEqual(usage_tokens({"choices": []}), (None, None))
        self.assertEqual(usage_tokens(None), (None, None))


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        tok = ByteTokenizer()
        engine = MockEngine(tok, "</think>\n\nHello from the mock engine.", max_context=4096)
        cls.svc = Service(engine, tok, ChatTemplate(ROOT / "serve/chat_template.jinja"))
        cls.svc.accounts = Accounts(Path(cls.dir.name) / "accounts.db", admins=["boss@example.com"])
        cls.httpd = serve(cls.svc, port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.dir.cleanup()

    def call(self, path, body=None, method=None, key=None, token=None):
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = "Bearer " + key
        if token:
            headers["Authorization"] = "Bearer " + token
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def signed_in(self, email="user@example.com"):
        status, out = self.call("/account/register", {"email": email, "password": "longenough"}, method="POST")
        self.assertEqual(status, 200, out)
        return out["token"], out["user"]

    def test_a_key_is_needed_once_accounts_are_on(self):
        self.assertEqual(self.call("/v1/models")[0], 401)
        token, user = self.signed_in()
        status, made = self.call("/account/keys", {"name": "laptop"}, method="POST", token=token)
        self.assertEqual(status, 200, made)
        self.assertEqual(self.call("/v1/models")[0], 401)                  # the key is not an account token
        self.assertEqual(self.call("/v1/models", key=made["key"]["key"])[0], 200)

    def test_the_page_and_its_session(self):
        token, user = self.signed_in("page@example.com")
        status, me = self.call("/account/me", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(me["user"]["email"], "page@example.com")
        self.assertEqual(self.call("/account/me")[0], 401)
        self.assertEqual(self.call("/account/me", token="broken.token.here")[0], 401)
        self.assertEqual(self.call("/account/keys", token=token)[0], 200)
        # the Keys tab is a page of the chat UI, with no route of its own; its script is served like the others
        with urllib.request.urlopen(self.base + "/", timeout=10) as r:
            html = r.read()
        self.assertIn(b"view-keys", html)
        with urllib.request.urlopen(self.base + "/web/keys.js", timeout=10) as r:
            self.assertIn(b"showTab", r.read())
        self.assertEqual(self.call("/account")[0], 404)

    def test_a_chat_request_records_what_the_key_used(self):
        token, user = self.signed_in("usage@example.com")
        _, made = self.call("/account/keys", {"name": "meter"}, method="POST", token=token)
        key = made["key"]["key"]
        status, answer = self.call("/v1/chat/completions",
                                   {"model": "strata", "messages": [{"role": "user", "content": "hi"}],
                                    "max_tokens": 8}, key=key)
        self.assertEqual(status, 200, answer)
        _, usage = self.call("/account/usage?days=1", token=token)
        self.assertEqual(usage["totals"]["requests"], 1)
        self.assertGreaterEqual(usage["totals"]["prompt_tokens"], 1)
        self.assertGreaterEqual(usage["totals"]["completion_tokens"], 1)
        self.assertEqual(usage["keys"][0]["requests"], 1)

    def test_registration_can_be_closed_and_the_owner_sees_the_ledger(self):
        token, user = self.signed_in("boss@example.com")
        _, made = self.call("/account/keys", {"name": "k"}, method="POST", token=token)
        self.call("/v1/chat/completions", {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 4},
                  key=made["key"]["key"])
        status, out = self.call("/account/overview", token=token)
        self.assertEqual(status, 200, out)
        self.assertIn("boss@example.com", [u["email"] for u in out["users"]])
        other, _ = self.signed_in("plain@example.com")
        self.assertEqual(self.call("/account/overview", token=other)[0], 404)
        self.svc.accounts.allow_register = False
        try:
            status, err = self.call("/account/register", {"email": "later@example.com", "password": "longenough"},
                                    method="POST")
        finally:
            self.svc.accounts.allow_register = True          # the other tests still make accounts
        self.assertEqual(status, 403)
        self.assertIn("does not take new accounts", err["error"]["message"])


class Off(unittest.TestCase):
    def test_without_the_config_block_nothing_changes(self):
        self.assertIsNone(Accounts.from_config(None))
        self.assertIsNone(Accounts.from_config(False))
        self.assertIsNone(Accounts.from_config({"enabled": False}))


if __name__ == "__main__":
    unittest.main()

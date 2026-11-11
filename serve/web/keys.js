/* The Keys tab (serve/web/index.html): sign in, make an API key, revoke one.
   Same plain style as the rest of serve/web. The session token is the server's HS256 token, kept in this browser. */
"use strict";

const ACCOUNT_TOKEN = "strata.account.token";
let accountToken = "";
try { accountToken = localStorage.getItem(ACCOUNT_TOKEN) || ""; } catch (e) { accountToken = ""; }
let accountUser = null;
let accountCreating = false;
let justCreated = 0;          // the key made a moment ago: its whole text is shown in its row, this visit only

function accountSaveToken(value) {
  accountToken = value || "";
  try { value ? localStorage.setItem(ACCOUNT_TOKEN, value) : localStorage.removeItem(ACCOUNT_TOKEN); } catch (e) {}
}

async function accountApi(path, options = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  if (accountToken) headers.Authorization = "Bearer " + accountToken;
  const res = await fetch(path, Object.assign({}, options, { headers }));
  let body = {};
  try { body = await res.json(); } catch (e) { body = {}; }
  if (!res.ok) {
    const message = (body.error && body.error.message) || ("HTTP " + res.status);
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }
  return body;
}

function accountWhen(seconds) {
  return seconds ? new Date(seconds * 1000).toLocaleString() : "–";
}

function showSignedIn(user) {
  accountUser = user;
  $("account-email").textContent = user.email.length > 22 ? user.email.slice(0, 20) + "…" : user.email;
  $("account-wrap").hidden = false;
  $("signin-btn").hidden = true;
  $("keys-auth-card").hidden = true;
  $("keys-card").hidden = false;
}

function showSignedOut() {
  accountUser = null;
  accountSaveToken("");
  $("account-wrap").hidden = true;
  $("signin-btn").hidden = false;
  $("keys-card").hidden = true;
  $("keys-auth-card").hidden = false;
  accountRenderAuthMode();
}

function accountRenderAuthMode() {
  $("keys-auth-title").textContent = accountCreating ? "Create an account" : "Sign in";
  $("keys-auth-submit").textContent = accountCreating ? "Create account" : "Sign in";
  $("keys-auth-switch").textContent = accountCreating ? "I already have an account" : "Create an account";
  $("keys-password").autocomplete = accountCreating ? "new-password" : "current-password";
}

async function loadKeys() {
  const { keys } = await accountApi("account/keys");
  const body = $("keys-list");
  body.textContent = "";
  if (!keys.length) {
    body.innerHTML = '<tr><td colspan="5" class="muted">No keys yet.</td></tr>';
    return;
  }
  for (const k of keys) {
    const tr = document.createElement("tr");
    const plain = k.key || null;                       // the server keeps the text for its owner, so any valid key copies
    const keyCell = document.createElement("td");
    keyCell.className = plain && k.id === justCreated ? "keys-plain" : "";
    keyCell.textContent = plain && k.id === justCreated ? plain : k.prefix;
    if (plain && k.id !== justCreated) keyCell.title = "Copy or Use it from the actions";
    const nameCell = document.createElement("td");
    nameCell.textContent = k.name || "(no name)";
    tr.append(nameCell, keyCell);
    for (const value of [accountWhen(k.created_at), accountWhen(k.last_used_at)]) {
      const td = document.createElement("td");
      td.textContent = value;
      tr.append(td);
    }
    const actions = document.createElement("td");
    actions.className = "keys-row-actions";
    const button = (text, run, enabled = true, why = "") => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "st-btn st-btn--secondary";
      b.textContent = text;
      b.disabled = !enabled;
      if (why) b.title = why;
      b.onclick = run;
      return b;
    };
    const madeHere = "This key was made before the server kept its text: make a new one to copy or use it";
    const copy = button("Copy", async () => {
      try { await navigator.clipboard.writeText(plain); copy.textContent = "Copied"; }
      catch (e) { copy.textContent = "Select it"; }
    }, !!plain && !k.revoked, k.revoked ? "This key is revoked" : madeHere);
    const use = button("Use", () => { setApiKey(plain); use.textContent = "In use"; },
                       !!plain && !k.revoked, k.revoked ? "This key is revoked" : madeHere);
    const revoke = button("Revoke", async () => {
      if (!confirm("Revoke “" + (k.name || k.prefix) + "”? Clients using it stop working at once.")) return;
      try {
        await accountApi("account/keys/revoke", { method: "POST", body: JSON.stringify({ id: k.id }) });
        loadKeys();
      } catch (e) { $("keys-err").textContent = e.message; }
    }, !k.revoked, "This key is already revoked");
    actions.append(copy, use, revoke);
    tr.append(actions);
    body.append(tr);
  }
}

// called by app.js once /health says this server has accounts
async function initAccount() {
  if (!accountToken) {
    showSignedOut();
    showTab("keys");                                   // nobody is signed in: say so instead of waiting for a 401
    return;
  }
  try {
    const out = await accountApi("account/me");
    showSignedIn(out.user);
    await loadKeys();
  } catch (e) {
    showSignedOut();
    if (e.status !== 401) $("keys-auth-err").textContent = e.message;
    showTab("keys");
  }
}

// app.js calls this when a chat request comes back 401: the session is gone or was never made
function needSignIn() {
  if (!health || !health.accounts) return;
  if (!accountToken) { showSignedOut(); showTab("keys"); return; }
  accountApi("account/me").catch(() => { showSignedOut(); showTab("keys"); });
}

function renderKeys() {
  if (!health || !health.accounts) return;
  if (accountUser) loadKeys().catch((e) => { $("keys-err").textContent = e.message; });
}

// ---- the header: the signed-in email, its menu on hover, and Sign out --------------------------------------------
let accountMenuTimer = 0;
function accountMenu(open) {
  clearTimeout(accountMenuTimer);
  $("account-menu").hidden = !open;
  $("account-chip").setAttribute("aria-expanded", String(open));
}
function accountMenuSoon(open) {                       // a short delay: the pointer can cross from chip to menu
  clearTimeout(accountMenuTimer);
  accountMenuTimer = setTimeout(() => accountMenu(open), open ? 0 : 220);
}
$("account-wrap").addEventListener("mouseenter", () => accountMenuSoon(true));
$("account-wrap").addEventListener("mouseleave", () => accountMenuSoon(false));
$("account-wrap").addEventListener("focusin", () => accountMenuSoon(true));
$("account-wrap").addEventListener("focusout", () => accountMenuSoon(false));
$("account-chip").onclick = () => accountMenu($("account-menu").hidden);
$("account-chip").onkeydown = (e) => {
  if (e.key === "Escape") accountMenu(false);
  if (e.key === "ArrowDown") { accountMenu(true); $("account-menu-keys").focus(); }
};
$("account-menu").onkeydown = (e) => { if (e.key === "Escape") accountMenu(false); };
$("account-menu-keys").onclick = () => { accountMenu(false); showTab("keys"); };
$("signout-btn").onclick = () => { accountMenu(false); showSignedOut(); };
$("signin-btn").onclick = () => { showSignedOut(); showTab("keys"); $("keys-email").focus(); };

// ---- the Keys tab -----------------------------------------------------------------------------------------------
$("keys-auth-switch").onclick = () => {
  accountCreating = !accountCreating;
  accountRenderAuthMode();
  $("keys-auth-err").textContent = "";
};
$("keys-auth-form").onsubmit = async (event) => {
  event.preventDefault();
  $("keys-auth-err").textContent = "";
  $("keys-auth-submit").disabled = true;
  try {
    const body = { email: $("keys-email").value.trim(), password: $("keys-password").value };
    const out = await accountApi(accountCreating ? "account/register" : "account/login",
                                 { method: "POST", body: JSON.stringify(body) });
    accountSaveToken(out.token);
    $("keys-password").value = "";
    showSignedIn(out.user);
    await loadKeys();
  } catch (e) {
    $("keys-auth-err").textContent = e.message;
  } finally {
    $("keys-auth-submit").disabled = false;
  }
};

$("keys-form").onsubmit = async (event) => {
  event.preventDefault();
  $("keys-err").textContent = "";
  try {
    const out = await accountApi("account/keys", { method: "POST", body: JSON.stringify({ name: $("keys-name").value.trim() }) });
    $("keys-name").value = "";
    justCreated = out.key.id;
    await loadKeys();
  } catch (e) { $("keys-err").textContent = e.message; }
};

accountRenderAuthMode();

# Phase 3 — Firmware JavaScript Analysis, SCRAM Verification & Read-Only API Validation

Branch: `phase-3-js-analysis`
Scope of this phase: **strictly offline**. No live-modem connection was opened; no login POST,
scan, band/cell write or any state-changing request was executed. All HTTP-dependent behavior is
mocked; all live evidence is inherited from the Phase 1 read-only session (commit `2836f65 data`)
and the working-tree copy of the same sanitized files.

---

## 1. Files inspected

| File (working tree) | Origin | Inspected for |
|---|---|---|
| `evidence/raw/js__js_main.js_r_1709723942` | `data` commit (2836f65), = device `/js/main.js` | endpoint map, login flow, token pool, chunk loader, write-token RSA path |
| `evidence/raw/lib_emui-crypto.js` | `data` commit, = `/lib/emui-crypto.js` (355,327 B) | SCRAM implementation (source, line 7558), jsrsasign RSA |
| `evidence/raw/chunk_common.js` | working tree (was fetchable unauthenticated) | store actions (`getToken`), guide-web login component |
| `evidence/raw/chunk_guide.js` | `data` commit | setup wizard; confirms `converged-status` GET is used pre-login |
| `evidence/raw/chunk_login.js` | `data` commit | login page composition |
| `evidence/raw/_api_user_state-login.xml` | Phase 1 probe (redacted) | `rsapadingtype=1`, `password_type=4`, `State=-1`, `accounts_number=2` |
| `evidence/raw/_root_session.html`, `_html_index.html` | Phase 1 probe (redacted) | asset load order: vue/vuex/axios/element-plus/echarts/**emui-crypto**+**main.js**; fresh `csrf_token` metas per page load |
| Phase 2 code (`src/huawei_tower/…`, `tests/`, `tools/probe.py`) | commit `b665ac9` (moved into working-tree root) | allowlist, gates, SCRAM stub, tests |

Administrative page chunks (`celllock`, `lockband`, `mobilesearch`, `mobilenetwork`, `networkmode`,
`onekey`, `home`) were **never retrievable** without a session: unauthenticated fetches return
HTTP 200 with body `<?xml version="1.0" encoding="UTF-8"?><error><code>100003</code><message/></error>`
(`text/xml`). This is preserved as-is; their internals remain unknown in this phase.

> The main.js and common.js files are minified into 1–2 lines; full line numbers are not
> meaningful for them. Symbols below are quoted verbatim and their reproducibility was checked by
> regex search across the exact bytes of the committed files.

## 2. Authentication flow — verified end-to-end (code-backed)

### 2.1 Trigger chain (`main.js`)

1. Login page mounts → store `monitoringStatus` GET + `getToken` dispatch.
2. `getToken` action (`main.js`, verbatim):
   `commonGet({"name": "getToken"}) → r.response.token.substr(32)` → `SET_TOKENS`.
   So `/api/webserver/token` returns a **64-char** token and the app stores **only `substr(32)`**
   (the second half). The first half is discarded by design. (Implemented will need the same
   truncation; do NOT treat the full token as the CSRF value.)
3. `GET /api/monitoring/status` (pre-login) is issued once by the login page and carries the
   special header `Update-Cookie: UpdateCookie` (verbatim:
   `"/api/monitoring/status"===s&&(u["Update-Cookie"]="UpdateCookie")`).
   This is the *only* GET in the whole UI with a non-default header. Its server-side effect is
   not documented anywhere in the JS — classified plausible-read-only/unknown, still gated.
4. The submit path lands in `N()` (verbatim anchors: `CryptoJS.SCRAM().nonce().toString()`,
   `{username: x.userName, firstnonce: e, mode: 1}`), then `commonPost user_challenge_login`.

### 2.2 SCRAM primitives (`lib_emui-crypto.js`, line 7558 — minified-friendly source)

```js
c = n.SCRAM = o.extend({cfg: o.extend({keySize: 8, hasher: i /*SHA256*/, hmac: s /*HmacSHA256*/}),
  nonce: function(){ return lastNonce = r.random(4 * this.cfg.keySize), lastNonce },
  saltedPassword: function(e, t, r){ return CryptoJS.PBKDF2(e, t, {keySize: this.cfg.keySize, iterations: r, hasher: this.cfg.hasher}) },
  clientKey: function(e){ return this.cfg.hmac(e, "Client Key") },
  serverKey: function(e){ return this.cfg.hmac(e, "Server Key") },
  storedKey: function(e){ var t = this.cfg.hasher.create(); return t.update(e), t.finalize() },
  signature: function(e, t){ return this.cfg.hmac(e, t) },
  clientProof: function(e, t, r, n){
      var i = this.saltedPassword(e, t, r), s = this.clientKey(i), o = this.storedKey(s),
          c = this.signature(o, n);
      for (var a = 0; a < s.sigBytes / 4; a += 1) s.words[a] = s.words[a] ^ c.words[a];
      return s.toString() },
  serverProof: function(e, t, r, n){
      var i = this.saltedPassword(e, t, r), s = this.serverKey(i);
      return this.signature(s, n).toString() }});
e.SCRAM = function(e){ return c.create(e) }
```

In CryptoJS, `HmacSHA256(message, key)` — the shortcut's **first** argument is the message.
Therefore:

| Primitive | Actual computation |
|---|---|
| `nonce()` | 32 random bytes → lowercase hex (64 chars) |
| `saltedPassword(pw, salt, iters)` | PBKDF2-HMAC-SHA256, dkLen **32**, salt = raw bytes from hex |
| `clientKey(km)` | HMAC(**key="Client Key"**, msg=km) — string label is the HMAC key |
| `serverKey(km)` | HMAC(**key="Server Key"**, msg=km) |
| `storedKey(ck)` | plain SHA-256 |
| `signature(e, t)` | HMAC(**key=arg2**, msg=arg1) — *swapped vs standard SCRAM* |
| `clientProof` | `clientKey ⊕ signature(storedKey(clientKey), authMessage)` |
| `serverProof` | `signature(serverKey, authMessage)` |

### 2.3 Login exchange (`main.js` `N()` + inner closure — verbatim anchors)

```
firstnonce = SCRAM().nonce().toString()
POST /api/user/challenge_login   {username, firstnonce, mode: 1}      # + loginflag "2" only on developermode route
← <salt><hex>, <iterations>, <servernonce>[, <newType>1, <newSalt>, <newIterations>]

authMessage = firstnonce + "," + servernonce + "," + servernonce        # servernonce TWICE (verified text)
u = saltedPassword(password, Hex.parse(salt), iterations).toString()    # 64 hex chars
p = serverKey(Hex.parse(u)).toString()
f = clientProof(password, Hex.parse(salt), iterations, authMessage).toString()
d = {clientproof: f, finalnonce: servernonce}
if newType === "1":
    g = saltedPassword(password, Hex.parse(newSalt), newIterations).toString()
    v = storedKey(clientKey(Hex.parse(g))).toString()                   # newStoredKey
    b = serverKey(Hex.parse(g)).toString()                             # newServerKey
    d.hashOldNewPwd = SHA256(v + b + f).toString()   # ASCII concatenation of the hex strings
POST /api/user/authentication_login  d
← {rsan, rsae, serversignature, rsapubkeysignature}
verified when serversignature === serverProof(...).toString()
         AND rsapubkeysignature === signature(Hex.parse(rsan), Hex.parse(p)).toString()   # key=p(serverKey bytes), msg=rsan bytes
→ I(rsan, rsae)  # localStorage "n"/"e" — keys for subsequent RSA token encryption
```

### 2.4 Token / transport machinery (`main.js` axios install + `k()`/`E()`/`S()` + `x()`)

- GET wrapper: `axios GET` with headers `_ResponseSource:"Broswer"`, `Accept:*/*`, default 30 s
  timeout; special-cases:
  - `'/api/wlan/multi-basic-settings' !== s && '/api/wlan/basic-settings' !== s || (u["Login-Type"]="Scram")`
  - `'/api/monitoring/status' === s && (u["Update-Cookie"]="UpdateCookie")`
- POST wrapper: `Content-Type: application/x-www-form-urlencoded; charset=UTF-8` (XML body
  `<?xml version="1.0" encoding="UTF-8"?>` + `jsonToXml("request", data)`), header
  `__RequestVerificationToken` taken **FIFO** from the local token pool (`m.splice(0,1)`,
  `SET_TOKENS`); pool refilled by `k()` from response headers named
  `__RequestVerificationTokenone` / `__RequestVerificationTokentwo` (or the singular forms).
- The **write** token nonce: function `x(t)` (a.k.a. `doRSAEncrypt`) — RSA-encrypts a session
  material string with `RSAKey.setPublic(n, e)`, chunked by `(n.length/2 − 11)` (PKCS#1 v1.5) or
  `(n.length/2 − 42)` with `encryptOAEP` when `rsapadingtype === "1"` (this device), result
  concatenated hex→ base64-ish string used as `__RequestVerificationToken` nonce.
  `b()` lives in `localStorage("n").localStorage("e")`; fallback for HTTPS-only apps stores via
  `window.name = "...[rsa_n=...&rsa_e=...]"`.
- Extra RSA fetch observed only for `classify !== "hilink"` paths (#`webServerPublicKey`
  `encpubkeyn` / `encpubkeye` — not the H158-381 `hilink` branch).
- An AES-CBC "SCRAM-encrypted" channel exists for select endpoints
  (`smsListPhone`, `newContact`, phonebook edits): `x()` RSA + `E()` AES decrypt. Not needed
  for status reads; kept as an unimplemented note for future SMS features.

### 2.5 Admin chunk loader (evidence for ID-D downloader)

`i.p = "../"` (public path) and:
`src = i.p + "js/" + ({0:"common", 5:"login", 19:"celllock-celllock-vue", 45:"lockband",
52:"mobilesearch-mobilesearch-vue", 55:"mobilenetwork-mobilenetwork-vue", 57:"networkmode",
37:"guide", 39:"home-home-vue", 25:"developermode", ...}[e] || e) + ".js"` (verbatim map keys —
the loader math `''+[chunkId]` makes IDs 114][.. widgets like 37 "guide" reachable at
`/js/guide.js` etc.). CSS analog at `/css/<name>.css`. Root page loads `/lib/*` statically
(vue, vuex, vue-router, axios, element-plus x2, echarts, **emui-crypto.js**, devicemanagement.js,
doubleColor.js, html5-qrcode.min.js, vue-i18n.global.prod.js) then `/js/main.js`.
So *chunk URLs are derived from a hardcoded build-time map, never from network data* — the
downloader replicates only this scheme.

## 3. Endpoint classification (Tier definitions from the task brief)

### Tier 1 — verified read-only (allowed GETs, unchanged from Phase 2)

`/api/device/basic_information`, `/api/net/current-plmn`,
`/api/monitoring/traffic-statistics`, `/api/dialup/connection`,
`/api/dialup/mobile-dataswitch`, `/api/pin/status`, `/api/user/state-login`,
`/api/global/module-switch`, `/api/monitoring/check-notifications`
(plus the two bootstrap endpoints `/api/webserver/SesTokInfo`, `/api/webserver/token` whose
*responses are secrets* and are never logged; `token` also mutates server-side state only by
allocating a one-time CSRF token — no configuration impact).

### Tier 2 — read-only *plausible but unverified* (stays blocked)

- `/api/monitoring/best-position-status` — name says status; but the calling page is inside an
  admin-only chunk that could not be fetched. No control-flow proof that GET is side-effect-free.
- `/api/monitoring/best-position-result` — same reasoning.
- `/api/device/information` — requires login (100003 pre-login); authenticated GET unexercised.
- `/api/monitoring/status` — requires login; app adds `Update-Cookie` header on every GET =
  probable *session-state* side effect; not affecting configuration but not verified.
- `/api/monitoring/converged-status` — used pre-login by the guide (evidence in `chunk_guide.js`),
  still unexercised live after login.
- `/api/device/signal` — classic Huawei signal read; name in map (`singal:`) — unexercised here.
- `/api/net/net-mode-list` — behind login; GET side effects unverified.
- `/api/net/network` — JS usage untraced; might touch registration flows → unknown.

### Tier 3 — potentially state-changing (hard-forbidden, stays forbidden)

`/api/monitoring/best-signal-position`, `/api/monitoring/external-best-signal-position`
(scan START endpoints; method + trigger unknown),
`/api/monitoring/onekey_diag` (one-key health check), `/api/net/plmn-list`
(manual network search — re-registration risk), `/api/net/register`, `/api/net/reconnect`,
`/api/net/net-mode` (write), `/api/net/lock-freq` (band lock write),
`/api/ntwk/celllock` (PCI lock write), `/api/net/handle-cell` (CA/band-op write),
`/api/dialup/dial`, `/api/device/control`, `/api/device/datalock`,
`/api/user/login|challenge_login|authentication_login` (auth POSTs — GET is senseless).

### Tier 4 — unknown

Anything not in any list above: rejected by default (exact-path allowlist → fail closed).

## 4. SCRAM verification (offline; results)

`src/huawei_tower/modem/scram.py` now implements the exact algorithm with pure functions:

- `new_nonce_hex()` — 32 random bytes, lowercase hex (Python `secrets`; never stored).
- `pbkdf2_sha256()` — PBKDF2-HMAC-SHA256, 32-byte output; accepts `iterations` as int or exact
  digit-string (XML dictionaries deliver digits as strings); rejects ≤ 0, empty salt/`.
- `client_key`, `server_key`, `stored_key`, `firmware_signature` — 1:1 JS transcription
  including the swapped HMAC orientation.
- `auth_message()` — dupe-server-nonce composition; rejects embedded commas/whitespace.
- `client_proof_hex`, `server_proof_hex` — byte-for-byte replication incl. the raw-bytes
  message orientation (stored/server keys are *raw digests*, not hex strings — critical detail).
- `build_authentication_login_payload()` — validates the challenge response fail-closed
  (missing fields, non-hex salt, non-digit iterations) then produces
  `{clientproof, finalnonce}` (+ `hashOldNewPwd`, `newStoredKey`, `newServerKey` greedily when
  `newType == "1"` with `newSalt`/`newIterations`).
- `verify_authentication_login_response()` — validates `rsan` hex first, then the two
  signatures, returning False on mismatch; raises `ScramDataError` on structural problems.

Tests (`tests/test_scram.py`, 21 cases) use:
1. An **independent re-derivation** built on `cryptography` (OpenSSL) primitives rather than the
   module's stdlib `hashlib/hmac` — different implementation classes.
2. Fixed-unit golden vectors (documented constants) — regenerated programmatically from the JS
   orientation, *not* adapted to the module.
3. 11 negative-path cases (missing fields, bad hex, non-positive/str-with-chars iterations,
   wrong signatures, bad rsan, whitespace nonces, migration with missing newSalt).

Phase-3 final **SCRAM golden values** (tokenless, synthetic test password `V3ct0rTest#42`):
```
salt (4096 iters, 0x001122...ef): 1fbcd3dd353466dca8de475010d027ba8a7fbf7f38f16fecb7022360aeacac16   (PBKDF2 out)
clientProof (fn 'a'-64, sn 'b'-64): 897f9713b03ba435bb057b20757f91f0710458be43c2ab8b0c4e90614280b938
serverProof:                        848441a05d030265feb07917726a64215cd85ca4900307278d3cdbde9f0ddb9d
```

### 4.1 Evidence quality caveat (honest limits)

The algorithm was transcribed from minified, human-verifiable code that is committed in-repo
(`data` commit). Cross-checks: syntax of the byte offsets was validated against the committed
binary blob and all plus-suffixed helpers were re-derived in tests. Still, the *server-side*
confirmation (that the firmware accepts a generated payload) is unavailable in Phase 3 because
the safety rules explicitly forbid live auth POSTs. Therefore:

- ✅ *confirmed for client-side construction.*
- ⚠ *pending one live round-trip in a later, approved phase* — see “next recommended step”.

## 5. JavaScript downloads (ID-D deliverable)

`src/huawei_tower/modem/jsdownloader.py`:

- Fixed `APPROVED_ASSETS` map — only the constants here can ever be fetched (12 files, keyed by
  exact path); admin chunks (`celllock`, `lockband`, `mobilesearch`, `mobilenetwork`,
  `networkmode`, `onekey`) are listed but flagged `requires_authenticated_session=True`,
  which raises until a separately-approved authenticated downloader is shipped.
- Uses HTTPS-only origin, explicit path-join; never trusts an URL from a response body/header.
- Hard-fails on: non-approved paths, traversal (`..`, backslashes), non-canonical prefixes,
  foreign-origin redirects (3xx always refused), non-200 statuses, XML error bodies (the
  Huawei `100003` response), size ceiling (default 8 MiB, accumulates stream-wise before write).
- Writes atomically (`*.tmp` → `replace`) only into an explicitly supplied `dest_dir`
  (documented default: `evidence/downloads/` which is `.gitignored`).
- `dry_run=True` turns `fetch()` into a no-op (still plan()'able); tests cover it via mocked
  sessions with zero socket use (guaranteed by the new offline fixture in `tests/conftest.py`).

## 6. Security & regression tests added/updated

- `tests/test_api_safety.py` (16 cases) — exact-path allowlist incl. trailing-slash, query, case,
  traversal and double-slash mutations; forbidden-set sweep; 3xx/4xx/5xx all raise; lack of any
  write HTTP verb; no-network socket guard proven live; gated entries all classified w/ reasons.
- `tests/test_jsdownloader.py` (11 cases) — dry-run, unapproved paths, auth-gated chunks,
  redirect rejection, HTTP error statuses, XML-body refusal, oversize refusal, exact-url/
  single-call verification, atomic write byte-fidelity, non-HTTPS rejection.
- `tests/test_scram.py` (21 cases) — summary in §4.
- `tests/test_security.py` (5 cases) — broader redaction (JSON-quoted keys, both cookie header
  forms, verification token headers, SCRAM proof & nonce material) + log-parseability.
- `tests/test_xmlutil.py` (3 cases) — unchanged (baseline still green).
- `tests/conftest.py` — new autouse socket-killer (marker `network` opt-out) = full-suite
  offline guarantee.

## 7. Workspace-relocation note (preserved)

Commit `b665ac9` initially lived under `huawei-h158381-phase2/…` (as the earlier planning doc
referenced). The working tree had *already relocated* these files to the repo root
(`src/`, `tests/`, `tools/`, `docs/PHASE2_STATUS.md`) as unstaged moves before this phase
started. Per the no-destructive-change rule, this phase **kept the relocated layout**; the
move is now committed as part of the `phase-3-js-analysis` branch work so history traces both.

## 8. Remaining uncertainties (explicit)

1. **No live login round-trip proved yet.** Client-side SCRAM construction is test-verified;
   the authentication POST itself was prohibited this phase by design.
2. **Token pool semantics** (exact `substr(32)` truncation interplay with response-header
   tokens `one/two`) was read from code but not exercised against the server.
3. **Scan endpoints `best-position-*`** — still undocumented payloads (their pages live in
   admin-chunks we cannot fetch without a session). They stay gated pending either: (a)
   authenticated admin-chunk download approval, or (b) explicit user permission to enable the
   corresponding page in a browser devtools trace.
4. **`Update-Cookie: UpdateCookie` side effect** — probable session refresh, unproven.
5. **`/api/net/plmn-list`** — classified forbidden (conservative), final verdict needs the
   `mobilesearch` chunk to see the exact trigger flow.

## 9. Exact next recommended step

Single, tightly-scoped approved live step (user-approved, uses `getpass`-fed password,
never persisted):

1. Run the read-only allowlist probe once more for baseline, then perform the two-request
   SCRAM login (challenge → authentication_login) with the new offline-verified client,
   capturing only *shape*, never values. Success criterion: HTTP 200 with a `<response>` body
   (no `<error>`) and both signature checks pass.
2. Immediately after, run `JSAssetDownloader` (still unauthenticated rules) → then flip its
   documented `allow_authenticated` gate (needs explicit approval) to fetch the four admin
   chunks (`celllock`, `lockband`, `mobilesearch`, `onekey`) from the local machine, revealing
   the exact POST schemas for `best-signal-position`, lock/cell APIs and their `handle-cell`
   guard flags. Then close.

Both steps remain PHYSICALLY gated behind the user's explicit go-ahead; until then the test
suite and static analysis deliverable are complete without touching the modem.

# Phase 1 — Repository & Firmware Discovery Findings

Date: 2026-10-16
Modem: Huawei H158-381 ("5G CPE Pro 5"), HTTPS on `https://192.168.70.1` (device acts as IPv4 gateway 192.168.70.1; HTTP redirects 307 → `https://hirouter.net/`).
Firmware web build stamp seen in asset URLs: `?r=1709723942` (2024-03-06 era build).

All evidence below was collected **read-only** (HTTP GET / static asset fetch only).
Raw, sanitized evidence: `evidence/raw/` (SessionIDs, CSRF tokens, SesInfo/TokInfo redacted).

---

## 1. Repository audit

- The workspace `H:\huawei-modem` was **empty** — no existing implementation, scripts, docs, configs, or test data were found anywhere in it (verified with recursive listing).
- Conclusion: there is no flawed implementation to inherit and nothing to preserve. The project starts from a clean slate; the only prior artifacts are the facts in this prompt (PLMN 43211, n78, PCI 125, failed SHA256 `/api/user/login` attempt → 108006).

## 2. What was discovered about the device (direct read-only probes)

Confirmed (HTTP 200, unauthenticated):

| Endpoint | Result |
|---|---|
| `/api/device/basic_information` | productfamily LTE, classify **cpe**, devicename **H158-381**, spreadname "5G CPE Pro 5" |
| `/api/net/current-plmn` | Numeric **43211**, Rat **7** (Rat 7 = Δutran-based NSA: LTE+NR on Huawei MBB firmwares) |
| `/api/monitoring/traffic-statistics` | live counters (CurrentConnectTime etc.) |
| `/api/dialup/connection` | MTU 1500, auto_dial_switch 1 |
| `/api/dialup/mobile-dataswitch` | dataswitch 1 (mobile data on) |
| `/api/pin/status` | SimState 257, PinOptState 258 (no PIN needed) |
| `/api/user/state-login` | **rsapadingtype=1**, **password_type=4**, State=-1 (not logged in), accounts_number=2, firstlogin=0 |
| `/api/global/module-switch` | many feature flags, incl. **nrProductEnable=1**, oneKeyCheckEnable=1, websocket_enabled=1, higame_web_enabled=1 |
| `/api/webserver/SesTokInfo` | returns `SesInfo` (session) + `TokInfo` (CSRF token) |
| `/api/webserver/token` | single-use CSRF token pool item |
| `/api/monitoring/check-notifications` | unread counters |

Blocked without login (HTTP 200 body `<error><code>100003</code>` / `125002`):

`/api/device/information`, `/api/net/net-mode`, `/api/net/net-mode-list`, `/api/monitoring/status`, `/api/version`, `/api/monitoring/converged-status`, admin JS chunks (`celllock`, `lockband`, `mobilesearch`, `mobilenetwork`, `networkmode`, `onekey`, `home`), `/api/config/global/config.xml`.

Code meanings (observed behavior): `100003` = not authorized / session not permitted for this endpoint; `125002` = monitoring requires logged-in session (seen for `/api/monitoring/status` pre-login); `108006` (from user's prior test) = wrong login format for this firmware.

## 3. Authentication — CONFIRMED from the device's own JS (high confidence)

Source: `/js/main.js` (common chunk), `/lib/emui-crypto.js` (contains `CryptoJS.SCRAM`), `login.js` chunk.
This explains the earlier `108006` failure: this firmware does **not** use `/api/user/login` with plain Base64(SHA256(password)). The standard flow is SCRAM over `/api/user/challenge_login` + `/api/user/authentication_login`. `/api/user/login` is only used by the browser for the "remember password" fast path (`password_type: "0"`, Base64-encoded clear formula) — not the normal login.

Flow (exact, as implemented):

1. **Pre-step (XML only):** `GET /api/webserver/SesTokInfo` → session cookie `SessionID=<...>` (charset `utf8` note) and token. Subsequent requests carry `Cookie: SessionID=...`.
2. **Challenge:** `POST /api/user/challenge_login`
   - Header `__RequestVerificationToken: <token>` (from step 1; token pool refilled from response headers `__RequestVerificationTokenone/two` and `/api/webserver/token`)
   - Body: `<?xml version="1.0" encoding="UTF-8"?><request><username>admin</username><firstnonce><64-hex-chars random></firstnonce><mode>1</mode></request>`
   - `firstnonce` = `CryptoJS.lib.WordArray.random(32 bytes)` → lowercase hex (64 chars)
3. **Challenge response:** `<response><salt><hex></salt><iterations>N</iterations><servernonce><hex></servernonce>…`
4. **Proof:** `POST /api/user/authentication_login` with header token, body:
   - `<clientproof><hex 64></clientproof><finalnonce><servernonce></finalnonce>`
   - If `<newType>1</newType>` in challenge response (password migration path), also `hashOldNewPwd`, `newStoredKey`, `newServerKey`.
   - `loginflag=2` only for the developermode route.
5. **Crypto (all SHA-256 based, from emui-crypto.js — non-standard SCRAM variants, must replicate exactly):**
   - `saltedPassword(pw, salt, iters)` = PBKDF2-HMAC-SHA256, keySize **32 bytes**, salt parsed as hex from server, `iterations` from server → 64-hex string.
   - `clientKey(km)` = HMAC-SHA256(key="Client Key", msg=km)
   - `serverKey(km)` = HMAC-SHA256(key="Server Key", msg=km)
   - `storedKey(ck)` = SHA256(ck)
   - `signature(km, am)` = HMAC-SHA256(**key=am, msg=km**) — NOTE argument order (key is the second arg; this is swapped vs standard SCRAM and matters).
   - `authMessage` = `firstnonce + "," + servernonce + "," + servernonce` (the JS concatenates servernonce twice — replicate this).
   - `clientProof = Hex( clientKey ⊕ HMAC(key=authMessage, msg=storedKey(clientKey)) )`  → 64-hex
   - `serverProof = Hex( HMAC(key=authMessage, msg=serverKey(saltedPassword)) )`
6. **Verify + RSA params:** authentication_login response contains `rsan`, `rsae`, `serversignature`, `rsapubkeysignature`.
   - Check `serverProof == serversignature` for server authenticity.
   - Check `HMAC(key=authMessage, msg=rsan) == rsapubkeysignature` (server-proofs the RSA modulus).
   - Store `rsan`/`rsae` as the write-crypto RSA public key.
7. **Request verification tokens after login:** `GET /api/webserver/token` returns single-use tokens. Every mutating POST needs header `__RequestVerificationToken: <nonce>` where `<nonce>` = RSA-encrypted token obtained from `/api/webserver/SesTokInfo` + RSA public key `rsan,rsae` — and it's appended to the header together with the current session token.
8. **Response format:** XML `<response>` normally, or `<error><code>N</code>`; login failure of a different vein comes with codes like 108xxx (auth-related).

Post-login RSA token encryption (from main.js `A()`/`doRSAEncrypt` path):

- RSA-OAEP encryption when `rsapadingtype == "1"` (this device), otherwise PKCS#1 v1.5.
- Token encrypted in chunks of size `modulus/2 - 42` chars (OAEP) with modulus length in hex digits (`w.n.length` is hex string length), concatenated → header `__RequestVerificationToken: `<chunk><chunk>` ... (see JS fragment below).

```js
(a=new RSAKey).setPublic(w.n,w.e), c=v(t) /* base64encode? v() */,
s=c.length/(w.n.length/2-42) ... // chips: h=c.substr(m*(w.n.length/2-42), w.n.length/2-42), f=a.encryptOAEP(h), u+=f
```

- Confirmation of "Login-Type: Scram" is **only required** for `/api/wlan/multi-basic-settings` and `/api/wlan/basic-settings` (special flag), not for normal writes.

## 4. Tower / cell scanning ("Best Signal Position") — endpoints present (medium confidence; flow still to verify live)

The firmware's own endpoint map (`main.js`) lists these — the antenna-positioning / signal-position scan feature:

- `testSignalPosition: "/api/monitoring/best-signal-position"` — starts/queries the scan (single method unverified).
- `moniBestSta: "/api/monitoring/best-position-status"` — poll status.
- `bestPositionRes: "/api/monitoring/best-position-result"` — fetch results.
- `moniexBestSignalPos: "/api/monitoring/external-best-signal-position"` — variant used by Hilink App ("external antenna" positioning).
- Also `oneKeyCheckEnable=1` in `module-switch` and a `onekey-onekey-vue` page; the Best Signal Position flow is part of the "one-key check / elevation guide" experience.

Cell / band / PCA-related endpoints also **present in the map** (login-chunk pages confirm they are UI-exposed):

- `cellInfo: /api/net/cell-info` (serving + neighbor info)
- `handleCell: /api/net/handle-cell`
- `ntwkCelllock: /api/ntwk/celllock` (page chunk `celllock-celllock-vue`)
- `lockFreq: /api/net/lock-freq`, `lteBandInfo: /api/net/lte-band-info`, `bandFreqList: /config/network/bandfreqlist.xml` (page chunk `lockband`)
- `netMode/net-mode-list`, `network`, `plmn-list`, `register`, `reconnect` (`mobilesearch` page = manual network search)
- `device/signal` (RSRP/RSRQ/SINR/rssi), `monitoring/status` (connection status, network type, signal bands)
- `monitoring/converged-status` (also tells UI login state, language)

Not yet fetched (they require an authenticated session): `celllock-celllock-vue`, `lockband`, `mobilenetwork`, `mobilesearch`, `onekey` JS chunks and `/config/network/*.xml` files. **The POST payloads for lock-freq / celllock / handle-cell are NOT yet know** — do not guess; implement the client first, log in under read-only rules, then (after approval) download those chunks to extract exact schemas.

## 5. Firmware capability matrix (updated continuously)

| Capability | Status | Evidence |
|---|---|---|
| Classic HiLink XML API | CONFIRMED | every probe response is XML |
| SCRAM challenge+authentication login | CONFIRMED (code path in main.js + emui-crypto.js SCRAM impl + state-login fields definition) | main.js, state-login |
| RSA-encrypted tokens for mutative POSTs | CONFIRMED (rsapadingtype=1 path in code; actual write not yet runtime-verified) | main.js |
| Serving/neighbor cell info | ENDPOINT PRESENT (`/api/net/cell-info`) — schema unverified | main.js |
| Best-signal-position (physical cell scan) | ENDPOINT PRESENT (`/api/monitoring/best-signal-position` + status/result) — schema/behaviour unverified; scan impact on connection unverified | main.js |
| Band lock | ENDPOINT PRESENT (`net/lock-freq`, `lte-band-info`, page chunk `lockband` exists) — payload unverified | main.js |
| Cell (PCI) lock | ENDPOINT PRESENT (`/api/ntwk/celllock`, chunk page `celllock-celllock-vue` exists) — payload unverified | main.js |
| Manual PLMN search | page chunk `mobilesearch` exists; `net/plmn-list`, `net/register`, `net/network` | main.js (page name) |
| CA / extra cell info (`handle-cell`) | ENDPOINT PRESENT — unverified | main.js |
| n73 API encryption variant(s) in device (sms) | Present for phonebook/SMS AES-SCRAM encryption — N/A for our scope but proves RSA closure machinery multi-purpose | main.js `E()` |

**Confidence legend:** CONFIRMED (direct code or response evidence) / PRESENT (endpoint listed in firmware map, page exists) / UNOWNED (not verified at runtime).

## 6. Missing evidence — collection checklist (read-only)

To be gathered once the read-only client + SCRAM login is implemented (still no writes):

1. Effective XML schema of `/api/monitoring/best-signal-position` (likely a POST action with a parameter like `<signal_position_type>`; do not guess).
2. Response schemas: `best-position-status` (`<response><status>…` fields), `best-position-result` fields (frequency/band/PCI/OPLL list? physical bearing? RSRP?).
3. Schemas of `net/cell-info`, `device/signal`, `monitoring/status`.
4. JS chunks `celllock-celllock-vue`, `lockband`, `mobilenetwork`, `mobilesearch`, `onekey` once logged in — to extract exact lock/search payloads.
5. Whether the scan disrupts the connection (observe `monitoring/status` during a scan with user approval).
6. Whether `cells-info` data changes with the config like `handle-cell`.

## 7. Proposed project structure

```
huawei-modem/
  diagrams, evidence/raw/          - collected raw evidence (redacted)
  docs/                            - findings, capability matrix, runbooks
  src/huawei_tower/                - python package
    modem/                         - API layer
      session.py                   - session, SCRAM login, RSA token handling
      api.py                       - typed wrappers for endpoints (read-only first)
      xmlutil.py                   - XML parse/serialize
      scram.py                     - PBKDF2/HMAC replication of emui-crypto
      rsa_token.py                 - chunked RSA-OAEP token encryption
      errors.py                    - 100002/3/125002/108xxx mapping
    towers/                        - Tower Explorer (serving/neighbor/scan results)
    metrics/                       - ping/loss/jitter/collectors
    scoring/                       - configurable weighted score
    store/                         - sqlite persistence
    webapp/                        - FastAPI + small frontend (Phase 6)
  tools/                           - CLI for evidence gathering, tests fixtures maker
  tests/                           - unit tests w/ sanitized fixtures
```

## 8. Minimal read-only implementation plan

Step 1 — `session.py` + `scram.py` + `rsa_token.py`: login via challenge/authentication, no writes. Unit-test SCRAM hashing/proof against the captured algorithm by re-implementing and cross-checking on dummy data.

Step 2 — `api.py` wrappers for: `basic_information`, `device/information`, `monitoring/status`, `monitoring/traffic-statistics`, `net/current-plmn`, `dialup/connection`/`mobile-dataswitch`, `device/signal`, `monitoring/converged-status`, `net/cell-info`, `monitoring/best-position-status`, `monitoring/best-position-result`, `net/network`, `net/net-mode-list` (read side).

Step 3 — CLI `tools/probe.py` dumping sanitized snapshots to `evidence/` for schema fixtures & tests.

Step 4 — only after user approval: fetch post-login JS chunks to extract lock/scan schemas; only after that consider POST-dependent discovery.

# Phase 6 — Offline API Contract and Operation-Risk Audit

Branch: `phase-3-js-analysis`. Audit-only: **no code behavior was changed, no
allowlist was modified, nothing was committed or pushed.** Every citation
below is to repository files at HEAD `93e2e08…` unless stated otherwise.

> **Phase 5 status:** `jsanalysis.py` and `docs/PHASE5_JS_STATIC_ANALYSIS.md`
> are **NOT approved** in this phase. Their regex findings are treated as
> unverified string-presence data and are NOT used as evidence anywhere in
> this report. The inventory below is built exclusively from artifacts that
> were already reviewed in Phases 1–3 (`docs/PHASE1_FINDINGS.md`,
> `docs/PHASE3_JS_ANALYSIS.md`, production source, and sanitized fixtures).

---

## 1. Exact repository state at audit time

- Branch `phase-3-js-analysis`, tracking `origin/phase-3-js-analysis`
  (dirty tree after this audit's new doc only).
- HEAD: `93e2e08a312022c893f74a14038e7265b44f5260`
  (`phase 5: offline JS static analysis tool with evidence report`).
- Recent commits: `93e2e08` ← `a0bbcbf` ← `059d2a3` ← `1bc510d` ←
  `c68a330` ← `c40ddd5` ← `04c1a71` ← `1badea9` (phase 3).

### 1.1 Phase 3–5 file line counts (`@()Count`, byte-faithful)

| File | Lines | `git diff --numstat 93e2e08^ 93e2e08` |
|---|---:|---:|
| `src/huawei_tower/modem/api.py` | 242 | (pre-existing) |
| `src/huawei_tower/modem/tls.py` | 98 | (pre-existing) |
| `src/huawei_tower/modem/scram.py` | 279 | (pre-existing) |
| `src/huawei_tower/modem/security.py` | 41 | (pre-existing) |
| `src/huawei_tower/modem/jsdownloader.py` | 343 | (pre-existing) |
| `src/huawei_tower/modem/jsanalysis.py` | 286 | 286 ✓ |
| `tests/test_jsanalysis.py` | 195 | 195 ✓ |
| `docs/PHASE5_JS_STATIC_ANALYSIS.md` | 551 | 551 ✓ |
| `tests/test_api_safety.py` | 266 | (pre-existing) |
| `tests/test_jsdownloader.py` | 412 | (pre-existing) |
| `tests/test_scram.py` | 277 | (pre-existing) |
| `tests/conftest.py` | 87 | (pre-existing) |
| `tests/test_security.py` | 37 | (pre-existing) |
| `tests/test_xmlutil.py` | 22 | (pre-existing) |

**Discrepancy recorded and resolved:** `(Get-Content … | Measure-Object
-Line).Lines` initially reported 249/150/512 for the three Phase 5 files —
that cmdlet counts NON-BLANK lines. Recounted with `@(...).Count`: 286/195/551,
matching `--numstat` and physical contents exactly. There are no count
discrepancies between documentation, numstat and file bytes; the earlier
`249/150/512` figures were a measurement artifact, not a repo anomaly.

---

## 2. Implementation inspection (with citations)

### 2.1 Request allowlist and default-deny — `api.py`

- `Endpoint`/`GatedEndpoint` dataclasses: `api.py:15-29`.
- Tier 1 verified read-only allowlist (11 paths, all `verified_read_only:
  True`): `api.py:35-69`. Notes state each returns HTTP 200 and that the two
  bootstrap endpoints (`SesTokInfo`, `token`) return secrets ("never logged",
  `api.py:60-65`).
- Tier 2/4 gated endpoints (10 path/`GatedEndpoint` rows with reasons and
  `Classification`): `api.py:73-143`. Default state = NOT callable.
- Tier 3 `FORBIDDEN_PATHS` (21 write/scan/auth paths, commented per-family):
  `api.py:146-168`. The client rejects these *before any I/O*.
- Exact-match classification `_classify`: `api.py:205-215`. Unknown paths
  fail closed (`api.py:216` branch: "not on the approved allowlist").
- `get()` raises `UnsafeOperationError` on any classification reason
  **before** building a URL or touching the session: `api.py:217-221`.

**Default-deny test evidence:** `tests/test_api_safety.py:32` (unapproved
blocked pre-network), `:40` (scan-start blocked), `:48` (all forbidden
blocked pre-I/O), `:74` (`/api/monitoring/statusx` look-alike rejected —
exact-match, not prefix), `:92` (unknown default-deny).

### 2.2 HTTP method restrictions and bypass resistance — `api.py`

- Only `get()` exists on the class; no post/put/patch/delete methods
  (`api.py:217-241`).
- `__getattr__` intercepts post/put/patch/delete/head/options/request and
  raises `UnsafeOperationError`: `api.py:235-242`, backed by
  `_WRITE_METHODS` tuple `api.py:170`. Test: `:232` (`test_no_http_verbs_exposed_for_writes`).
- **Bypass review (offline reasoning, cite-level):**
  - Attribute-to-verb reach: any OTHER attribute name raises
    `AttributeError` (`api.py:242`), so no generic `request()` path exists.
  - URL manipulation: exact-match allowlist (`api.py:209`) means `..`- or
    suffix-padded variants never match (test `:74`). `urljoin` is only run
    on an *approved* exact path (`api.py:221`), and paths are fixed strings;
    no response or server field can inject a URL (client has no such flow).
  - Verb reachability through injected session: the client forwards only
    `self._session.get(...)` (`api.py:222-227`); a caller-injected session
    keeps ITS OWN configuration (`api.py:199-202`), so a pathological
    injected session could still do unexpected things — but that session is
    constructed by the caller, deliberately; documented at `api.py:200-201`
    (including falsey-session preservation, test `:209`).
  - Residual gap **G-1**: `__getattr__` does not intercept `connect`/`trace`
    (they fail with plain `AttributeError` — still safe, but the explicit
    refuse-with-message set is smaller). Cosmetic; no exploit path because
    no method exists and urllib3 verbs are not reachable attributes.
  - Residual gap **G-2**: `requests.Session.get(url, params=...)` — the
    client never passes `params`, and `path` is a fixed string; no query
    injection surface exists in code, but no dedicated test asserts that
    a path with `?query` is rejected (it *is* rejected by exact-match since
    no allowlist entry contains `?`; gap = missing explicit regression test).

### 2.3 TLS verification, CA handling, proxy/env, timeout, redirects

- TLS single-control-point `tls.resolve_verify_tls`: `tls.py:67-98` —
  `True` → default trust store; str → existing PEM-file path validated
  offline (`_validate_ca_bundle`, `tls.py:28-64`, X.509 parse of each block
  via local `cryptography` import `tls.py:54-63`); `False`/`None`/`1`/`0` /
  `""`/missing file → `ValueError` (`tls.py:74-97`).
- Both consumers fail-closed in constructors **before any I/O**:
  `api.py:190`, `jsdownloader.py:182`. Tests: `test_api_safety.py:115-174`
  (9 cases: no-disable, never-forwards-False, CA forwarded, missing/empty/
  malformed/truncated bundle rejected); downloader equivalents
  `test_jsdownloader.py:242-265`.
- HTTPS-only enforcement: `api.py:184-186`, `jsdownloader.py:172-174`
  (tests `test_api_safety.py:106`, `test_jsdownloader.py:236`).
- Proxy/env inheritance: internally created sessions set
  `trust_env = False` (`api.py:197-198`, `jsdownloader.py:241-249`).
  Caller-injected sessions are preserved as-is including falsey objects
  (`api.py:199-202`; `jsdownloader.py:239-249`; tests `test_api_safety.py:139-147`,
  `test_jsdownloader.py:267-282`, `:397-406`).
- Timeouts: fixed per-request `timeout=` always passed (`api.py:224`,
  `jsdownloader.py:256`); defaults 8.0 s (`api.py:181`) / 15.0 s
  (`jsdownloader.py:168`). Gap **G-3**: no unit test asserts the timeout is
  forwarded (mock-compatible but untested value).
- Redirects: `allow_redirects=False` everywhere + explicit non-2xx /
  3xx errors (`api.py:226-229`, `jsdownloader.py:260-265`; tests
  `test_api_safety.py:215-230`, `test_jsdownloader.py:185-200`).
- Streaming ceilings: downloader caps at `_MAX_ASSET_BYTES` (default 8 MiB,
  `jsdownloader.py:52`, enforced per-chunk `jsdownloader.py:269-275`,
  test `:214-221`). The API client has **no response-size cap** —
  gap **G-4** (bounded by timeout in practice, but an unbounded-body GET
  exists in principle).

### 2.4 Session injection, cookies/tokens, redaction, error paths

- The client performs no login, no token acquisition, no cookie logic; it
  only stores one UA/`Accept` header (`api.py:203`). No
  `__RequestVerificationToken` support exists (none is needed for the
  Tier-1 GETs). Any future *write* client is out of scope here.
- Cookie/token secret hygiene: `security.redact_secrets` redacts
  `password|SessionID|SesInfo|TokInfo|__RequestVerificationToken*|
  csrf_token|Cookie|clientproof|storedkey|serverkey|firstnonce|…`
  (`security.py:14-41`); tests `tests/test_security.py` (37 lines, 5-6
  cases). Bootstrap-endpoint secret sensitivity is flagged in the allowlist
  notes (`api.py:60-65`).
- Error paths: non-200 → `ModemHTTPError` with path+status only
  (`api.py:228-229`, `jsdownloader.py:264-265`); unsafe →
  `UnsafeOperationError` (`errors.py`); invalid config → `ValueError`
  (`tls.py`). No response body content flows into error messages
  (gap **G-5**: no explicit test that error text never contains response
  bodies/headers — reason strings are compile-time only today).
- `get()` returns the raw `requests.Response` — callers could read secrets
  (e.g. `SesTokInfo`); that is by design for GUI use, but nothing in-repo
  logs it. Gap **G-6**: no test that logging of responses is absent (a
  source-scan "no logging of response.text/headers" regression test is
  missing).

### 2.5 JS downloader destination safety, temp lifecycle, concurrency

- Fixed approved list of exactly 12 assets, 6 flagged
  `requires_authenticated_session`: `jsdownloader.py:71-108`. `plan()` maps
  them to sanitized single-file names under caller `dest_dir`
  (`jsdownloader.py:186-191`). Tests: list-finiteness/no-dot-paths
  (`test_jsdownloader.py:57`), destinations under dest (`:65`),
  traversal/foreign-path rejection (`:82-142`).
- Temp lifecycle: `_publish` uses `tempfile.mkstemp` (unique/exclusive)
  in the destination's own directory, `O_CREAT|O_EXCL` semantics
  (`jsdownloader.py:317-320`), writes, then atomic no-clobber
  `os.link(tmp, dest)` with explicit `FileExistsError` → preserve and
  `OSError` (no hard-link support) → refuse (`jsdownloader.py:325-338`),
  unconditional `tmp.unlink(missing_ok=True)` in `finally`
  (`jsdownloader.py:339-340`). Only its own temp file is touched.
- Same-destination concurrency: proven by `test_jsdownloader.py:332-384`
  (uniqueness + exactly-once publish), `:308-321` (concurrent appearance
  never overwritten), `:386-395` (foreign temp preserved), `:284-293`
  (existing destination preserved byte-for-byte), `:295-306` (tmp cleanup
  on failure).
- XML-error/non-asset detection: `_ERROR_MARKERS` on first 64 bytes
  (`jsdownloader.py:54`, `278-283`; test `:202-213`). Dry-run: no I/O
  (`:234-235`; test `:73-81`).
- Auth gate: `AuthenticatedDownloadAuthorization` frozen dataclass, exact
  path, operator+reason, never constructed by the downloader, session
  cookies never sufficient (`jsdownloader.py:127-155`, `:203-216`; tests
  `:92-181`, `:177-184`).

---

## 3. Evidence-based API inventory

**Rules applied:** a path is listed only with its evidence citation; HTTP
method is stated ONLY when explicitly supported (Phase 1 probes = observed
GET/200s; `scram.py:193-232` documents POST bodies for the two auth
endpoints as payload *builders*, not as executed calls). No allowlist change.
Exactly three status levels per task:

- `✔ confirmed-by-source` — present as reviewed code/doc fact.
- `◆ candidate` — plausible from reviewed Phase 1–3 evidence; NOT confirmed.
- `? unknown` — evidence missing (admin chunks unavailable offline).

### 3.1 Confirmed by source code (client Tier-1, executed once in Phase 1)

| # | path | method | evidence | auth | risk | notes |
|---|---|---|---|---|---|---|
| 1 | `/api/device/basic_information` | GET | `api.py:36`; PHASE1 §2 (family/cpe/H158-381) | none observed | `read_only_candidate` (GET behavior confirmed safe) | XML payload observed |
| 2 | `/api/net/current-plmn` | GET | `api.py:39`; PHASE1 §2 (43211, Rat 7) | none observed | `read_only_candidate` | serving PLMN/RAT |
| 3 | `/api/monitoring/traffic-statistics` | GET | `api.py:42`; PHASE1 §2 | none observed | `read_only_candidate` | counters |
| 4 | `/api/dialup/connection` | GET | `api.py:45`; PHASE1 §2 | none observed | `read_only_candidate` | MTU/auto-dial |
| 5 | `/api/dialup/mobile-dataswitch` | GET | `api.py:48`; PHASE1 §2 | none observed | `read_only_candidate` | status read; the corresponding dataswitch *setting* is a different operation and is not offered by this client |
| 6 | `/api/pin/status` | GET | `api.py:51`; PHASE1 §2 | none observed | `read_only_candidate` | SimState 257 |
| 7 | `/api/user/state-login` | GET | `api.py:54`; PHASE1 §2 | none observed | `read_only_candidate` | login metadata |
| 8 | `/api/global/module-switch` | GET | `api.py:57`; PHASE1 §2 | none observed | `read_only_candidate` | feature flags (nrProductEnable=1) |
| 9 | `/api/webserver/SesTokInfo` | GET | `api.py:60`; PHASE1 §2 + login flow step 1 | unauthenticated bootstrap; response CONTAINS secrets | `sensitive_read_candidate` | response = session cookie + token; never logged |
| 10 | `/api/webserver/token` | GET | `api.py:63`; PHASE1 §2 (single-use token pool) | unauthenticated bootstrap; server-side state allocation | `sensitive_read_candidate` | allocates CSRF token (side effect is state allocation, exercised-by-design in browser flow) |
| 11 | `/api/monitoring/check-notifications` | GET | `api.py:66`; PHASE1 §2 | none observed | `read_only_candidate` | unread counters |

`scram.py` payload builders (`scram.py:193-232` + PHASE3 doc lines 90-103)
confirm the two auth POST bodies offline: `POST /api/user/challenge_login`
→ `{username, firstnonce, mode:1}` (auth REQUIRED), `POST
/api/user/authentication_login` → `{clientproof, finalnonce[, newStoredKey,
newServerKey, hashOldNewPwd]}` (auth REQUIRED). These are **never
callable** by `ReadOnlyModemClient` (`api.py:164-168`); risk: `unknown`
until live (unproven round-trip; `rsan/rsapubkeysignature` semantics
unverified per `scram.py:246-271`).

### 3.2 Candidates (reviewed Phase 1–3 evidence only)

| path/class | evidence | risk | unresolved |
|---|---|---|---|
| `/api/monitoring/best-signal-position` | PHASE1 §5 (`testSignalPosition` map), PHASE3 doc 174; FORBIDDEN `api.py:148` | `state_changing_candidate` (likely scan trigger; may degrade connection) | method, parameters, scan impact — unknown |
| `/api/monitoring/external-best-signal-position` | PHASE1 §5, FORBIDDEN `api.py:149` | `state_changing_candidate` | same as above (Hilink-app variant) |
| `/api/monitoring/best-position-status` + `-result` | PHASE1 §5, GATED `api.py:78-91` | `read_only_candidate` (poll only) | caller chunk admin-only; side-effect-free-on-unscanned-state unproven |
| `/api/monitoring/onekey_diag` | PHASE1 §5, FORBIDDEN `api.py:150` | `state_changing_candidate` | one-key health check behavior unknown |
| `/api/net/handle-cell`, `/api/ntwk/celllock`, `/api/net/lock-freq` | PHASE1 §5; FORBIDDEN `api.py:152-154` | `state_changing_candidate` (lock writes) | payloads, persistence scope (volatile?), recovery — unknown |
| `/api/net/net-mode` (+`net-mode-list`) | PHASE1 §5; FORBIDDEN/GATED `api.py:155`,`136` | `state_changing_candidate` (write) / `read_only_candidate` (list) | write payload unknown |
| `/api/net/register`, `/api/net/reconnect`, `/api/net/plmn-list` | PHASE3 doc 176-177; FORBIDDEN `api.py:157-159` | `state_changing_candidate` | re-registration risk unquantified |
| `/api/dialup/dial`, `/api/device/control`, `/api/device/datalock` | PHASE3 doc 180-181; FORBIDDEN `api.py:160-163` | `state_changing_candidate` | unreachable-no-sim-ops; semantics unknown |
| `/api/device/information`, `/api/monitoring/status`, `/api/monitoring/converged-status`, `/api/device/signal`, `/api/net/cell-info`, `/api/net/network` | GATED `api.py:92-135` | `sensitive_read_candidate` / `unknown` | login-required confirmed (100003); authenticated GET behavior unexercised; Update-Cookie header semantics unverified (`api.py:99-105`) |
| `/api/user/login`, `/api/user/password_scram`, `/api/wlan/{,multi-}basic-settings` | PHASE1 (108006 — wrong format), PHASE3 doc 90-114; absent from client | `unknown` | login fast-path & WLAN writes not needed for Best Pair; unimportant |
| `/config/network/bandfreqlist.xml`, `/config/**` XML resources | PHASE1 §5 (`bandFreqList`), PHASE3 doc 101 | `read_only_candidate` (static resource GET) | availability pre/post login unknown |

### 3.3 Unknown due to missing chunks

Admin pages (`celllock`, `lockband`, `mobilesearch`, `mobilenetwork`,
`networkmode`, `onekey` — asset entries `jsdownloader.py:90-107`) return
HTTP 200 + XML `100003` unauthenticated (`evidence/raw/*_api_js_*.xml`
fixtures). Their code — the only source of method/payload truth — is not
possessed. **No attempt was made to fetch it.**

### 3.4 String-presence ≠ fact (policy recall)

Any firmware-bundle string mapping a path (PHASE1 §5 excerpt
`main.js` symbols such as `testSignalPosition: "/api/monitoring/
best-signal-position"`, `lockFreq: "/api/net/lock-freq"`) is evidence of
*presence in a minified map only* — never of an active endpoint, method, or
success. Every such row above is therefore `candidate` at best, and the
client enforces that (`api.py:73-143` gates; `146-168` forbidden).

---

## 4. Known facts vs hypotheses (ledger)

**Confirmed by source code:** allowlist default-deny architecture
(§2.1-2.2); TLS/CA fail-closed (§2.3); trust_env=False for created sessions
(§2.3); downloader no-clobber temp lifecycle (§2.5); offline SCRAM
algorithm matches firmware constants as committed `scram.py:34-279`
(offline-vs-firmware only); Test-suite offline guard (`conftest.py:19-53`).

**Confirmed only by sanitized fixture:** Phase 1 probe payloads in
`evidence/raw/*.xml` + `evidence/fixtures/*.xml` (41 tracked files);
purchase: those XML bodies = what Phase 1 observed; nothing since.

**Inferred candidates:** every row of §3.2 (names/maps from unauthenticated
HTML/JS collections); `config/**` availability.

**Unknown:** auth'd GET forms of gated reads; all write payloads; scan
trigger schema; admin chunk logic; SCRAM live round-trip; token refresh
mechanics post-login; `rsapubkeysignature` relevance (`scram.py:252-271`
implementing an unverified interpretation).

---

## 5. Review of test suite — exact offline results

`python -m pytest` → **Exit 0, `99 passed, 0 failed, ~3,772 warnings in
~1.3 s`** (all warnings from the user-global `pytest-asyncio` plugin under
Python 3.14; none suppressed, suite unmodified).

Coverage map: `test_api_safety.py` 24 tests, `test_jsdownloader.py` 29,
`test_scram.py` 21, `test_jsanalysis.py` 17, `test_tls_*`-railroaded via
api/downloader suites, `test_security.py`, `test_xmlutil.py`. The suite has
zero `network`-marker tests (`conftest.py:36-38`; documented: guard is
per-interpreter, children escape, `socketpair` unpatched — `conftest.py:31-35`).

### Prioritized security/test gaps (no modem contact needed to close)

1. **G-1** (low) — add `connect`/`trace` to `_WRITE_METHODS` + explicit
   regression test (clearer failure surface; currently safe via bare
   AttributeError).
2. **G-2** (medium) — dedicated test that paths containing `?`/`#` never
   match the allowlist (exact-match makes them rejected today, but not
   asserted explicitly).
3. **G-3** (medium) — assert the chosen `timeout` forwarded per request in
   both `api.py:224` and `jsdownloader.py:256` (mock capture).
4. **G-4** (medium) — response-size ceiling for `ReadOnlyModemClient.get`
   analog of downloader cap; plus test (fix REQUIRED if client ever gains a
   bulky read).
5. **G-5** (medium) — test that `ModemHTTPError`/`UnsafeOperationError`
   message text contains no response body/headers (currently true by
   construction: only path+status; keep it enforced).
6. **G-6** (medium) — source-scan test: no logging of
   `response.text/.content/.headers/.cookies` anywhere in client code
   (protects the `SesTokInfo` "never logged" policy `api.py:60-65`).
7. **G-7** (high-value, future) — an offline mock proving SCRAM round-trip
   consistency against a fixture challenge/response pair (algorithm is
   correct offline; live semantics remain a live-phase blocker).
8. **G-8** (low) — downloader `_SessionLike` Protocol lacks
   `close()`; internal sessions close fine (`jsdownloader.py:289-291`)
   but a Protocol-level test for close-on-error is a hardening nicety.

---

## 6. Deliverables table (concise)

| Fact class | Count | Where |
|---|---|---|
| Confirmed-by-source client GETs | 11 (+2 auth POST builders offline) | `api.py:35-69`, `scram.py:193-232` |
| Gated reads (login-first, GET-side-effect unknown) | 10 | `api.py:73-143` |
| State-changing candidates (never callable) | 21 paths | `api.py:146-168` |
| Downloader assets (mixed, 6 admin-gated) | 12 | `jsdownloader.py:71-108` |
| Offline suite failures | 0 | 99/99 pass, exit 0 |

### Go/No-Go for a separately authorized live-phase review

**NO-GO today**, with the following conditional GO path (in order):

1. Phase-5 report independently adjudicated (this audit uses none of it).
2. Close gaps G-3, G-5, G-6 (mock-only, offline).
3. Live-phase plan produced separately, listing: exact GETs (Tier-1
   verified list only), SCRAM live proof protocol, admin-chunk download
   with operator-authorized `AuthenticatedDownloadAuthorization`, and
   explicit "no write commands" boundary — each item gated on its own
   explicit approval.

**Next audit-cycle risk cap:** live work may only cover *reads + login*;
any scan/lock/reconnect operation requires its own separate phase and
approval.

---

## 7. Compliance recap

- Entire audit offline: no HTTP/HTTPS, no sockets, no login, no scan, no
  downloads, no code execution of captured content, no replay.
- No `verify=False`, no warning suppression, no HTTP fallback, no secret
  logging introduced; no production-behavior change; no allowlist change.
- Report contains no credentials, tokens, cookies, proofs, keys or other
  sensitive values.
- Nothing committed or pushed; the working tree gains exactly one new
  file: this document.
- **No live modem interaction occurred in this audit. Live access is NOT
  authorized by this document and requires a separate explicit approval.**

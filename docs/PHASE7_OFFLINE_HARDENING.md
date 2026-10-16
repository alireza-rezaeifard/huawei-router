# Phase 7 — Offline Security Hardening & API Contract Tests

Branch: `phase-3-js-analysis`. Baseline HEAD at phase start:
`93e2e08a312022c893f74a14038e7265b44f5260` with a clean tree except the
Phase 6 doc (uncommitted, preserved). **Strictly offline:** no modem
contact, no live operation of any kind, no allowlist expansion — the only
behavior change is documented narrowing. **Nothing is committed or pushed
pending review.**

## 1. Baseline (recorded before any change)

- `git status --short --branch`: `## phase-3-js-analysis...origin/...` +
  `?? docs/PHASE6_API_RISK_AUDIT.md` (Phase 6 deliverable, left in place).
- Tests at baseline: `99 passed, 0 failed` (exit 0).
- Read: `api.py`, `tls.py`, `jsdownloader.py`, `errors.py`, `security.py`,
  `conftest.py`, `tests/test_api_safety.py`, `tests/test_jsdownloader.py`,
  Phase 5/6 docs. Phase 5's regex findings remain **not accepted as
  evidence** in this phase; nothing depends on them.

## 2. Files changed and reasons

| File | Change | Why |
|---|---|---|
| `src/huawei_tower/modem/api.py` | (a) `_WRITE_METHODS` += `connect`, `trace`; (b) new `max_response_bytes` constructor option with streaming enforcement inside `get()`; (c) `get()` now requests with `stream=True`, verifies status before reading the body, enforces the byte ceiling mid-stream, releases the connection in a `finally`, and materializes `_content` for the historical eager contract; (d) `/api/webserver/SesTokInfo` and `/api/webserver/token` moved from `SAFE_GET_ENDPOINTS` to `GATED_GET_ENDPOINTS` as classification `state_allocating` (new `Classification` literal) | (a) closes G-1; (b/c) closes G-3/G-4 and hardens G-5; (d) implements the Phase 6 audit finding that a GET on these identifiers is NOT side-effect-free (session/token allocation), task 4 of this phase |
| `tests/test_api_safety.py` | `FakeResponse` extended (additive: `headers`, `iter_content`, `close` — so existing tests exercise the new streaming contract); gated-classification set extended with `state_allocating`; nine-verb block test extended with `connect`/`trace` | keep the existing suite meaningful under the streamed client contract; no test was loosened or hidden (all previously-passing assertions still hold, e.g. `verified_read_only is True` for every SAFE entry, exact-set semantics) |
| `tests/test_phase7_hardening.py` | NEW: 25 tests (grouped G-1…G-6 + bootstrap reclassification + session wiring + downloader determinism extras) | closes the Phase 6 gap list with deterministic, mocked, offline tests |
| `docs/PHASE6_API_RISK_AUDIT.md` | gap ledger annotated with Phase 7 resolution status (G-1…G-6 closed, G-7/G-8 open) + audit-vs-implementation reconciliation note for the two bootstrap endpoints | documentation sync requested by this phase |
| `docs/PHASE7_OFFLINE_HARDENING.md` | NEW (this file) | deliverable |

`tests/test_jsdownloader.py` already covered same-destination concurrency /
unique temp files / no-clobber / cleanup deterministically
(`:284-395`); Phase 7 adds two extra no-leftover-`.part` determinism tests
 (`tests/test_phase7_hardening.py`) rather than duplicating the race.

## 3. What was closed (with evidence)

- **G-1 verbs:** `_WRITE_METHODS` now includes `connect`/`trace`
  (`api.py`); `__getattr__` covers all nine; test:
  `test_phase7_hardening.py::test_all_nine_write_and_unknown_verbs_blocked_fail_closed`
  (asserts zero session calls), plus
  `::test_connect_and_trace_added_to_blocked_method_tuple`.
- **G-2 path validation:** query strings/fragments (`?x=1`, `#frag`, `?`,
  combined) can never exact-match the allowlist even if their base path is
  an approved entry — tests
  `::test_query_strings_and_fragments_never_match_the_allowlist`,
  `::test_query_string_on_bootstrap_entry_is_rejected_too`.
- **G-3 timeout propagation:** default (8.0) and custom (3.5) timeouts are
  captured per request by a mocked session —
  `::test_default_timeout_is_forwarded_per_request`,
  `::test_custom_timeout_is_forwarded_per_request`; also asserts
  `stream=True` and `allow_redirects=False` forwarding
  (`::test_streaming_mode_is_declared_on_every_request`).
- **G-4 response-size policy:**
  - *Which responses need a limit:* the client's Tier-1 XML answers
    (`/api/device/basic_information`, counters, login-metadata). They are
    bounded server documents; a firmware bug or adversarial origin could
    stream unbounded data (memory pressure, secret-laden bodies). The
    downloader already enforced 8 MiB (`jsdownloader.py:52,269-275`); the
    API client had no ceiling (Phase 6 G-4).
  - *Enforcement while reading, not after buffering:* `get()` uses
    `stream=True` and consumes `iter_content(65536)` with a running byte
    total; a mid-stream exceed raises immediately and the `finally` closes
    the response — the oversized tail is never downloaded or buffered
    (`api.py` `get()`). Tests:
    `::test_oversized_response_abandoned_while_streaming` (connection
    released), `::test_exact_limit_passes_bytewise_and_off_limit_fails`
    (off-by-one determinism: exactly-at-limit passes, +1 byte fails),
    `::test_limit_can_be_explicitly_disabled_but_only_deliberately`,
    `::test_invalid_max_response_bytes_rejected_before_any_io` (0, -1,
    1.5, True, "64" all rejected pre-I/O), and
    `::test_interrupted_stream_raises_and_closes` (mid-read
    `ChunkedEncodingError` → `ModemHTTPError`, connection released).
  - *Compatibility impact (unavoidable, documented):* `get()` returns the
    same `requests.Response` with `.content/.text` eagerly materialized as
    before; the contract differences are (1) requests are now made with
    `stream=True`, (2) responses larger than `max_response_bytes` (default
    8 MiB; `None` = explicit disable) raise `ModemHTTPError` instead of
    returning, (3) interrupted transfers raise `ModemHTTPError` instead of
    surfacing urllib3 exceptions. No allowlist change; no path acceptance
    change.
- **G-5 error hygiene:** on any non-200 the body is NEVER read
  (status-checked before streaming) and the connection is closed —
  `::test_non_200_responses_are_never_even_streamed`; error text is
  asserted free of body/headers: `::test_http_error_text_never_embeds_body_or_headers`;
  forbidden-path rejections expose the path but no fabricated content —
  `::test_classified_dangerous_paths_yield_no_endpoint_data_in_errors`.
- **G-6 no logging:** source-scan proves neither `api.py` nor
  `jsdownloader.py` contains `print(`/`logging`/`logger`/`getLogger`/
  `.debug(`/`.warning(`/`.critical(`/`.error(` nor references
  `response.text/.content/.headers/.cookies` —
  `::test_modem_client_and_downloader_never_log_responses`,
  `::test_session_secret_names_never_appear_in_client_source_logging_context`.
- **Bootstrap reclassification (task 4):** GET on `/api/webserver/
  SesTokInfo` allocates a fresh session (and returns `SessionID`+token
  secrets); GET on `/api/webserver/token` consumes a single-use CSRF token
  from the server pool. Both are now `GATED_GET_ENDPOINTS` entries with
  `classification="state_allocating"`; the client refuses them like every
  other gated path. Prerequisites documented in the reason strings: a
  separately authorized authentication phase. Tests:
  `::test_bootstrap_endpoints_are_gated_state_allocating_not_unconditionally_read_only`,
  `::test_client_refuses_bootstrap_endpoints_and_every_classified_entry`,
  `::test_safe_allowlist_remains_strictly_verified_and_unexpanded`
  (Tier-1 set pinned to exactly 9 entries — cannot expand silently).
- **Session wiring:** falsey injected-session identity and usage proven
  across a full GET
  (`::test_falsey_injected_session_is_used_even_after_a_full_get`); the
  internally created session keeps `trust_env=False` and its own UA headers
  (`::test_internally_created_session_has_no_env_inheritance_and_own_headers`).
- **Downloader determinism extras:** sequential same-destination
  publication preserves bytes+mtime with zero `.part` litter
  (`::test_sequential_same_destination_publication_never_clobbers`); all
  error paths (XML-body, oversize, non-200, unapproved path) leave no
  `.part` files (`::test_error_download_paths_leave_no_part_files`).

## 4. Security & regression verification (task 5)

Grep over `src/` and `tests/` for
`verify=False|verify = False|disable_warnings|InsecureRequestWarning|
urllib3.disable|trust_env = True|allow_redirects=True|exec\(|eval\(`:
the ONLY hit is a test comment simulating the requests default
(`tests/test_jsdownloader.py:273`, asserting that the downloader then
FORCES it to False). Verified properties:

- HTTPS-only + mandatory certificate validation (`tls.py` unchanged;
  all 9 TLS pre-I/O rejection tests still pass).
- No `verify=False`, no TLS-warning suppression, no HTTP fallback, no
  proxy-environment bypass regression introduced.
- Redirects remain disabled on every request path (asserted per-call in
  `::test_streaming_mode_is_declared_on_every_request` and the pre-existing
  suites).
- Client stays default-deny; Tier-1 allowlist is pinned to exactly the
  same 9 entries as Phase 6 (two bootstrap entries moved OUT — narrowing,
  never expansion).
- No downloaded JavaScript is executed: no `exec(`/`eval(`/subprocess in
  any modem module; the analyzer reads bytes only.
- No credentials/tokens/cookies/live captures added anywhere: fixtures use
  synthetic values only (`SYNTHETIC-FAKE-VALUE`, `SYNTHETIC-COOKIE-BODY`,
  `// offline mocked test body`); error- and warning-free.

## 5. Exact test results (final suite run, nothing suppressed)

`python -m pytest` from the repo root:

```
124 passed, 0 failed, 0 skipped, ~4,855 warnings in ~1.2 s (Exit: 0)
```

- 99 baseline tests + 25 new (17 in `test_phase7_hardening.py`, plus the
  extended/updated cases in `test_api_safety.py` and the downloader extras
  in the same new file — exact split via `pytest --collect-only` on
  request). Warnings remain 100 % the user-global
  `pytest-asyncio` plugin deprecations under Python 3.14 (pre-existing,
  not project code, not suppressed, tests unmodified to make the run
  appear clean).

## 6. Remaining risks and limitations

- These are OFFLINE guarantees only. Nothing here establishes live-modem
  behavior: SCRAM round-trip, admin chunks, POST payloads, scan/lock
  semantics stay unverified (unchanged from Phase 6; G-7 still open).
- The streaming read relies on `requests`' `iter_content`; a hostile
  *server* could still trickle bytes slowly — bounded by the TCP read
  timeout but not by total wall-clock time (documented residual).
- `response._content` assignment depends on the requests internal
  attribute used to cache the body; pinned-contract behavior documented
  here; if a future requests release changes it, the eager-return
  contract degrades visibly (callers' `.content` re-reads the connection)
  — caught by the materialization tests.
- `max_response_bytes=None` deliberately allows unbounded bodies; source
  must set it explicitly, and that choice is visible in the constructor
  call (no silent default disable).

## 7. Compliance reconfirmations

- No real modem requests or connection attempts; no login/SCRAM/auth
  downloads/scans/Best Pair/band-cell lock/reboot/reconnect/registration/
  configuration changes; no JS execution; no secrets or live captures.
- No push, merge, or release; no allowlist expansion; NO live-phase
  authorization implied or granted.
- **No live modem access occurred in this phase.** Off-line tests prove
  only offline properties.

## 8. Review readiness

The branch is ready for review: working tree carries
`M src/huawei_tower/modem/api.py`, `M tests/test_api_safety.py`,
`?? tests/test_phase7_hardening.py`, `M docs/PHASE6_API_RISK_AUDIT.md`,
`?? docs/PHASE7_OFFLINE_HARDENING.md`, and the full suite is green at 124.
Commit only after the reviewer accepts this document and the diff.

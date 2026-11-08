# Phase 10 — Static API Discovery (Audit Only)

Status: **audit complete. No implementation, no live device contact, no source
change.** This document is the only artifact produced by Phase 10. Phase 10
implementation is **not started** and must not begin without explicit approval.

Branch at audit time: `phase-3-js-analysis`, tracking
`origin/phase-3-js-analysis`, clean working tree.
HEAD: `04df48b8f94c8249e45624e5d1bdfc8285121a92` (`phase 9: add
evidence-based device capability profile`).

> **Citation convention.** All four real JavaScript bundles are minified and
> keep their payload on physical line 2. A citation such as
> `main.js:2@118132` means *file `js__js_main.js_r_1709723942`, line 2, byte
> offset 118132* (0-based, counted on the UTF-8 decoded text). Offsets are
> provided so every claim can be re-checked mechanically. Capture files are
> cited by repository path. Python citations are 1-based source lines.

---

## 1. Executive summary

1. The firmware exposes a large symbolic endpoint map in `main.js`
   (`main.js:2@105330`, first entry `customUrl` at `main.js:2@105415`).
   Static count: **341 key→path entries, 334 unique paths**; raw path
   literals: **350 matches, 335 unique**, with 5 additional literals used
   outside the map. No duplicate map keys were found.
2. Every LTE-band, NR-band, band-frequency, cell and signal reference is a
   **name in that constant map only**. Of the four high-value names —
   `lteBandInfo`, `lockFreq`, `bandFreqList`, `cellInfo` — each occurs
   **exactly once** in `main.js`, inside the map. `singal` is the same.
3. The only *service* accessors that dispatch these reads live in
   `chunk_common.js` module `495:function` (`chunk_common.js:2@707520`):
   `getSingal` (`@707731`) and `getCellInfo` (`@708222`). Neither accessor is
   called anywhere in the retrievable bundles; their callers live in the
   admin chunks, which are **not JavaScript** (see §4).
4. **No NR band-capability endpoint exists anywhere.** There is no
   `nrBandInfo`, no `/api/net/nr-band-info`, no `/api/net/band-info`, and no
   `n78` / `n41` string in any real bundle. “5G” appears only as a
   *network-type label* derived from `CurrentNetworkTypeEx`
   (`chunk_common.js:2@593832`, `@594561`).
5. **No successful schema capture exists for any band, cell or signal
   endpoint.** The only related captures are gated error stubs
   (`100003` / `125002`). The three band-capability files that
   `evidence.py` expects (`_BAND_CAPTURE_SOURCES`, `evidence.py:77-82`) are
   **absent from disk**.
6. Consequently the Phase 9 profile correctly remains at **zero confirmed
   band slots**, with `n78` retained only as an `observed` historical fact
   (`evidence.py:613-644`). This audit found nothing that justifies promoting
   it.
7. **Security finding:** several of the most interesting paths are *not on
   the `api.py` allowlist at all* and therefore fall through the default-deny
   branch (`api.py:266`): `/api/net/lte-band-info`,
   `/config/network/bandfreqlist.xml`, `/config/network/net-mode.xml`,
   `/config/network/networkband_E5785-92a.xml`, `/config/global/net-type.xml`,
   `/config/global/config.xml`, `/api/version`, and `/api/app/operatorinfo`.
   They must stay blocked. `/api/app/operatorinfo` is especially notable: it
   was captured successfully (HTTP 200) yet is **not allowlisted**, so it is
   captured-but-unreachable by policy.
8. Recommended Phase 10 scope: **do not expand the callable surface.** Add
   fail-closed parsers for already-confirmed captures only, carry provenance
   through unchanged, keep GET-only bounded streaming, and keep every band /
   cell / signal path gated until an authenticated, sanitized capture exists.

---

## 2. Baseline

Verified before any write:

```text
$ git status --short --branch
## phase-3-js-analysis...origin/phase-3-js-analysis
$ git rev-parse HEAD
04df48b8f94c8249e45624e5d1bdfc8285121a92
$ git log --oneline -5
04df48b phase 9: add evidence-based device capability profile
9ddcf4e phase 8: restore offline Best Pair core workflow
7bf21b8 update
5faea1b phase 7: offline hardening - bounded streaming reads, verb/path hardening, bootstrap reclassification
f0b3493 Create PHASE6_API_RISK_AUDIT.md
```

Baseline facts:

- Working tree clean; the Phase 9 commit is present and is the parent of this
  audit.
- No uncommitted source, test, evidence, or endpoint-allowlist change exists.
- Phase 8 engine (`engine.py`) and Phase 9 evidence layer (`evidence.py`) are
  the current, approved behavior and are treated as read-only inputs here.
- Historical note: a stray 0-byte untracked file named `-Pattern` was removed
  earlier in this session to restore a clean tree; no tracked file was
  affected. This is the only filesystem mutation performed during Phase 10
  work, and it happened before the audit baseline was declared clean.

### 2.1 Scope discipline observed

- No modem contact, HTTP/HTTPS request, DNS, socket, scan, login, SCRAM,
  reconnect, reboot, lock, or configuration change.
- No JavaScript execution. Bundles were read as bytes and searched with
  literal/regular-expression matching only.
- No browser automation and no asset download; every input already existed in
  `evidence/raw/`.
- No source, test, allowlist, or Git configuration change; no commit, push,
  reset, amend, or checkout.
- No secret value is reproduced in this document.

---

## 3. Security architecture (`api.py`)

`src/huawei_tower/modem/api.py` remains the authoritative gate. The audit
re-read the file at HEAD `04df48b`; the following line references are exact.

### 3.1 Declared vocabulary

```text
api.py:12-18  Classification = Literal[
                  "verified_read_only", "plausible_read_only",
                  "state_allocating", "unsafe", "unknown"]
```

The task’s requested security classes are a normalized projection of this
vocabulary (§10.1). The code retains the original names.

### 3.2 Three-tier allowlist

| Tier | Location | Entries | Meaning |
|---|---|---|---|
| `SAFE_GET_ENDPOINTS` | `api.py:52-80` | 9 | `verified_read_only=True`; each observed HTTP 200 during discovery. |
| `GATED_GET_ENDPOINTS` | `api.py:84-178` | 12 | Known identifiers, deliberately not callable. Sub-classifications: `state_allocating` (`SesTokInfo`, `token`), `plausible_read_only`, and `unknown`. |
| `FORBIDDEN_PATHS` | `api.py:181-203` | 15 | Rejected before any I/O. Scan triggers, cell/band/PCI locks, registration hazards, auth POSTs. |

Safe list in order: `/api/device/basic_information` (53), `/api/net/current-plmn`
(56), `/api/monitoring/traffic-statistics` (59), `/api/dialup/connection`
(62), `/api/dialup/mobile-dataswitch` (65), `/api/pin/status` (68),
`/api/user/state-login` (71), `/api/global/module-switch` (74),
`/api/monitoring/check-notifications` (77).

Notable gated entries: `/api/webserver/SesTokInfo` (91, `state_allocating`),
`/api/webserver/token` (101, `state_allocating`),
`/api/monitoring/best-position-status` (113), `.../best-position-result` (120),
`/api/device/information` (127), `/api/monitoring/status` (134),
`/api/monitoring/converged-status` (141), `/api/net/cell-info` (147),
`/api/net/signal` (153), `/api/device/signal` (159), `/api/net/network` (165),
`/api/net/net-mode-list` (171).

Forbidden paths: `/api/monitoring/best-signal-position` (183),
`/api/monitoring/external-best-signal-position` (184),
`/api/monitoring/onekey_diag` (185), `/api/net/handle-cell` (187),
`/api/ntwk/celllock` (188), `/api/net/lock-freq` (189), `/api/net/net-mode`
(190), `/api/net/register` (192), `/api/net/reconnect` (193),
`/api/net/plmn-list` (194), `/api/dialup/dial` (195),
`/api/monitoring/start_date` (196), `/api/device/control` (197),
`/api/device/datalock` (198), plus three authentication POSTs (200-202).

### 3.3 Enforcement path

| Control | Location | Behavior |
|---|---|---|
| HTTPS required | `api.py:220-223` | Rejects non-`https` or missing host before I/O. |
| TLS fail-closed | `api.py:226` → `tls.py:67-98` | `verify_tls=False` is rejected at `tls.py:74-79`; never forwarded. |
| Size policy validation | `api.py:228-242` | Rejects bool/`0`/negative/non-int; `None` is the only documented disable. |
| No ambient proxies/credentials | `api.py:243-254` | Internally created session sets `trust_env = False`. Injected sessions are never modified. |
| Classification | `api.py:256-266` | Forbidden first (258), then safe (260), then gated (263), else default-deny (266). |
| GET-only execution | `api.py:268-330` | `session.get(...)`, `allow_redirects=False` (277), `stream=True` (278). |
| Bounded streaming | `api.py:288-308` | `_MAX_RESPONSE_BYTES = 8 MiB` (20), `_CHUNK = 65536` (21); aborts mid-read at 300-307. |
| Non-200 refusal before body | `api.py:291-297` | Status is safe to log; body/headers are never embedded. |
| Transfer exception policy | `api.py:309-312` | Only `requests.exceptions.RequestException` becomes `ModemHTTPError`; others propagate. |
| Connection release | `api.py:313-316` | `finally` closes the response. |
| Write-verb denial | `api.py:335-342` | Any `post/put/patch/delete/...` attribute raises `UnsafeOperationError`. `_WRITE_METHODS` at `api.py:205`. |

### 3.4 Consequence for band/cell/signal work

- `/api/net/lte-band-info` is **not** in any of the three tiers. It is
  therefore rejected by the fall-through at `api.py:266`.
- `/config/**` XML resources are also not in any tier, so the same
  default-deny applies. `urljoin` at `api.py:272` would happily build the URL,
  but classification happens first at `api.py:269-271`.
- `/api/net/lock-freq`, `/api/net/net-mode`, `/api/net/handle-cell`,
  `/api/ntwk/celllock`, `/api/net/register` and `/api/net/plmn-list` are
  forbidden (`api.py:187-194`), matching their mutation/registration risk.
- `/api/device/signal` and `/api/net/cell-info` are gated, not safe; they
  cannot be read by the current client even though they are plausibly
  read-only.

---

## 4. JavaScript inventory

### 4.1 Real JavaScript (6 files)

| File | Bytes | Role |
|---|---:|---|
| `evidence/raw/js__js_main.js_r_1709723942` | 276,923 | Application bundle: endpoint map, Vuex store, axios request layer. |
| `evidence/raw/chunk_common.js` | 734,833 | Shared service/helper modules, incl. module 495. |
| `evidence/raw/chunk_guide.js` | 211,260 | First-run guide / language flow. |
| `evidence/raw/chunk_login.js` | 10,000 | Login chunk (truncated capture). |
| `evidence/raw/lib_emui-crypto.js` | (crypto lib) | Crypto primitives; no API paths. |
| `evidence/raw/js__html_index.js` | 912 | Bootstrap index script; no API paths. |

`js__html_index.js` and `js__html_index.html` only rewrite
`/html/index.html` → `/` and load `../js/main.js?r=1709723942`
(`_html_index.html:10`).

### 4.2 Admin chunks are gated XML, not JavaScript

Every one of the following is a **94-byte** `<error><code>100003</code>`
stub — 90 bytes in the Phase 5 record — not code:

`chunk_lockband.js`, `chunk_mobilenetwork-mobilenetwork-vue.js`,
`chunk_mobilesearch-mobilesearch-vue.js`, `chunk_networkmode.js`,
`chunk_onekey-onekey-vue.js`, `chunk_comm.js`, `chunk_home-home-vue.js`,
`chunk_celllock-celllock-vue.js`, `chunk_cryptojs.js`, `js__js_app.js`.

This is the single largest evidence gap in the project: the pages that would
call the band/cell/signal accessors were never retrieved.

### 4.3 Endpoint map and request layer

| Element | Location |
|---|---|
| Endpoint map variable `b` begins | `main.js:2@105330` |
| First map entry (`customUrl`) | `main.js:2@105415` |
| Symbolic-name resolver `function i(e){var t=b[e]...}` | `main.js:2@127420` |
| `$get` implementation `var a=function(...)` | `main.js:2@128465` |
| GET verb `method:"get"` | `main.js:2@128909` |
| `Update-Cookie` injection for `/api/monitoring/status` | `main.js:2@128845` |
| `$post` verb `method:"post"` | `main.js:2@130523` |
| CSRF header `__RequestVerificationToken` | first at `main.js:2@126501`; GET path at `@128639`; POST at `@129710` |
| Vuex `configGet` / `commonGet` | `main.js:2@11428` / `@11577` |
| Vuex `commonPost` / `multiGets` | `main.js:2@11974` / `@12658` |
| `$request = {$get, $post, $all, DEBUG}` | `main.js:2@132441` |

Read chain: `commonGet` (`@11577`) → `$request.$get` (`@11651`) →
`$get` (`@128465`) → symbolic name resolved at `@127420` →
`axios({method:"get"...})` (`@128909`). Writes are a separate chain through
`$post` (`@130523`) and the CSRF token pool; they are out of scope for
Phase 10.

### 4.4 Target endpoint anchors (all in `main.js`, line 2)

| Symbolic key | Path literal | Key offset | Value offset |
|---|---|---|---:|---:|
| `globalNetType` | `/config/global/net-type.xml` | 106204 | 106219 |
| `convergedStatus` | `/api/monitoring/converged-status` | 106531 | 106548 |
| `globalModule` | `/api/global/module-switch` | 106631 | 106648 |
| `monitoringStatus` | `/api/monitoring/status` | 107615 | 107633 |
| `netCurrentPlmn` | `/api/net/current-plmn` | 107704 | 107720 |
| `deviceBasicInfo` | `/api/device/basic_information` | 109281 | 109298 |
| `globalConfig` | `/config/global/config.xml` | 110297 | 110311 |
| `userStateLogin` | `/api/user/state-login` | 110335 | 110354 |
| `getToken` | `/api/webserver/token` | 110172 | 110189 |
| `appOperatorinfo` | `/api/app/operatorinfo` | 110412 | 110430 |
| `singal` | `/api/device/signal` | 111546 | 111554 |
| `netMode` | `/api/net/net-mode` | 112558 | 112567 |
| `netType` | `/config/global/net-type.xml` | 112586 | 112595 |
| `netModeXml` | `/config/network/net-mode.xml` | 112671 | 112683 |
| `netModeList` | `/api/net/net-mode-list` | 112713 | 112726 |
| `network` | `/api/net/network` | 112750 | 112759 |
| `deviceInformation` | `/api/device/information` | 112777 | 112796 |
| `netRegister` | `/api/net/register` | 112815 | 112834 |
| `netPlmnList` | `/api/net/plmn-list` | 112847 | 112866 |
| `deviceNameUrl` | `/config/network/networkband_E5785-92a.xml` | 112886 | 112901 |
| `cellInfo` | `/api/net/cell-info` | 115813 | 115823 |
| `ntwk_celllock` | `/api/ntwk/celllock` | 116987 | 117005 |
| `handleCell` | `/api/net/handle-cell` | 117019 | 117037 |
| `bestPositionRes` | `/api/monitoring/best-position-result` | 117651 | 117669 |
| `moniBestSta` | `/api/monitoring/best-position-status` | 117770 | 117788 |
| `lteBandInfo` | `/api/net/lte-band-info` | 118119 | 118132 |
| `lockFreq` | `/api/net/lock-freq` | 118156 | 118166 |
| `bandFreqList` | `/config/network/bandfreqlist.xml` | 118186 | 118200 |
| `testSignalPosition` | `/api/monitoring/best-signal-position` | 118551 | 118569 |

`/api/version` has **no** map entry and no path literal in any bundle.
`/api/webserver/SesTokInfo` likewise has no bundle literal; only
`/api/webserver/token` and `/api/webserver/publickey` (`@111945`).

### 4.5 Service accessors in `chunk_common.js`

Module `495:function` starts at `chunk_common.js:2@707520`. Twelve accessors
wrap `commonGet`; the relevant ones:

| Accessor | Symbolic name | Offset |
|---|---|---:|
| `getFeatureSwitch` | `featureSwitch` | 707568 |
| `getSingal` | `singal` | 707731 |
| `getDeviceInformation` | `deviceInformation` | 707880 |
| `getMonitoringTraffic` | `monitoringTraffic` | 708051 |
| `getCellInfo` | `cellInfo` | 708222 |
| `getCspsState` | `cspsState` | 708375 |
| `getMonitoringStatus` | `monitoringStatus` | 708530 |
| `getWanInfo` | `wanInfo` | 708699 |
| `getDeviceInformationConfig` | `deviceInfoConfig` | 708850 |
| `getDeviceRi` | `deviceRi` | 709022 |
| `getVoiceInfo` | `voiceInfo` | 709175 |
| `getEid` | `simInfo` | 709330 |

Cross-bundle check: `getSingal` and `getCellInfo` each occur **once in total**
(the definition). No caller exists in `main.js`, `chunk_common.js`,
`chunk_guide.js`, or `chunk_login.js`. The caller pages are the missing admin
chunks.

`chunk_common.js` contains only two raw endpoint literals:
`/api/ntwk/uploadvpncerts` (`@332007`) and `/api/filemanager/upload`
(`@608516`). Every other call is symbolic.

`chunk_guide.js` contains zero raw `/api` or `/config` literals. Its five
`bandInfo` hits (`@159814`, `@161608`, `@161712`, `@166597`, `@168545`) are
substrings of `broadbandInfo`, not band capability.

---

## 5. LTE findings

**Static evidence present, behavioral evidence absent.**

- The only LTE-band identifier is the map entry
  `lteBandInfo: "/api/net/lte-band-info"` (`main.js:2@118119` key,
  `@118132` value). It occurs exactly once in the entire bundle.
- There is no `getLteBandInfo`-style accessor in `chunk_common.js`, no call
  site, and no response-field read such as `Band`, `BandList`, `WorkBand`, or
  `CurrentBand` anywhere in the retrievable JS.
- The string `LTE` appears in `chunk_common.js` only in network-type constant
  names and comments/labels:
  - `MACRO_NET_WORK_TYPE_EX_LTE` at `@593698` (label `"4G"`),
  - `MACRO_NET_WORK_TYPE_EX_LTE_PLUS` at `@593762` (`"4G+"`),
  - `MACRO_NET_WORK_TYPE_LTE` at `@594509`,
  - `MACRO_NET_WORK_TYPE_LTE_NR` at `@594561`.
  These are display labels derived from `CurrentNetworkTypeEx` /
  `CurrentNetworkType`, not band enumerations.
- `/api/net/lte-band-info` is **not** on the `api.py` allowlist of any tier;
  a GET would be rejected by `api.py:266`.
- `evidence.py:78` expects an `_api_net_lte-band-info.xml` capture. **No such
  file exists** (§9). The Phase 9 profile therefore has no LTE band slot.

Conclusion: LTE band capability is a *named but unproven* capability. It must
remain `static_reference_only` / `unknown`.

---

## 6. NR findings

**There is no NR capability endpoint.**

- No `nrBandInfo` identifier, no `/api/net/nr-band-info`, no
  `/api/net/band-info`, and no `nrband` / `nr_band` token in any of the six
  real bundles.
- No `n78`, `n41`, `n1`, `n3`, or `n28` band token. (`n1` substrings exist at
  `main.js:2@81585`, `@253599`, `@253623`, `@256110`, `@256163`, but they are
  unrelated identifiers, not band labels.)
- The only “5G” signals are UI labels from network-type constants:
  `MACRO_NET_WORK_TYPE_EX_NR` → `"5G"` (`chunk_common.js:2@593832`) and
  `MACRO_NET_WORK_TYPE_LTE_NR` → `"5G"` (`@594561`).
- `chunk_common.js:2@595855` reads `EndcStatus`, `@595885`/`@596160` read
  `SignalIconNr`, and `@595948` reads
  `globalModule.response.nrProductEnable`. These are:
  - `EndcStatus` — an EN-DC *state* flag;
  - `SignalIcon` / `SignalIconNr` — icon selectors;
  - `nrProductEnable` — a **product/UI toggle**, explicitly classified in
    `evidence.py:53-62` as *not* band-capability evidence.
  None of them enumerates an NR band.
- `Rat 7` in `_api_net_current-plmn.xml` proves NSA LTE+NR *mode* on the
  serving network (`evidence.py:22-24`); it does not prove a band.

Conclusion: NR capability is **unavailable**, not merely unverified. No Phase
10 code may invent an NR band list, and `n78` stays `observed` only.

---

## 7. Band-frequency findings (`bandfreqlist.xml`)

- The only reference is
  `bandFreqList: "/config/network/bandfreqlist.xml"` at
  `main.js:2@118186` (key) / `@118200` (value). One occurrence.
- No accessor, no call site, no parser, no schema. The XML element names of
  this file are **completely unknown**.
- There is no capture on disk. `evidence.py:81` lists it as an expected
  source; §9 confirms it is missing.
- The path is not allowlisted; a GET is default-denied at `api.py:266`.
- Related, equally unproven resources:
  `/config/network/net-mode.xml` (`main.js:2@112683`),
  `/config/network/networkband_E5785-92a.xml` (`@112901`),
  `/config/global/net-type.xml` (`@106219`, `@112595`),
  `/config/global/config.xml` (`@110311`).

Conclusion: band-frequency content is `static_reference_only` / `unknown`.
No inference about band support may be drawn from the filename, the
`E5785-92a` model suffix, or the `lockband` page name.

---

## 8. Cell and signal findings

### 8.1 Signal (`/api/device/signal`)

- Map entry `singal: "/api/device/signal"` at `main.js:2@111546` /
  `@111554`. One occurrence.
- `chunk_common.js` accessor `getSingal` at `@707731` dispatches
  `commonGet name:"singal"`.
- No caller, no response-field read. There is **no** `rsrp` / `rsrq` / `sinr`
  / `rssi` / `pci` / `earfcn` token in any bundle (case-insensitive scan of
  all six files returned zero). Phase 1 asserted RSRP/RSRQ/SINR/rssi
  (`docs/PHASE1_FINDINGS.md:103`) but that is **historical expectation**, not
  observed schema.
- `/api/device/signal` is gated (`api.py:159-164`), not safe.
- The separate gated placeholder `/api/net/signal` (`api.py:153-158`) is
  **contradicted**: it appears nowhere in JS, and the comment itself says the
  real path is `device/signal`.

### 8.2 Cell (`/api/net/cell-info`)

- Map entry `cellInfo: "/api/net/cell-info"` at `main.js:2@115813` /
  `@115823`. One occurrence.
- `chunk_common.js` accessor `getCellInfo` at `@708222`.
- No caller, no schema, no `ServingCell` / `NeighborCell` / `CellId` / `Pci`
  token in any bundle.
- Gated as `unknown` (`api.py:147-152`).
- No capture on disk.

### 8.3 Monitoring status / converged status (the actual field evidence)

These are the only endpoints with real field-level evidence, and both are
gated:

- `monitoringStatus` (`main.js:2@107633`) — fields observed in static reads:
  `ConnectionStatus`, `WifiConnectionStatus`, `batteryaconline`, `voice_busy`,
  `CurrentNetworkType`, `CurrentNetworkTypeEx`, `CurrentServiceDomain`,
  `ServiceStatus`, `RoamingStatus`.
  Anchors: `main.js:2@53237` (`CurrentNetworkType`), `@53261`
  (`CurrentNetworkTypeEx`), `@56629-56671` (`ConnectionStatus` /
  `WifiConnectionStatus`); `chunk_common.js:2@648010` (`batteryAcOnline`);
  `chunk_common.js:2@645458` (`voice_busy`).
- `netCurrentPlmn` (`main.js:2@107720`) — `Rat` at
  `chunk_common.js:2@397614` and `@648497`.
- `convergedStatus` (`main.js:2@106548`) — `CurrentLanguage` at
  `main.js:2@59697`, `chunk_common.js:2@471844`/`@657946`,
  `chunk_guide.js:2@1577`/`@13623`.
- `deviceInformation` — `ComponentList`, `Component`, `Version`,
  `SoftwareVersion`, `WebUIVersion` around `chunk_common.js:2@524759`.
- `deviceBasicInfo` — `classify`, `restore_default_status`,
  `captive_portal_guide_enable` around `main.js:2@59697`.

These fields are useful for connection/state display. They do **not** carry
band, cell identity, or RF measurements.

---

## 9. Capture correlation

Inventory of `evidence/raw/` at HEAD. Only non-JS captures are listed.

| Capture | Status | Error | Usable payload | Correlates to |
|---|---|---|---|---|
| `_api_device_basic_information.xml` | HTTP 200 | — | Yes: `productfamily`, `classify`, `multimode`, `restore_default_status`, `sim_save_pin_enable`, `devicename`, `spreadname_en/zh` | `/api/device/basic_information` |
| `_api_net_current-plmn.xml` | HTTP 200 | — | Yes: `State`, `FullName`, `ShortName`, `Numeric`, `Rat=7`, `Spn` | `/api/net/current-plmn` |
| `_api_global_module-switch.xml` | HTTP 200 | — | Yes: feature toggles (`ussd_enabled`, `sms_enabled`, `wifi_enabled`, …) | `/api/global/module-switch` |
| `_api_user_state-login.xml` | HTTP 200 | — | Yes: login capability metadata | `/api/user/state-login` |
| `_api_app_operatorinfo.xml` | HTTP 200 | — | Yes: JSON `{"OperatorName":""}` | `/api/app/operatorinfo` (not allowlisted) |
| `_api_dialup_connection.xml` | HTTP 200 | — | Yes | `/api/dialup/connection` |
| `_api_dialup_mobile-dataswitch.xml` | HTTP 200 | — | Yes | `/api/dialup/mobile-dataswitch` |
| `_api_pin_status.xml` | HTTP 200 | — | Yes | `/api/pin/status` |
| `_api_monitoring_traffic-statistics.xml` | HTTP 200 | — | Yes | `/api/monitoring/traffic-statistics` |
| `_api_monitoring_check-notifications.xml` | HTTP 200 | — | Yes | `/api/monitoring/check-notifications` |
| `_api_webserver_SesTokInfo.xml` | HTTP 200 | — | **Secret-bearing** (`SesInfo`, `TokInfo`); not quoted | `/api/webserver/SesTokInfo` (gated) |
| `_api_webserver_token.xml` | HTTP 200 | — | **Secret-bearing** (`token`); not quoted | `/api/webserver/token` (gated) |
| `_api_monitoring_status.xml` | HTTP 200 | `125002` | No — error stub | `/api/monitoring/status` (gated) |
| `_api_net_net-mode.xml` | HTTP 200 | `100003` | No — error stub | `/api/net/net-mode` (forbidden) |
| `_api_net_net-mode-list.xml` | HTTP 200 | `100003` | No — error stub | `/api/net/net-mode-list` (gated) |
| `_api_device_information.xml` | HTTP 200 | `100003` | No — error stub | `/api/device/information` (gated) |
| `_api_version.xml` | HTTP 200 | `100003` | No — error stub | `/api/version` (not allowlisted) |
| `_api_config_global_config_xml.xml` | HTTP 200 | `100003` | No — error stub | `/config/global/config.xml` (not allowlisted) |
| `_api_user_hilink_devicelist.xml` | HTTP 200 | `100003` | No — error stub | `/api/user/hilink-device-list` |
| `_api_device_usb-tethering-switch.xml` | HTTP 200 | `100002` | No — error stub | `/api/device/usb-tethering-switch` |

### 9.1 Missing captures (the critical gaps)

None of the following exists in `evidence/raw/` or `evidence/fixtures/`:

- `_api_net_lte-band-info.xml` (expected by `evidence.py:78`)
- `_api_net_nr-band-info.xml` (`evidence.py:79`)
- `_api_net_band-info.xml` (`evidence.py:80`)
- `config/network/bandfreqlist.xml` (`evidence.py:81`)
- `_api_net_cell-info.xml`
- `_api_device_signal.xml`
- `_api_monitoring_converged-status.xml`
- `_api_net_network.xml`
- `_api_net_register.xml`, `_api_net_plmn-list.xml`
- `/config/network/net-mode.xml`, `/config/network/networkband_E5785-92a.xml`,
  `/config/global/net-type.xml`

Phase 9 fixtures are only two minimal files:
`evidence/fixtures/device_basic_information.xml` (169 bytes) and
`evidence/fixtures/current_plmn.xml` (126 bytes). Neither contains band data.

### 9.2 What correlation proves

- Identity, PLMN/RAT, feature flags and login state are **directly verified**.
- Connection/network-type fields are **statically verified but not captured**
  (the capture is a `125002` stub).
- Band, cell, RF and NR capability are **not correlated at all**.

---

## 10. Classification matrix

### 10.1 Security-class mapping

`api.py` uses its own literals (`api.py:12-18`). The normalized classes
requested for Phase 10 map as follows:

| Requested class | Meaning here | `api.py` counterpart |
|---|---|---|
| `read_only_verified` | Allowlisted safe GET **and** a successful capture/observation exists | `verified_read_only` in `SAFE_GET_ENDPOINTS` |
| `read_candidate_unverified` | Plausibly read-only, no successful capture, not callable | `plausible_read_only` |
| `mutation` | Known write/registration/lock path | `FORBIDDEN_PATHS` |
| `gated` | Known identifier deliberately not callable by this client | `GATED_GET_ENDPOINTS` (any sub-class) |
| `forbidden` | Rejected before I/O for safety | `FORBIDDEN_PATHS` |
| `unknown` | Not on any tier → default-deny | fall-through at `api.py:266` |

`mutation` and `forbidden` overlap by design: every forbidden path here is a
mutation or a scan/registration hazard. In the matrix, write paths are marked
`mutation` and non-write hazards (scan triggers) are marked `forbidden`.

### 10.2 Endpoint matrix

`E-class` = endpoint evidence class; `Sec` = normalized security class.
`GET` is the only method the current client can issue.

| # | Path | Method | Source (file:line@offset) | Symbol / component | Params / body | Response fields used | R/W | UI feature | Conf. | E-class | Sec |
|---|---|---|---|---|---|---|---:|---|---|---|---|
| 1 | `/api/device/basic_information` | GET | `main.js:2@109298` | `deviceBasicInfo` → `commonGet` | none | `classify`, `restore_default_status`, `captive_portal_guide_enable`, `devicename` | read | device identity / restore gating | high | `confirmed_capture` | `read_only_verified` |
| 2 | `/api/net/current-plmn` | GET | `main.js:2@107720` | `netCurrentPlmn` → `getCradlePlmn` `chunk_common:2@711789` | none | `State`, `FullName`, `ShortName`, `Numeric`, `Rat`, `Spn` | read | serving operator / RAT | high | `confirmed_capture` | `read_only_verified` |
| 3 | `/api/global/module-switch` | GET | `main.js:2@106648` | `globalModule` | none | `nrProductEnable`, `cradle_enabled`, `wifioffload_enabled`, `sa_enable`, … | read | feature gating | high | `confirmed_capture` | `read_only_verified` |
| 4 | `/api/user/state-login` | GET | `main.js:2@110354` | `userStateLogin` | none | login-state metadata | read | login page | high | `confirmed_capture` | `read_only_verified` |
| 5 | `/api/monitoring/traffic-statistics` | GET | `api.py:59` (no map literal) | safe wrapper | none | traffic counters | read | traffic page | high | `confirmed_capture` | `read_only_verified` |
| 6 | `/api/dialup/connection` | GET | capture only | safe wrapper | none | dial config | read | dial settings | high | `confirmed_capture` | `read_only_verified` |
| 7 | `/api/dialup/mobile-dataswitch` | GET | capture only | safe wrapper | none | `dataswitch` | read | data toggle | high | `confirmed_capture` | `read_only_verified` |
| 8 | `/api/pin/status` | GET | capture only | safe wrapper | none | `SimState`, `PinOptState`, … | read | SIM PIN | high | `confirmed_capture` | `read_only_verified` |
| 9 | `/api/monitoring/check-notifications` | GET | capture only | safe wrapper | none | notification counters | read | notification badge | high | `confirmed_capture` | `read_only_verified` |
| 10 | `/api/webserver/SesTokInfo` | GET | `api.py:91-100` | bootstrap | none | `SesInfo`, `TokInfo` (**secrets**) | read + state allocation | login bootstrap | high | `confirmed_capture` | `gated` |
| 11 | `/api/webserver/token` | GET | `main.js:2@110189` | `getToken` | none | `token` (**secret**) | read + state allocation | CSRF bootstrap | high | `confirmed_capture` | `gated` |
| 12 | `/api/monitoring/status` | GET | `main.js:2@107633` | `monitoringStatus` | none; **sends `Update-Cookie: UpdateCookie`** (`@128845`) | `ConnectionStatus`, `WifiConnectionStatus`, `CurrentNetworkType(Ex)`, `ServiceStatus`, `RoamingStatus`, `voice_busy`, `batteryaconline` | read (cookie refresh) | home status | high (fields) / low (behavior) | `unavailable` | `gated` |
| 13 | `/api/monitoring/converged-status` | GET | `main.js:2@106548` | `convergedStatus` | none | `CurrentLanguage` | read | language / converged UI | medium | `static_reference_only` | `read_candidate_unverified` |
| 14 | `/api/device/information` | GET | `main.js:2@112796` | `deviceInformation` | none | `ComponentList`, `Component`, `Version`, `SoftwareVersion`, `WebUIVersion` | read | firmware info | medium | `unavailable` | `read_candidate_unverified` |
| 15 | `/api/device/signal` | GET | `main.js:2@111554` | `singal` → `getSingal` `chunk_common:2@707731` | none | none observed in JS | read | signal page (missing) | low | `static_reference_only` | `read_candidate_unverified` |
| 16 | `/api/net/signal` | GET | `api.py:153-158` only | placeholder | none | none | unknown | none | none | `contradicted` | `gated` |
| 17 | `/api/net/cell-info` | GET | `main.js:2@115823` | `cellInfo` → `getCellInfo` `chunk_common:2@708222` | none | none observed in JS | read? | cell info page (missing) | low | `static_reference_only` | `gated` (api class `unknown`) |
| 18 | `/api/net/lte-band-info` | GET | `main.js:2@118132` | `lteBandInfo` | none known | none known | unknown | band lock page (missing) | low | `static_reference_only` | `unknown` |
| 19 | `/api/net/nr-band-info` | — | none anywhere | — | — | — | unknown | none proven | none | `unavailable` | `unknown` |
| 20 | `/api/net/band-info` | — | none anywhere | — | — | — | unknown | none proven | none | `unavailable` | `unknown` |
| 21 | `/api/net/lock-freq` | GET/POST? | `main.js:2@118166` | `lockFreq` | unknown | unknown | **write (band lock)** | band lock page (missing) | medium | `static_reference_only` | `mutation` / `forbidden` (`api.py:189`) |
| 22 | `/api/net/net-mode` | GET/POST | `main.js:2@112567` | `netMode` | `NetworkMode`? schema unknown | unknown | **write** | network mode page (missing) | medium | `static_reference_only` | `mutation` / `forbidden` (`api.py:190`) |
| 23 | `/api/net/net-mode-list` | GET | `main.js:2@112726` | `netModeList` | none | axis list, schema unknown | read | network mode page | low | `unavailable` | `read_candidate_unverified` (gated `api.py:171`) |
| 24 | `/api/net/network` | GET | `main.js:2@112759` | `network` | none known | none known | unknown | net select page | low | `static_reference_only` | `gated` (api class `unknown`) |
| 25 | `/api/net/register` | — | `main.js:2@112834` | `netRegister` | unknown | unknown | **network registration** | manual register | medium | `static_reference_only` | `mutation` / `forbidden` (`api.py:192`) |
| 26 | `/api/net/plmn-list` | GET | `main.js:2@112866` | `netPlmnList` | unknown | unknown | **triggers scan/re-registration** | manual network search | medium | `static_reference_only` | `forbidden` (`api.py:194`) |
| 27 | `/api/net/handle-cell` | — | `main.js:2@117037` | `handleCell` | unknown | unknown | **CA/band op write** | admin cell page | medium | `static_reference_only` | `mutation` / `forbidden` (`api.py:187`) |
| 28 | `/api/ntwk/celllock` | — | `main.js:2@117005` | `ntwk_celllock` | unknown | unknown | **PCI/cell lock write** | admin celllock | medium | `static_reference_only` | `mutation` / `forbidden` (`api.py:188`) |
| 29 | `/api/monitoring/best-signal-position` | — | `main.js:2@118569` | `testSignalPosition` | unknown | unknown | **scan trigger** | best-signal scan | medium | `static_reference_only` | `forbidden` (`api.py:183`) |
| 30 | `/api/monitoring/best-position-status` | GET? | `main.js:2@117788` | `moniBestSta` | unknown | `<status>`-like, unknown | read? | scan polling | low | `static_reference_only` | `read_candidate_unverified` (gated `api.py:113`) |
| 31 | `/api/monitoring/best-position-result` | GET? | `main.js:2@117669` | `bestPositionRes` | unknown | frequency/PCI/RSRP? unknown | read? | scan result | low | `static_reference_only` | `read_candidate_unverified` (gated `api.py:120`) |
| 32 | `/config/network/bandfreqlist.xml` | GET | `main.js:2@118200` | `bandFreqList` | none | XML schema unknown | read (static resource) | band lock page | low | `static_reference_only` | `unknown` |
| 33 | `/config/network/net-mode.xml` | GET | `main.js:2@112683` | `netModeXml` | none | XML schema unknown | read | network mode page | low | `static_reference_only` | `unknown` |
| 34 | `/config/network/networkband_E5785-92a.xml` | GET | `main.js:2@112901` | `deviceNameUrl` | none | XML schema unknown | read | band display | low | `static_reference_only` | `unknown` |
| 35 | `/config/global/net-type.xml` | GET | `main.js:2@106219`, `@112595` | `globalNetType`, `netType` | none | XML schema unknown | read | network type list | low | `static_reference_only` | `unknown` |
| 36 | `/config/global/config.xml` | GET | `main.js:2@110311` | `globalConfig` | none | XML schema unknown | read | global config | low | `unavailable` | `unknown` |
| 37 | `/api/version` | GET | `docs/PHASE1_FINDINGS.md:37`; capture `_api_version.xml` | — | none | none (100003) | read | firmware version | none | `unavailable` | `unknown` |
| 38 | `/api/app/operatorinfo` | GET | `main.js:2@110430` | `appOperatorinfo` | none | `OperatorName` | read | operator name | high | `confirmed_capture` | `unknown` (not allowlisted) |

### 10.3 Non-endpoint claims

| Claim | Evidence | Class | Note |
|---|---|---|---|
| Serving network uses NSA LTE+NR (`Rat=7`) | `_api_net_current-plmn.xml` | `confirmed_capture` | Proves mode only; **not** a band. |
| `n78` observed | `docs/PHASE1_FINDINGS.md:15` | `historical_documentation` | Single historical observation; no capture, no JS reference. Must stay `observed`. |
| “5G CPE Pro 5” / H158-381 identity | `_api_device_basic_information.xml` | `confirmed_capture` | Product identity, not capability. |
| `nrProductEnable` etc. are band capability | `chunk_common.js:2@595948`; `evidence.py:53-62` | `contradicted` | Product toggles; explicitly excluded from band evidence. |
| `/api/net/signal` is a real endpoint | `api.py:153-158` | `contradicted` | No JS/doc/capture reference; real name is `/api/device/signal`. |

---

## 11. Evidence gaps

Ordered by impact on any future band-aware feature:

1. **No authenticated JS.** All ten admin chunks are 94-byte `100003` stubs
   (§4.2). Without them, no call site, parameter name, or response schema for
   band/cell/signal pages can be known.
2. **No band capture.** `_api_net_lte-band-info.xml`,
   `_api_net_nr-band-info.xml`, `_api_net_band-info.xml`, and
   `config/network/bandfreqlist.xml` are all absent (§9.1). `evidence.py`
   already models this correctly as a gap.
3. **No cell/signal capture.** `/api/net/cell-info` and
   `/api/device/signal` have neither capture nor field names.
4. **No authenticated status capture.** `/api/monitoring/status` returns
   `125002`; converged status has no capture at all.
5. **NR capability is undefined.** There is no NR band endpoint to capture.
   Any future NR work must first establish whether the firmware exposes one.
6. **Policy gap is not a data gap.** Even if a capture appeared, the current
   client could not fetch it: none of the band/cell/config paths is
   allowlisted (§3.4).
7. **Historical docs vs verified evidence.** Phase 1 lines 96-117 describe
   `cellInfo`, `lockFreq`, `lteBandInfo`, `bandFreqList`, RSRP/RSRQ/SINR, and
   band lock as “present in the map”. That is a *map* observation. Phase 1
   line 15’s `n78` is a *prior-session* observation. Neither is a verified
   schema, and neither may be promoted by Phase 10.
8. **`/api/app/operatorinfo` asymmetry.** It is captured successfully but not
   allowlisted. This is a deliberate default-deny outcome, not an oversight to
   “fix” in Phase 10.

---

## 12. Recommended Phase 10 implementation plan

The recommendation is deliberately minimal. It preserves every existing
control and adds **no** callable endpoint.

### 12.1 Non-negotiable constraints

- Keep `ReadOnlyModemClient` GET-only, exact-path allowlisted, redirect-free,
  bounded-streaming, and default-deny (`api.py:256-330`).
- Keep `_MAX_RESPONSE_BYTES` and `_CHUNK` unchanged unless a demonstrated
  defect requires otherwise.
- Keep TLS verification fail-closed (`tls.py:67-98`).
- Keep provenance and the `observed` vs `confirmed` split
  (`evidence.py:40`, `:613-644`).
- Do **not** promote any `observed` fact, JS name, UI option, product flag, or
  firmware string to `confirmed`.
- Do **not** change the scoring/ranking engine without a demonstrated defect.

### 12.2 Proposed sequence

| Step | Work | Safety property |
|---:|---|---|
| 1 | Freeze baseline: record HEAD, clean tree, test count. | Reproducibility. |
| 2 | Add fail-closed parsers **only** for the five successful captures: `basic_information`, `current-plmn`, `global/module-switch`, `state-login`, `app/operatorinfo`. Each parser rejects missing/unknown fields and returns an explicit gap. | No schema guessing. |
| 3 | Thread provenance through the new parsers using the existing `EvidenceFact` model (`evidence.py`). | Every value traceable to file + locator. |
| 4 | Extend tests for: gated captures, `100003`/`125002`/`100002` stubs, absent band files, `Rat=7` mode-only, and no band promotion. | Regression + fail-closed proof. |
| 5 | Document the gap table (§11) as machine-readable/tested behavior, not prose only. | Gaps cannot silently disappear. |
| 6 | Leave all band/cell/signal endpoints gated/forbidden/unknown exactly as today. | Zero surface expansion. |
| 7 | Stop and hand off for review. | No live phase implied. |

### 12.3 Explicit non-goals

- No `/api/net/lte-band-info`, `nr-band-info`, `band-info`, `cell-info`,
  `device/signal`, `lock-freq`, `net-mode`, `net-mode-list`, `network`,
  `register`, `plmn-list`, `handle-cell`, `celllock`, `best-*`, or `/config/**`
  enablement.
- No authenticated session, login, SCRAM, token bootstrap, or capture.
- No new scoring inputs, band slots, or rank weights.
- No inference from `nrProductEnable`, `EndcStatus`, `SignalIconNr`,
  `sa_enable`, `celllock_enabled`, `bestsignal_enable`, or `Rat=7`.
- No change to `SAFE_GET_ENDPOINTS`, `GATED_GET_ENDPOINTS`, or
  `FORBIDDEN_PATHS`.

### 12.4 Acceptance criteria for Phase 10

1. `git diff` shows only the intended new parser/tests/doc changes.
2. All new parsers reject malformed, gated, and unknown-field inputs.
3. No endpoint becomes callable that was not callable at HEAD `04df48b`.
4. Every new derived fact carries `source_file` + `locator`.
5. Band slots remain zero-confirmed; `n78` remains `observed`.
6. Full offline test suite passes.

---

## 13. Safety and risk

### 13.1 What this audit did and did not do

- Read-only, offline analysis of existing repository files.
- No modem contact, no HTTP/HTTPS, no DNS, no socket, no scan, no lock, no
  reconnect, no reboot, no configuration change.
- No JS execution, no browser automation, no asset download.
- No source, test, allowlist, or Git-config change; no commit/push.

### 13.2 Residual risks if Phase 10 is implemented carelessly

| Risk | Why it matters | Mitigation |
|---|---|---|
| Enabling a band path to “test” it | `lock-freq`, `net-mode`, `handle-cell`, `celllock`, `register`, `plmn-list` can change radio state or trigger re-registration | Keep `FORBIDDEN_PATHS` unchanged; no live probing. |
| Treating `nrProductEnable` / `EndcStatus` / `Rat=7` as band proof | Would fabricate capability and mis-rank pairs | Enforce the existing `evidence.py` exclusion and add a regression test. |
| Guessing `bandfreqlist.xml` structure | A wrong parser can silently drop bands or invent them | Fail closed on unknown elements; mark the source unavailable. |
| Promoting JS names to confirmed | A name in a bundle is not a device fact | Keep `candidate` / `static_reference_only` labeling. |
| Unbounded response reading | Memory exhaustion from a large XML/HTML error page | Keep `8 MiB` streamed cap (`api.py:20`, `:298-307`). |
| Redirect or proxy leakage | Could exfiltrate session material or reach an unintended host | Keep `allow_redirects=False` (`api.py:277`) and `trust_env=False` (`api.py:249`). |
| Embedding secrets in logs/docs | `SesTokInfo` / `token` captures contain secrets | Never quote them; `security.py:36-41` redaction stays in force. |

### 13.3 Bottom line

The device’s real, verified read surface is small and already correctly
modeled. Band, NR, cell, and RF-signal capability are **named but not
evidenced**, and the most tempting endpoints are either gated, forbidden, or
default-denied. Phase 10 should therefore **harden and document**, not expand.

---

## Appendix A — Verification commands run

```text
git status --short --branch
git log --oneline -5
git rev-parse HEAD
```

Static inspection methods: byte-offset literal search and anchored regular
expressions over the six real JS files; line/byte citations recorded above.
No code was executed and no network I/O occurred.

## Appendix B — Files intentionally not modified

`src/huawei_tower/modem/api.py`, `tls.py`, `security.py`, `errors.py`,
`jsdownloader.py`, `src/huawei_tower/bestpair/engine.py`,
`src/huawei_tower/bestpair/evidence.py`, all tests, all evidence files, and
all Git configuration. This document is the only new file.

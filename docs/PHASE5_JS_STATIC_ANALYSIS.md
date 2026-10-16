# Phase 5 — Offline JavaScript Static Analysis

Branch: `phase-3-js-analysis`. **Strictly offline**: no HTTP/HTTPS request, no
socket, no login/SCRAM, no asset download, no scan, no configuration change,
no execution of any analyzed code. The analyzer reads only local evidence
files that the caller names, one `read_bytes()` per file, and never writes to
them.

## What was built

`src/huawei_tower/modem/jsanalysis.py` — a small, testable, string-presence
static analyzer:

- **Input policy (fail-closed)**: only existing regular files; rejects
  missing paths, directories, empty files, files over
  `MAX_INPUT_BYTES` (32 MiB), and — by default — any non-UTF-8 bytes
  (`AnalysisInputError`, see tests). Minified firmware bundles that contain
  stray non-UTF-8 bytes can be analyzed with the explicit, documented
  `encoding_mode='replace'`; the report metadata then marks the file
  `utf-8-errors=replace` so results are weighed accordingly.
- **No-semantic-claim policy**: every finding is labeled
  - `candidate` — a string/identifier is present in the text (endpoints,
    auth symbols, session-material names, module references, management
    operation names), or
  - `unverified` — a write HTTP-method call site (`.post(` / `.put(` /
    `.delete(` / `.patch(` / `.request(`) is present; its target URL is
    generally elsewhere in the minified line, so the *binding between
    method and endpoint is NOT established by this tool*.
  String presence is never treated as firmware truth.
- **Extraction kinds**: `endpoint` (string literals under `/api/`, `/config/`,
  `/html/`, `/js/`, `/lib/`, `/css/`), `write_method_call`, `auth_symbol`
  (SCRAM/PBKDF2/HMAC identifiers), `session_material` (token/cookie/CSRF
  *names only* — values are never captured), `module_ref` (webpack/
  require/localStorage construction), `management_candidate` (scan/lock/
  registration/diagnostics operation names).
- **Referenceability**: every value carries one or more
  `file:line:byte-offset` refs, plus a per-file sha256 in the metadata so a
  reader can re-verify the exact analyzed artifact.
- **Redaction**: all extracted values pass through
  `huawei_tower.modem.security.redact_secrets` and a standalone
  opaque-string filter (hex ≥16 chars / base64-like ≥28 chars are replaced
  by `<redacted>`). Cookie/token/password/key values cannot reach a report
  even if present in a bundle.
- **Output**: `analyze_files(paths) -> dict` (JSON-serializable),
  `to_json(report)` and `to_markdown(report)` for review documents.
- **Determinism/no network**: pure local computation; guarded by the
  suite-wide socket/DNS blocker; a source scan test additionally asserts the
  module imports no HTTP/socket libraries. A suite test analyzes the *real*
  in-repo evidence and asserts the input files' bytes are untouched.

## Usage

```python
from huawei_tower.modem.jsanalysis import analyze_files, to_json, to_markdown

report = analyze_files(["evidence/raw/js__js_main.js_r_1709723942"])            # strict UTF-8
report = analyze_files(files, encoding_mode="replace")                          # minified bundles
print(to_json(report)); print(to_markdown(report))
```

## Confirmed vs hypothesis (mandatory split)

**Confirmed from existing code (offline):**
- The presence of the documented endpoints/symbols below at the cited
  `file:line:offset` locations, and the sha256 of each analyzed file.

**Hypothesis only (NOT confirmed by this tool):**
- That any endpoint is callable, side-effect-free, or bound to a particular
  HTTP method. `write_method_call` findings are positional, not linked.
- That any `management_candidate` actually performs a scan/lock/registration
  operation; caller pages for these are still missing (their chunks exist
  locally only as the XML `100003` error stubs).
- That redacted values (e.g. long hex segments redacted inside paths) had
  any particular meaning; defensiveness removes context, deliberately.

## Narrow static analysis — limitations

1. Regex-based extraction over minified bundles: no AST, no control-flow,
   no cross-statement binding of method→URL; minified lines are hundreds of
   kilobytes, so refs are `line@offset`, not statements.
2. `encoding_mode='replace'` can merge replacement characters into adjacent
   captures; endpoints extracted from a lossy file are marginally less
   trustworthy and the metadata says so.
3. The opaque-value redaction can hide an entire path if it embeds a long
   base64-like string (seen in the real report as `/<redacted>` values);
   the tool refuses to speculate about such values.
4. No coverage claim: absence of a string in findings does not mean absence
   in the firmware; it means the pattern did not match this bundle.

## Evidence sufficiency and gap report

Locally analyzable real bundles: `chunk_common.js` (733 KB), `chunk_guide.js`
(211 KB), `js__js_main.js_r_1709723942` (276 KB), `chunk_login.js` (10 KB),
`lib_emui-crypto.js` (355 KB) plus the two HTML shells. The remaining files
in `evidence/raw/` are the unauthenticated server responses (HTTP 200 +
XML `100003`) for the six admin chunks — they carry **no page code**, so the
scan/lock page logic remains unanalyzable offline. Summary of what the
analyzer can and cannot close offline:

- ✅ Full endpoint inventory of the device UI bundle (324 unique paths).
- ✅ Independent confirmation of the SCRAM flow symbols documented in
  Phase 3 (identical file/offset anchors).
- ✅ Webpack loading scheme confirmation (`webpackJsonp`, `i.p=`, chunk refs).
- ❌ Method↔endpoint binding, page logic of the admin chunks, confirmation
  of any side effect — all require code we do not possess; **no attempt was
  made to fetch it** (that would require the future authorized live phase).

Notable *new* candidates surfaced by this pass (all `candidate`,
not previously triaded in the Phase 3 classification because they are new to
the offline lens — they change nothing in the shipped allowlists):

- `/api/user/password_scram` (main.js @110226/@131516) — SCRAM password
  reset path (POST only per name semantics; unknown; stays outside every
  applicable endpoint list until a live phase proves otherwise).
- `/config/network/bandfreqlist.xml`, `/config/network/net-mode.xml` and the
  full `/config/**` map — static XML resources fetched by the UI with plain
  GET; usable offline considerations but unverified side effects, unlisted.
- `.post(` binding only found at `chunk_common.js:2@332000` — i.e. the
  axios post wrapper; still unlinked to URLs (expected for minified code).
- `/api/developer/*` family (AT port status, modem logs, upload-runlog,
  `device/control`, `device/datalock`, `diagnosis/time_reboot`,
  `diagnosis/diagnose_ping` / `diagnose_traceroute`) — dangerous-looking
  device-management endpoints are present in the bundle; ALL stay outside
  the read-only allowlist (forbidden/absent by default).

## Compliance recap

- Evidence files: opened read-only; hash-verified unchanged by tests.
- Analyzer never networks: suite guard + source-scan test prove it.
- No secrets: redaction pipeline tests + report scan (`<redacted>` only).
- No live modem access occurred in this phase (none is authorized).

---

## Appendix — auto-generated report from the real evidence

(output of `to_markdown(analyze_files(evidence/raw/{*.js,*.html…},
encoding_mode='replace'))`; refs are `file:line@byte-offset`,
sha256s truncated to 16 hex chars)

# Offline JS static-analysis report

> Generated by `huawei_tower.modem.jsanalysis`. **Every finding is
> `candidate`/`unverified` string presence, never firmware truth.**

## Input files

| file | bytes | lines | sha256 |
|---|---|---|---|
| `evidence\raw\_html_index.html` | 916 | 12 | `fdf19624d5df3a47…` |
| `evidence\raw\_root_session.html` | 3076 | 38 | `ce26ffb4edf697ac…` |
| `evidence\raw\chunk_celllock-celllock-vue.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\chunk_comm.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\chunk_common.js` | 733636 | 3 | `e3905200d5ce280d…` |
| `evidence\raw\chunk_cryptojs.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\chunk_guide.js` | 211137 | 3 | `55c281310e0775a2…` |
| `evidence\raw\chunk_home-home-vue.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\chunk_lockband.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\chunk_login.js` | 10001 | 3 | `08622b30f4d69b97…` |
| `evidence\raw\chunk_mobilenetwork-mobilenetwork-vue.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\chunk_mobilesearch-mobilesearch-vue.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\chunk_networkmode.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\chunk_onekey-onekey-vue.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\js__html_index.js` | 916 | 12 | `fdf19624d5df3a47…` |
| `evidence\raw\js__js_app.js` | 90 | 7 | `1dd3c4c216aa65cb…` |
| `evidence\raw\js__js_main.js_r_1709723942` | 276480 | 3 | `bd5095a631774ec8…` |
| `evidence\raw\lib_emui-crypto.js` | 355329 | 10975 | `94976b1f325968fd…` |

## Findings

### `endpoint` — confidence: **candidate** (324 unique values)

- `/<redacted>` — `js__js_main.js_r_1709723942:2@109959`, `js__js_main.js_r_1709723942:2@110007`, `js__js_main.js_r_1709723942:2@117928`, `js__js_main.js_r_1709723942:2@117974`, `js__js_main.js_r_1709723942:2@118048`, `js__js_main.js_r_1709723942:2@118750` (+4 more)
- `/<redacted>.xml` — `js__js_main.js_r_1709723942:2@106014`, `js__js_main.js_r_1709723942:2@114646`, `js__js_main.js_r_1709723942:2@118464`
- `/api/app/operatorinfo` — `js__js_main.js_r_1709723942:2@110429`
- `/api/app/privacypolicy` — `js__js_main.js_r_1709723942:2@110388`
- `/api/cradle/basic-info` — `js__js_main.js_r_1709723942:2@107201`
- `/api/cradle/current-mac` — `js__js_main.js_r_1709723942:2@107237`
- `/api/cradle/eth-detect` — `js__js_main.js_r_1709723942:2@118710`
- `/api/cradle/factory-mac` — `js__js_main.js_r_1709723942:2@107165`
- `/api/cradle/feature-switch` — `js__js_main.js_r_1709723942:2@107125`
- `/api/cradle/mac-info` — `js__js_main.js_r_1709723942:2@107088`
- `/api/cradle/status-info` — `js__js_main.js_r_1709723942:2@107436`
- `/api/cwmp/basic-info` — `js__js_main.js_r_1709723942:2@115741`
- `/api/ddns/ddns-list` — `js__js_main.js_r_1709723942:2@111616`
- `/api/ddns/serverlist` — `js__js_main.js_r_1709723942:2@111584`
- `/api/ddns/status` — `js__js_main.js_r_1709723942:2@111649`
- `/api/devcapacity/devcapacity` — `js__js_main.js_r_1709723942:2@106768`
- `/api/developer/atport-status` — `js__js_main.js_r_1709723942:2@118088`
- `/api/developer/developermode-featureswitch` — `js__js_main.js_r_1709723942:2@117106`
- `/api/developer/log-status` — `js__js_main.js_r_1709723942:2@117360`
- `/api/developer/modem-log` — `js__js_main.js_r_1709723942:2@118243`
- `/api/developer/ps-slow` — `js__js_main.js_r_1709723942:2@117589`
- `/api/developer/upload-runlog` — `js__js_main.js_r_1709723942:2@117883`
- `/api/developer/webapp-log` — `js__js_main.js_r_1709723942:2@117316`
- `/api/developer/webapp-support-module` — `js__js_main.js_r_1709723942:2@117459`
- `/api/device/antenna_set_type` — `js__js_main.js_r_1709723942:2@114770`
- `/api/device/antenna_type` — `js__js_main.js_r_1709723942:2@114697`
- `/api/device/autorun-version` — `js__js_main.js_r_1709723942:2@118519`
- `/api/device/basic_information` — `js__js_main.js_r_1709723942:2@109297`
- `/api/device/boot_time` — `js__js_main.js_r_1709723942:2@106263`
- `/api/device/control` — `js__js_main.js_r_1709723942:2@108445`
- `/api/device/datalock` — `js__js_main.js_r_1709723942:2@117160`
- `/api/device/device-feature-switch` — `js__js_main.js_r_1709723942:2@107482`
- `/api/device/device-feature-switchion` — `js__js_main.js_r_1709723942:2@108053`
- `/api/device/information` — `js__js_main.js_r_1709723942:2@112795`
- `/api/device/logport` — `js__js_main.js_r_1709723942:2@118013`
- `/api/device/net-access-info` — `js__js_main.js_r_1709723942:2@119448`
- `/api/device/nfcswitch` — `js__js_main.js_r_1709723942:2@114805`
- `/api/device/ri` — `js__js_main.js_r_1709723942:2@119123`
- `/api/device/signal` — `js__js_main.js_r_1709723942:2@111553`
- `/api/device/sn_verification` — `js__js_main.js_r_1709723942:2@118670`
- `/api/device/usb-disk-status` — `js__js_main.js_r_1709723942:2@118284`
- `/api/device/vendorname` — `js__js_main.js_r_1709723942:2@119151`
- `/api/device/wan-mirror-capture-switch` — `js__js_main.js_r_1709723942:2@117228`
- `/api/deviceInfo/deviceInfo` — `js__js_main.js_r_1709723942:2@106727`
- `/api/dhcp/feature-switch` — `js__js_main.js_r_1709723942:2@118376`
- `/api/dhcp/settings` — `js__js_main.js_r_1709723942:2@108677`
- `/api/dhcp/static-addr-info` — `js__js_main.js_r_1709723942:2@118329`
- `/api/dhcp/static-arp-info` — `js__js_main.js_r_1709723942:2@109918`
- `/api/diagnosis/diagnose_ping` — `js__js_main.js_r_1709723942:2@109757`
- `/api/diagnosis/diagnose_traceroute` — `js__js_main.js_r_1709723942:2@109806`
- `/api/diagnosis/get-wan-service-name` — `js__js_main.js_r_1709723942:2@109702`
- `/api/diagnosis/oversea-log` — `js__js_main.js_r_1709723942:2@114511`
- `/api/diagnosis/time_reboot` — `js__js_main.js_r_1709723942:2@114465`
- `/api/diagnosis/user_behavior` — `js__js_main.js_r_1709723942:2@110720`
- `/api/dialup/IptvProfile` — `js__js_main.js_r_1709723942:2@115892`
- `/api/dialup/SinglePdn` — `js__js_main.js_r_1709723942:2@113439`
- `/api/dialup/apn-retry` — `js__js_main.js_r_1709723942:2@113399`
- `/api/dialup/connection` — `js__js_main.js_r_1709723942:2@112189`
- `/api/dialup/constant_apn_status` — `js__js_main.js_r_1709723942:2@112303`
- `/api/dialup/dial` — `js__js_main.js_r_1709723942:2@112225`
- `/api/dialup/dialup-feature-switch` — `js__js_main.js_r_1709723942:2@112048`
- `/api/dialup/mobile-dataswitch` — `js__js_main.js_r_1709723942:2@106172`, `js__js_main.js_r_1709723942:2@112101`
- `/api/dialup/multiWanProfiles` — `js__js_main.js_r_1709723942:2@112437`
- `/api/dialup/profiles` — `js__js_main.js_r_1709723942:2@112352`
- `/api/dialup/tr069-profiles` — `js__js_main.js_r_1709723942:2@115784`
- `/api/dialup/voice-connect-info` — `js__js_main.js_r_1709723942:2@119081`
- `/api/dialup/voice-connect-status` — `js__js_main.js_r_1709723942:2@113818`
- `/api/dialup/voice-dataswitch` — `js__js_main.js_r_1709723942:2@113773`
- `/api/dialup/voice-profiles` — `js__js_main.js_r_1709723942:2@113733`
- `/api/dns/static-dns` — `js__js_main.js_r_1709723942:2@111681`
- `/api/filemanager/upload` — `chunk_common.js:2@608515`
- `/api/global/custommenu-url` — `js__js_main.js_r_1709723942:2@105425`
- `/api/global/module-switch` — `js__js_main.js_r_1709723942:2@106647`
- `/api/hilink/higame` — `js__js_main.js_r_1709723942:2@114027`
- `/api/hilink/higamecontrol` — `js__js_main.js_r_1709723942:2@114062`
- `/api/hilink/higameinfo` — `js__js_main.js_r_1709723942:2@113991`
- `/api/host/info` — `js__js_main.js_r_1709723942:2@106458`
- `/api/lan/changedevicename` — `js__js_main.js_r_1709723942:2@116725`
- `/api/lan/switch-ipmode` — `js__js_main.js_r_1709723942:2@107016`
- `/api/language/current-language` — `js__js_main.js_r_1709723942:2@106601`
- `/api/led/appctrlled` — `js__js_main.js_r_1709723942:2@114400`
- `/api/led/circle-switch` — `js__js_main.js_r_1709723942:2@114429`
- `/api/log/logexport` — `js__js_main.js_r_1709723942:2@114868`
- `/api/log/loginfo` — `js__js_main.js_r_1709723942:2@114839`
- `/api/monitoring/best-position-result` — `js__js_main.js_r_1709723942:2@117668`
- `/api/monitoring/best-position-status` — `js__js_main.js_r_1709723942:2@117787`
- `/api/monitoring/best-signal-position` — `js__js_main.js_r_1709723942:2@118568`
- `/api/monitoring/check-notifications` — `js__js_main.js_r_1709723942:2@106840`
- `/api/monitoring/clear-traffic` — `js__js_main.js_r_1709723942:2@109652`
- `/api/monitoring/converged-status` — `js__js_main.js_r_1709723942:2@106547`
- `/api/monitoring/daily-data-limit` — `js__js_main.js_r_1709723942:2@109454`
- `/api/monitoring/external-best-signal-position` — `js__js_main.js_r_1709723942:2@117727`
- `/api/monitoring/month_statistics` — `js__js_main.js_r_1709723942:2@109549`
- `/api/monitoring/onekey_diag` — `js__js_main.js_r_1709723942:2@114137`
- `/api/monitoring/start_date` — `js__js_main.js_r_1709723942:2@109506`
- `/api/monitoring/statistic-feature-switch` — `js__js_main.js_r_1709723942:2@109398`
- `/api/monitoring/status` — `js__js_main.js_r_1709723942:2@107632`, `js__js_main.js_r_1709723942:2@128811`
- `/api/monitoring/traffic-statistics` — `js__js_main.js_r_1709723942:2@109602`
- `/api/net/antenna-configuration` — `js__js_main.js_r_1709723942:2@114910`
- `/api/net/cell-info` — `js__js_main.js_r_1709723942:2@115822`
- `/api/net/csps_state` — `js__js_main.js_r_1709723942:2@115853`
- `/api/net/current-plmn` — `js__js_main.js_r_1709723942:2@107719`
- `/api/net/handle-cell` — `js__js_main.js_r_1709723942:2@117036`
- `/api/net/lock-freq` — `js__js_main.js_r_1709723942:2@118165`
- `/api/net/lte-band-info` — `js__js_main.js_r_1709723942:2@118131`
- `/api/net/net-feature-switch` — `js__js_main.js_r_1709723942:2@112641`
- `/api/net/net-mode` — `js__js_main.js_r_1709723942:2@112566`
- `/api/net/net-mode-list` — `js__js_main.js_r_1709723942:2@112725`
- `/api/net/network` — `js__js_main.js_r_1709723942:2@112758`
- `/api/net/plmn-list` — `js__js_main.js_r_1709723942:2@112865`
- `/api/net/reconnect` — `js__js_main.js_r_1709723942:2@114734`
- `/api/net/register` — `js__js_main.js_r_1709723942:2@112833`
- `/api/ntwk/access_auth` — `js__js_main.js_r_1709723942:2@105720`
- `/api/ntwk/celllock` — `js__js_main.js_r_1709723942:2@106300`, `js__js_main.js_r_1709723942:2@117004`
- `/api/ntwk/devicewanbind` — `js__js_main.js_r_1709723942:2@114212`
- `/api/ntwk/dualwaninfo` — `js__js_main.js_r_1709723942:2@108736`
- `/api/ntwk/ethwanrate` — `js__js_main.js_r_1709723942:2@106373`
- `/api/ntwk/ipcapture` — `js__js_main.js_r_1709723942:2@117508`
- `/api/ntwk/ipcapturestart` — `js__js_main.js_r_1709723942:2@117548`
- `/api/ntwk/ipv6-dhcp` — `js__js_main.js_r_1709723942:2@106100`
- `/api/ntwk/ipv6-enable` — `js__js_main.js_r_1709723942:2@106133`
- `/api/ntwk/ipv6-slaac` — `js__js_main.js_r_1709723942:2@106068`
- `/api/ntwk/lan-wan-config` — `js__js_main.js_r_1709723942:2@116867`
- `/api/ntwk/lan-wan-relation` — `js__js_main.js_r_1709723942:2@116909`
- `/api/ntwk/lan_upnp_portmapping` — `js__js_main.js_r_1709723942:2@108835`
- `/api/ntwk/uploadvpncerts` — `chunk_common.js:2@332006`, `js__js_main.js_r_1709723942:2@112001`
- `/api/ntwk/wlan_easymesh` — `js__js_main.js_r_1709723942:2@114334`
- `/api/online-update/ack-newversion` — `js__js_main.js_r_1709723942:2@107994`
- `/api/online-update/ack-readytoupdate` — `js__js_main.js_r_1709723942:2@107941`
- `/api/online-update/autoupdate-config` — `js__js_main.js_r_1709723942:2@107380`
- `/api/online-update/check-new-version` — `js__js_main.js_r_1709723942:2@107885`
- `/api/online-update/configuration` — `js__js_main.js_r_1709723942:2@114553`
- `/api/online-update/forceupdate-config` — `js__js_main.js_r_1709723942:2@108146`
- `/api/online-update/redirect_cancel` — `js__js_main.js_r_1709723942:2@107832`
- `/api/online-update/status` — `js__js_main.js_r_1709723942:2@107282`
- `/api/online-update/url-list` — `js__js_main.js_r_1709723942:2@107327`
- `/api/pb/group-count` — `js__js_main.js_r_1709723942:2@116046`
- `/api/pb/group-delete` — `js__js_main.js_r_1709723942:2@116191`
- `/api/pb/group-list` — `js__js_main.js_r_1709723942:2@116075`
- `/api/pb/group-new` — `js__js_main.js_r_1709723942:2@116162`
- `/api/pb/group-update` — `js__js_main.js_r_1709723942:2@116256`
- `/api/pb/pb-copySIM` — `js__js_main.js_r_1709723942:2@116287`
- `/api/pb/pb-count` — `js__js_main.js_r_1709723942:2@115994`
- `/api/pb/pb-delete` — `js__js_main.js_r_1709723942:2@116319`
- `/api/pb/pb-list` — `js__js_main.js_r_1709723942:2@116020`
- `/api/pb/pb-match` — `js__js_main.js_r_1709723942:2@115967`
- `/api/pb/pb-move` — `js__js_main.js_r_1709723942:2@116226`
- `/api/pb/pb-new` — `js__js_main.js_r_1709723942:2@116136`
- `/api/pb/pb-update` — `js__js_main.js_r_1709723942:2@116105`
- `/api/pin/operate` — `js__js_main.js_r_1709723942:2@110829`
- `/api/pin/save-pin` — `js__js_main.js_r_1709723942:2@110798`
- `/api/pin/simlock` — `js__js_main.js_r_1709723942:2@105878`, `js__js_main.js_r_1709723942:2@114175`
- `/api/pin/status` — `js__js_main.js_r_1709723942:2@105846`, `js__js_main.js_r_1709723942:2@106803`
- `/api/pin/verify-simlock` — `js__js_main.js_r_1709723942:2@105911`
- `/api/prsite/getrandurl` — `js__js_main.js_r_1709723942:2@108103`
- `/api/prsite/homepage` — `js__js_main.js_r_1709723942:2@117629`
- `/api/prsite/upgrade_redirction` — `js__js_main.js_r_1709723942:2@105472`
- `/api/redirection/homepage` — `js__js_main.js_r_1709723942:2@118627`
- `/api/security/acl` — `js__js_main.js_r_1709723942:2@117063`
- `/api/security/bridgemode` — `js__js_main.js_r_1709723942:2@106929`
- `/api/security/dmz` — `js__js_main.js_r_1709723942:2@108708`
- `/api/security/feature-switch` — `js__js_main.js_r_1709723942:2@108534`
- `/api/security/firewall-switch` — `js__js_main.js_r_1709723942:2@106971`
- `/api/security/lan-ip-filter` — `js__js_main.js_r_1709723942:2@113307`
- `/api/security/mac-filter` — `js__js_main.js_r_1709723942:2@109877`
- `/api/security/nat` — `js__js_main.js_r_1709723942:2@106890`
- `/api/security/pcp` — `js__js_main.js_r_1709723942:2@109847`
- `/api/security/sip` — `js__js_main.js_r_1709723942:2@108876`
- `/api/security/special-applications` — `js__js_main.js_r_1709723942:2@115106`
- `/api/security/upnp` — `js__js_main.js_r_1709723942:2@108801`
- `/api/security/url-filter` — `js__js_main.js_r_1709723942:2@108583`
- `/api/security/virtual-servers` — `js__js_main.js_r_1709723942:2@115157`
- `/api/security/white-lan-ip-filter` — `js__js_main.js_r_1709723942:2@113354`
- `/api/security/white-url-filter` — `js__js_main.js_r_1709723942:2@108633`
- `/api/sim/down-profile` — `js__js_main.js_r_1709723942:2@119282`
- `/api/sim/esim-auto-download` — `js__js_main.js_r_1709723942:2@119365`
- `/api/sim/esim-profiles` — `js__js_main.js_r_1709723942:2@119217`
- `/api/sim/operate-profile` — `js__js_main.js_r_1709723942:2@119321`
- `/api/sim/sim-info` — `js__js_main.js_r_1709723942:2@119184`
- `/api/sim/sim-mode` — `js__js_main.js_r_1709723942:2@119250`
- `/api/sim/sim-mode-reboot` — `js__js_main.js_r_1709723942:2@119409`
- `/api/smartsrvc/social/switch` — `js__js_main.js_r_1709723942:2@110592`
- `/api/sms/backup-sim` — `js__js_main.js_r_1709723942:2@115698`
- `/api/sms/config` — `js__js_main.js_r_1709723942:2@115632`
- `/api/sms/delete-sms` — `js__js_main.js_r_1709723942:2@115415`
- `/api/sms/get-cbschannellist` — `js__js_main.js_r_1709723942:2@116514`
- `/api/sms/get-cbsnewslist` — `js__js_main.js_r_1709723942:2@116639`
- `/api/sms/operate-cbschannel` — `js__js_main.js_r_1709723942:2@116555`
- `/api/sms/save-sms` — `js__js_main.js_r_1709723942:2@115533`
- `/api/sms/send-sms` — `js__js_main.js_r_1709723942:2@115303`
- `/api/sms/send-status` — `js__js_main.js_r_1709723942:2@115272`
- `/api/sms/set-read` — `js__js_main.js_r_1709723942:2@115238`
- `/api/sms/sms-count` — `js__js_main.js_r_1709723942:2@115601`
- `/api/sms/sms-count-contact` — `js__js_main.js_r_1709723942:2@115453`
- `/api/sms/sms-delete-phone` — `js__js_main.js_r_1709723942:2@115335`
- `/api/sms/sms-feature-switch` — `js__js_main.js_r_1709723942:2@115375`
- `/api/sms/sms-list` — `js__js_main.js_r_1709723942:2@130881`
- `/api/sms/sms-list-contact` — `js__js_main.js_r_1709723942:2@115497`
- `/api/sms/sms-list-phone` — `js__js_main.js_r_1709723942:2@115566`
- `/api/sms/splitinfo-sms` — `js__js_main.js_r_1709723942:2@115202`
- `/api/sntp/authprofile` — `js__js_main.js_r_1709723942:2@108340`
- `/api/sntp/manualtimeset` — `js__js_main.js_r_1709723942:2@108378`
- `/api/sntp/ntpswitch` — `js__js_main.js_r_1709723942:2@108230`
- `/api/sntp/serverinfo` — `js__js_main.js_r_1709723942:2@108267`
- `/api/sntp/sntpswitch` — `js__js_main.js_r_1709723942:2@108197`
- `/api/sntp/timeinfo` — `js__js_main.js_r_1709723942:2@108303`, `js__js_main.js_r_1709723942:2@114105`
- `/api/sta/wps-cancel` — `js__js_main.js_r_1709723942:2@111378`
- `/api/sta/wps-pbc` — `js__js_main.js_r_1709723942:2@116407`
- `/api/sta/wps-pin` — `js__js_main.js_r_1709723942:2@116480`
- `/api/staticroute/staticroute` — `js__js_main.js_r_1709723942:2@114250`
- `/api/staticroute/wanpath` — `js__js_main.js_r_1709723942:2@106335`
- `/api/statistic/feature-roam-statistic` — `js__js_main.js_r_1709723942:2@109341`
- `/api/stk/stk-get-main` — `js__js_main.js_r_1709723942:2@116764`
- `/api/stk/stk-get-sub` — `js__js_main.js_r_1709723942:2@116798`
- `/api/stk/stk-query` — `js__js_main.js_r_1709723942:2@116833`
- `/api/system/HostInfo` — `js__js_main.js_r_1709723942:2@108769`
- `/api/system/devcapacity` — `js__js_main.js_r_1709723942:2@110471`
- `/api/system/deviceinfo` — `js__js_main.js_r_1709723942:2@110514`
- `/api/system/deviceinfoex` — `js__js_main.js_r_1709723942:2@110558`
- `/api/system/onlineupg` — `js__js_main.js_r_1709723942:2@107534`, `js__js_main.js_r_1709723942:2@131220`
- `/api/system/topology` — `js__js_main.js_r_1709723942:2@105686`
- `/api/time/timeout` — `js__js_main.js_r_1709723942:2@116380`
- `/api/timerule/timerule` — `js__js_main.js_r_1709723942:2@115934`
- `/api/tr111/basic-info` — `js__js_main.js_r_1709723942:2@116603`
- `/api/user/authentication_login` — `js__js_main.js_r_1709723942:2@110146`, `js__js_main.js_r_1709723942:2@131466`
- `/api/user/challenge_login` — `js__js_main.js_r_1709723942:2@110063`, `js__js_main.js_r_1709723942:2@131421`
- `/api/user/heartbeat` — `js__js_main.js_r_1709723942:2@107757`
- `/api/user/hilink_login` — `js__js_main.js_r_1709723942:2@107055`
- `/api/user/history-login` — `js__js_main.js_r_1709723942:2@110681`
- `/api/user/login` — `js__js_main.js_r_1709723942:2@110102`
- `/api/user/logout` — `js__js_main.js_r_1709723942:2@109214`
- `/api/user/password_scram` — `js__js_main.js_r_1709723942:2@110226`, `js__js_main.js_r_1709723942:2@131516`
- `/api/user/pwd` — `js__js_main.js_r_1709723942:2@119055`
- `/api/user/remember-pwd` — `js__js_main.js_r_1709723942:2@110639`
- `/api/user/rule` — `js__js_main.js_r_1709723942:2@109186`
- `/api/user/second_login` — `js__js_main.js_r_1709723942:2@117195`
- `/api/user/session` — `js__js_main.js_r_1709723942:2@107791`, `js__js_main.js_r_1709723942:2@131056`
- `/api/user/state-login` — `js__js_main.js_r_1709723942:2@110353`
- `/api/user/web-feature-switch` — `js__js_main.js_r_1709723942:2@109250`
- `/api/ussd/get` — `js__js_main.js_r_1709723942:2@109075`
- `/api/ussd/release` — `js__js_main.js_r_1709723942:2@109103`
- `/api/ussd/send` — `js__js_main.js_r_1709723942:2@109050`
- `/api/voice/addsipaccount` — `js__js_main.js_r_1709723942:2@115014`
- `/api/voice/advancecodec` — `js__js_main.js_r_1709723942:2@113481`
- `/api/voice/deletesipaccount` — `js__js_main.js_r_1709723942:2@114965`
- `/api/voice/featureswitch` — `js__js_main.js_r_1709723942:2@115060`
- `/api/voice/functioncode` — `js__js_main.js_r_1709723942:2@113615`
- `/api/voice/sipaccount` — `js__js_main.js_r_1709723942:2@113523`
- `/api/voice/sipadvance` — `js__js_main.js_r_1709723942:2@113910`
- `/api/voice/sipserver` — `js__js_main.js_r_1709723942:2@113657`
- `/api/voice/speeddial` — `js__js_main.js_r_1709723942:2@113565`
- `/api/voice/voice-basic-settings` — `js__js_main.js_r_1709723942:2@116956`
- `/api/voice/voiceadvance` — `js__js_main.js_r_1709723942:2@113954`
- `/api/voice/voicebusy` — `js__js_main.js_r_1709723942:2@108414`
- `/api/voice/voiperstatus` — `js__js_main.js_r_1709723942:2@113693`
- `/api/voice/volte` — `js__js_main.js_r_1709723942:2@111527`
- `/api/vpn/br_list` — `js__js_main.js_r_1709723942:2@111926`
- `/api/vpn/feature-switch` — `js__js_main.js_r_1709723942:2@111720`
- `/api/vpn/ipsec_settings` — `js__js_main.js_r_1709723942:2@111890`
- `/api/vpn/l2tp_settings` — `js__js_main.js_r_1709723942:2@111803`
- `/api/vpn/l2tpv3-settings` — `js__js_main.js_r_1709723942:2@111846`
- `/api/vpn/pptp_settings` — `js__js_main.js_r_1709723942:2@111762`
- `/api/vsim/operateswitch-vsim` — `js__js_main.js_r_1709723942:2@109141`
- `/api/webserver/publickey` — `js__js_main.js_r_1709723942:2@111964`
- `/api/webserver/token` — `js__js_main.js_r_1709723942:2@110188`
- `/api/wlan/backhaul` — `js__js_main.js_r_1709723942:2@114369`
- `/api/wlan/basic-settings` — `js__js_main.js_r_1709723942:2@128753`
- `/api/wlan/guesttime-setting` — `js__js_main.js_r_1709723942:2@105522`
- `/api/wlan/handover-setting` — `js__js_main.js_r_1709723942:2@112391`
- `/api/wlan/link-turbo-settings` — `js__js_main.js_r_1709723942:2@111445`
- `/api/wlan/multi-basic-settings` — `js__js_main.js_r_1709723942:2@111015`, `js__js_main.js_r_1709723942:2@128715`
- `/api/wlan/multi-macfilter-settings` — `js__js_main.js_r_1709723942:2@105640`
- `/api/wlan/multi-macfilter-settings-ex` — `js__js_main.js_r_1709723942:2@105577`
- `/api/wlan/multi-security-settings` — `js__js_main.js_r_1709723942:2@111108`
- `/api/wlan/multi-security-settings-ex` — `js__js_main.js_r_1709723942:2@111168`
- `/api/wlan/multi-switch-settings` — `js__js_main.js_r_1709723942:2@113009`
- `/api/wlan/smart-sleep-settings` — `js__js_main.js_r_1709723942:2@113262`
- `/api/wlan/ssid-switch-settings` — `js__js_main.js_r_1709723942:2@105956`
- `/api/wlan/sta-sim-relation` — `js__js_main.js_r_1709723942:2@112960`, `js__js_main.js_r_1709723942:2@116441`
- `/api/wlan/station-information` — `js__js_main.js_r_1709723942:2@106414`
- `/api/wlan/status-switch-settings` — `js__js_main.js_r_1709723942:2@110961`
- `/api/wlan/wifi-feature-switch` — `js__js_main.js_r_1709723942:2@110912`
- `/api/wlan/wifiaddprofile` — `js__js_main.js_r_1709723942:2@113182`
- `/api/wlan/wifidial` — `js__js_main.js_r_1709723942:2@113222`
- `/api/wlan/wifiprofile` — `js__js_main.js_r_1709723942:2@113139`
- `/api/wlan/wifiscan` — `js__js_main.js_r_1709723942:2@113056`
- `/api/wlan/wifiscanresult` — `js__js_main.js_r_1709723942:2@113096`
- `/api/wlan/wlan-debug` — `js__js_main.js_r_1709723942:2@111486`
- `/api/wlan/wlan-guide-settings` — `js__js_main.js_r_1709723942:2@110862`
- `/api/wlan/wlandbho` — `js__js_main.js_r_1709723942:2@111216`
- `/api/wlan/wlanintelligent` — `js__js_main.js_r_1709723942:2@114297`
- `/api/wlan/wlanwifisync` — `js__js_main.js_r_1709723942:2@111061`
- `/api/wlan/wps` — `js__js_main.js_r_1709723942:2@111411`
- `/api/wlan/wps-appin` — `js__js_main.js_r_1709723942:2@111279`
- `/api/wlan/wps-cancel` — `js__js_main.js_r_1709723942:2@111342`
- `/api/wlan/wps-pbc` — `js__js_main.js_r_1709723942:2@111312`
- `/api/wlan/wps-switch` — `js__js_main.js_r_1709723942:2@111247`
- `/config/cradle/config.xml` — `js__js_main.js_r_1709723942:2@112481`
- `/config/device/config.xml` — `js__js_main.js_r_1709723942:2@114601`
- `/config/dialup/config.xml` — `js__js_main.js_r_1709723942:2@112257`
- `/config/dialup/connectmode.xml` — `js__js_main.js_r_1709723942:2@112145`
- `/config/global/config.xml` — `js__js_main.js_r_1709723942:2@110310`
- `/config/global/languagelist.xml` — `js__js_main.js_r_1709723942:2@106497`
- `/config/global/net-type.xml` — `js__js_main.js_r_1709723942:2@106218`, `js__js_main.js_r_1709723942:2@112594`
- `/config/global/region-list.xml` — `js__js_main.js_r_1709723942:2@110264`
- `/config/lan/config.xml` — `js__js_main.js_r_1709723942:2@118419`
- `/config/lanConfig/config.xml` — `js__js_main.js_r_1709723942:2@106685`
- `/config/network/bandfreqlist.xml` — `js__js_main.js_r_1709723942:2@118199`
- `/config/network/net-mode.xml` — `js__js_main.js_r_1709723942:2@112682`
- `/config/network/networkband_E5785-92a.xml` — `js__js_main.js_r_1709723942:2@112900`
- `/config/network/networkmode.xml` — `js__js_main.js_r_1709723942:2@112524`
- `/config/pb/config.xml` — `js__js_main.js_r_1709723942:2@116348`
- `/config/pincode/config.xml` — `js__js_main.js_r_1709723942:2@110761`
- `/config/sms/config.xml` — `js__js_main.js_r_1709723942:2@115663`
- `/config/update/config.xml` — `js__js_main.js_r_1709723942:2@107676`
- `/config/ussd/config.xml` — `js__js_main.js_r_1709723942:2@108907`
- `/config/ussd/postpaidussd.xml` — `js__js_main.js_r_1709723942:2@109009`
- `/config/ussd/prepaidussd.xml` — `js__js_main.js_r_1709723942:2@108955`
- `/config/voice/config.xml` — `js__js_main.js_r_1709723942:2@113865`
- `/config/webuicfg/config.xml` — `js__js_main.js_r_1709723942:2@108482`
- `/config/wifi/configure.xml` — `js__js_main.js_r_1709723942:2@105807`
- `/config/wifi/countryChannel.xml` — `js__js_main.js_r_1709723942:2@105759`
- `/html/OPEN_SOURCE_SOFTWARE_NOTICE.txt` — `chunk_common.js:2@470835`, `chunk_guide.js:2@10450`
- `/html/index.html` — `_html_index.html:8@756`, `js__html_index.js:8@756`

### `auth_symbol` — confidence: **candidate** (16 unique values)

- `HmacSHA256` — `lib_emui-crypto.js:1688@47515`, `lib_emui-crypto.js:2986@87849`, `lib_emui-crypto.js:2988@87891`, `lib_emui-crypto.js:7558@243475`, `lib_emui-crypto.js:8280@268179`, `lib_emui-crypto.js:8285@268353` (+9 more)
- `PBKDF2` — `lib_emui-crypto.js:4124@127609`, `lib_emui-crypto.js:4124@127625`, `lib_emui-crypto.js:4145@128389`, `lib_emui-crypto.js:4146@128446`, `lib_emui-crypto.js:4147@128517`, `lib_emui-crypto.js:4228@131098` (+5 more)
- `SCRAM` — `js__js_main.js_r_1709723942:2@79929`, `js__js_main.js_r_1709723942:2@180315`, `js__js_main.js_r_1709723942:2@180582`, `lib_emui-crypto.js:7558@243499`, `lib_emui-crypto.js:7558@244390`
- `authentication_login` — `js__js_main.js_r_1709723942:2@110157`, `js__js_main.js_r_1709723942:2@131477`
- `challenge_login` — `js__js_main.js_r_1709723942:2@110074`, `js__js_main.js_r_1709723942:2@131432`
- `clientKey` — `js__js_main.js_r_1709723942:2@181058`, `lib_emui-crypto.js:7558@243800`, `lib_emui-crypto.js:7558@244131`
- `clientproof` — `js__js_main.js_r_1709723942:2@180843`
- `finalnonce` — `js__js_main.js_r_1709723942:2@180857`
- `firstnonce` — `js__js_main.js_r_1709723942:2@180365`
- `rsae` — `js__js_main.js_r_1709723942:2@181680`
- `rsan` — `js__js_main.js_r_1709723942:2@181475`, `js__js_main.js_r_1709723942:2@181664`
- `rsapubkeysignature` — `js__js_main.js_r_1709723942:2@181627`
- `serverKey` — `js__js_main.js_r_1709723942:2@180747`, `js__js_main.js_r_1709723942:2@181111`, `lib_emui-crypto.js:7558@243860`, `lib_emui-crypto.js:7558@244334`
- `servernonce` — `js__js_main.js_r_1709723942:2@180669`
- `serversignature` — `js__js_main.js_r_1709723942:2@181595`
- `storedKey` — `js__js_main.js_r_1709723942:2@181046`, `lib_emui-crypto.js:7558@243920`, `lib_emui-crypto.js:7558@244151`

### `session_material` — confidence: **candidate** (4 unique values)

- `Update-Cookie` — `js__js_main.js_r_1709723942:2@128845`
- `csrf_token` — `_html_index.html:1@50`, `_html_index.html:2@101`, `_root_session.html:1@50`, `_root_session.html:2@101`, `chunk_common.js:2@331742`, `chunk_common.js:2@612642` (+5 more)
- `localStorage` — `js__js_main.js_r_1709723942:2@77506`, `js__js_main.js_r_1709723942:2@77999`, `js__js_main.js_r_1709723942:2@180084`
- `token.substr` — `js__js_main.js_r_1709723942:2@19049`

### `management_candidate` — confidence: **candidate** (13 unique values)

- `best-position-result` — `js__js_main.js_r_1709723942:2@117685`
- `best-position-status` — `js__js_main.js_r_1709723942:2@117804`
- `best-signal-position` — `js__js_main.js_r_1709723942:2@118585`
- `celllock` — `chunk_guide.js:2@21697`, `js__js_main.js_r_1709723942:2@1534`, `js__js_main.js_r_1709723942:2@1543`, `js__js_main.js_r_1709723942:2@5848`, `js__js_main.js_r_1709723942:2@5857`, `js__js_main.js_r_1709723942:2@47169` (+5 more)
- `external-best-signal-position` — `js__js_main.js_r_1709723942:2@117744`
- `handle-cell` — `js__js_main.js_r_1709723942:2@117046`
- `lock-freq` — `js__js_main.js_r_1709723942:2@118175`
- `mobilesearch` — `chunk_common.js:2@418963`, `js__js_main.js_r_1709723942:2@2464`, `js__js_main.js_r_1709723942:2@2477`, `js__js_main.js_r_1709723942:2@6778`, `js__js_main.js_r_1709723942:2@6791`, `js__js_main.js_r_1709723942:2@227400` (+2 more)
- `net-mode` — `js__js_main.js_r_1709723942:2@112576`, `js__js_main.js_r_1709723942:2@112699`, `js__js_main.js_r_1709723942:2@112735`
- `networkmode` — `js__js_main.js_r_1709723942:2@2602`, `js__js_main.js_r_1709723942:2@6916`, `js__js_main.js_r_1709723942:2@32247`, `js__js_main.js_r_1709723942:2@32266`, `js__js_main.js_r_1709723942:2@32711`, `js__js_main.js_r_1709723942:2@112541`
- `onekey_diag` — `js__js_main.js_r_1709723942:2@114154`
- `plmn-list` — `js__js_main.js_r_1709723942:2@112875`
- `reconnect` — `js__js_main.js_r_1709723942:2@114724`, `js__js_main.js_r_1709723942:2@114744`

### `write_method_call` — confidence: **unverified** (2 unique values)

- `delete` — `js__js_main.js_r_1709723942:2@268541`, `js__js_main.js_r_1709723942:2@270219`
- `post` — `chunk_common.js:2@332000`

### `module_ref` — confidence: **candidate** (5 unique values)

- `i.p=` — `js__js_main.js_r_1709723942:2@9930`
- `importScripts` — `js__js_main.js_r_1709723942:2@246469`
- `require (` — `lib_emui-crypto.js:951@25561`
- `require(` — `lib_emui-crypto.js:954@25668`
- `webpackJsonp` — `chunk_common.js:2@72`, `chunk_common.js:2@92`, `chunk_guide.js:2@71`, `chunk_guide.js:2@91`, `chunk_login.js:2@71`, `chunk_login.js:2@91` (+2 more)

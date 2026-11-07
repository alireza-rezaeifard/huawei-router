# Phase 9 — Evidence-Based Device Profile and Read-Only Integration Contract

Status: **Phase 9 implemented and verified offline.**
Phase 10 is **not** started. No live device I/O, HTTP request, authentication,
scan, lock, reconnect, reboot or configuration change was performed.

Phase 8 checkpoint (local, unpushed):

```text
9ddcf4e4bda866850d1dd26514c085959a6dfcfd
phase 8: restore offline Best Pair core workflow
```

## 1. Scope and files

| File | Change |
|---|---|
| `src/huawei_tower/bestpair/evidence.py` | **Created** — provenance-tagged extraction, gap reporting, profile building |
| `src/huawei_tower/bestpair/__init__.py` | **Modified** — exports the Phase 9 evidence API |
| `tests/test_bestpair.py` | **Extended** — focused evidence, provenance, contradiction, malformed-input and gap tests |
| `docs/PHASE9_DEVICE_PROFILE_AND_INTEGRATION.md` | **Created** — this document |

Phase 8 files and behavior remain unchanged except for the new exports. The
Phase 8 engine (`engine.py`) was reviewed but not modified.

## 2. Evidence sources and extraction policy

`collect_device_facts()` reads **only** a fixed allowlist of sanitized local
artifacts, exposed as `EVIDENCE_SOURCES`:

| Source | Role |
|---|---|
| `evidence/raw/_api_device_basic_information.xml` | Confirmed device identity |
| `evidence/fixtures/device_basic_information.xml` | Identity corroboration / contradiction check |
| `evidence/raw/_api_net_current-plmn.xml` | Confirmed PLMN and RAT mode |
| `evidence/fixtures/current_plmn.xml` | PLMN/RAT corroboration / contradiction check |
| `evidence/raw/_api_global_module-switch.xml` | Confirmed product feature flags |
| `evidence/raw/_api_app_operatorinfo.xml` | Operator label; empty stub is reported as a gap |
| `docs/PHASE1_FINDINGS.md` | Historical n78 context (observed only) and documented endpoint names |
| Six gated `_api_*.xml` captures | Recorded as unavailable data sources |
| Four candidate band-capability paths | Checked for presence only; absent captures become gaps |

No JavaScript bundle, credential, environment file, virtual environment or
cache is read. The extractor performs no network, socket, subprocess or
JavaScript execution.

### XML hierarchy and namespaces

The actual local hierarchy was verified before extraction:

- Raw captures contain HTTP header text followed by an XML document. The
  extractor starts at `<?xml` (or the first `<`) before parsing.
- All parsed roots are either `<response>` or `<error>`.
- **No namespaces are present.** A namespaced root or child is rejected as
  unsupported rather than silently misread.
- Raw identity/PLMN fields are **direct children** of `<response>`:
  `<devicename>`, `<productfamily>`, `<classify>`, `<spreadname_en>`,
  `<Numeric>`, `<Rat>`.
- Fixtures use PascalCase direct children: `<DeviceName>`, `<ProductFamily>`,
  `<Classify>`, `<SpreadName>`, `<Numeric>`, `<Rat>`.
- Nested or repeated direct children are rejected as ambiguous.
- `_api_app_operatorinfo.xml` is JSON (`{"OperatorName":""}`), not XML, and is
  parsed as JSON.
- Malformed XML/JSON raises `EvidenceExtractionError`; it is never ignored.

### Fact contract

Every `EvidenceFact` carries:

| Field | Meaning |
|---|---|
| `name` | Stable fact identifier |
| `value` | Extracted string value |
| `status` | Exactly `confirmed` or `observed` |
| `source_file` | Repository-relative path |
| `locator` | XML element / JSON field / document line |
| `explanation` | Short interpretation and limitations |

`EvidenceGap` records an unavailable data source with the same provenance
discipline and a fixed `unavailable` status.

## 3. Extracted facts and provenance

The current repository produces 13 facts.

### Confirmed facts

| Fact | Value | Source | Locator |
|---|---|---|---|
| `device.model` | `H158-381` | `evidence/raw/_api_device_basic_information.xml` | `/response/devicename` |
| `device.product_family` | `LTE` | same | `/response/productfamily` |
| `device.classify` | `cpe` | same | `/response/classify` |
| `device.product_name` | `5G CPE Pro 5` | same | `/response/spreadname_en` |
| `network.plmn` | `43211` | `evidence/raw/_api_net_current-plmn.xml` | `/response/Numeric` |
| `network.rat_mode` | `7` | same | `/response/Rat` |
| `feature.nrProductEnable` | `1` | `evidence/raw/_api_global_module-switch.xml` | `/response/nrProductEnable` |
| `feature.oneKeyCheckEnable` | `1` | same | `/response/oneKeyCheckEnable` |
| `feature.bestsignal_enable` | `0` | same | `/response/bestsignal_enable` |
| `feature.celllock_enabled` | `1` | same | `/response/celllock_enabled` |
| `feature.antenna_enabled` | `1` | same | `/response/antenna_enabled` |
| `feature.sa_enable` | `1` | same | `/response/sa_enable` |

The four identity facts and the PLMN/RAT facts are corroborated against the
sanitized fixtures. Any disagreement raises `EvidenceContradictionError`.

### Observed facts

| Fact | Value | Source | Locator |
|---|---|---|---|
| `band.nr.n78` | `n78` | `docs/PHASE1_FINDINGS.md` | `line 15` |

`n78` is historical prior-session context recorded in an actual repository
document. No captured device capability response exists, so it remains
`observed` and is never promoted automatically. It is retained so the engine can
explain its exclusion rather than silently dropping it.

### Unavailable data sources (gaps)

| Gap | Source | Locator | Reason |
|---|---|---|---|
| Operator display name | `_api_app_operatorinfo.xml` | `/OperatorName` | Field present but empty |
| Firmware identity | `_api_device_information.xml` | `/error/code` | Gated `100003` |
| Firmware version | `_api_version.xml` | `/error/code` | Gated `100003` |
| Serving cell / monitoring | `_api_monitoring_status.xml` | `/error/code` | Gated `125002` |
| RAT mode configuration | `_api_net_net-mode.xml` | `/error/code` | Gated `100003` |
| RAT mode option list | `_api_net_net-mode-list.xml` | `/error/code` | Gated `100003` |
| Device configuration XML | `_api_config_global_config_xml.xml` | `/error/code` | Gated `100003` |
| LTE band capability | `_api_net_lte-band-info.xml` | not captured | No local capture |
| NR band capability | `_api_net_nr-band-info.xml` | not captured | No local capture |
| Generic band capability | `_api_net_band-info.xml` | not captured | No local capture |
| LTE/NR band frequency list | `config/network/bandfreqlist.xml` | not captured | No local capture |

Gated/stub responses are recorded **only** as unavailable data sources. They are
never interpreted as supported bands, and no schema is guessed.

## 4. Confirmed versus observed capabilities

`build_profile_from_evidence()` converts only `band.*` facts into band slots:

- `confirmed` facts become `confirmed` slots and are eligible for ranking.
- `observed` facts become `observed` slots and are **never** eligible for
  ranking or pairing.
- Bands absent from the evidence do not exist in the profile.
- Duplicate or capability-conflicting band evidence is rejected.
- An observed `device.model` cannot be used to build a profile; identity must be
  confirmed.
- Malformed band fact names or values raise `EvidenceValidationError`.

Current profile:

```text
Device:   H158-381
PLMN:     43211
RAT mode: 7
Slots:    NR n78 — observed
Confirmed band slots: none
```

This is the honest result: there is **no confirmed LTE or NR band**. The profile
therefore produces no ranked candidates and no LTE+NR combinations. Ranking an
`n78` candidate yields an explicit exclusion:

```text
NR n78 has only observed evidence; confirmed capability is required for ranking
```

`evidence_minimal_profile()` remains available as a conservative fallback. The
new `repository_device_profile()` convenience function performs
`collect_device_facts()` + `build_profile_from_evidence()`.

Feature flags remain product toggles. `nrProductEnable=1`, `sa_enable=1`, and
`celllock_enabled=1` are not band evidence. Rat 7 remains mode evidence only.

## 5. Phase 8 scoring review

The committed Phase 8 engine was inspected against the requested checks.

| Check | Result |
|---|---|
| Missing metric handling | Correct. Missing metrics contribute `0`; weights are not redistributed. |
| Coverage reporting | Correct. `coverage` is the sum of weights for measured metrics and is exposed per candidate/pair. |
| Combination score inflation | Correct. A pair metric contributes only when **both** members measured it; one-sided measurements cannot inflate the score. |
| Confirmed vs observed eligibility | Correct. `evaluate_candidate()` excludes observed-only slots before scoring. |
| Unsupported combination exclusion | Correct. Rat 7 gates the mode; each band slot must additionally be confirmed. Same-RAT combinations are never generated. |
| Honest empty output | Correct. No confirmed bands produces an empty ranking, explicit exclusions and explicit combination skip reasons. |

**No concrete scoring defect was found, so `engine.py` was not modified.** The
only Phase 8-adjacent change is the additive export surface in `__init__.py`.

## 6. Future read-only integration contract

This section defines the data contract for a future collector. It is
**documentation only**; nothing here is implemented or enabled in Phase 9.
Every live schema below is **pending confirmation**. Endpoint paths are listed
only where they already appear in this repository; no path is invented.

### 6.1 Mandatory provenance envelope

Every future reading must carry, at minimum:

| Field | Requirement |
|---|---|
| `endpoint` | Exact path used |
| `method` | `GET` only for read-only collection |
| `http_status` | Observed status code |
| `content_type` | Observed content type |
| `schema_status` | `confirmed` or `pending_confirmation` |
| `captured_at` | UTC timestamp |
| `authenticated` | Whether a session was used |
| `body_file` | Sanitized local capture path |
| `redactions` | Fields removed before storage |

A reading without complete provenance must not become an `EvidenceFact`.
Response bodies must be bounded and streamed under the existing
`ReadOnlyModemClient` limits (`_MAX_RESPONSE_BYTES = 8 MiB`, 64 KiB chunks in
`src/huawei_tower/modem/api.py`). The collector must reuse the existing
safe/gated/forbidden endpoint sets rather than adding ad-hoc requests.

### 6.2 Data items

| Data item | Documented candidate source | Repository evidence | Live schema status |
|---|---|---|---|
| Device model / product identity | `/api/device/basic_information` | Confirmed HTTP 200 payload in `evidence/raw/_api_device_basic_information.xml`; `docs/PHASE1_FINDINGS.md` §2 | **Confirmed** for the captured fields |
| Firmware identity / version | `/api/device/information`, `/api/version` | Documented names in `docs/PHASE1_FINDINGS.md` §2; both gated `100003` locally | **Pending confirmation** |
| Current RAT mode | `/api/net/current-plmn` (field `Rat`) | Confirmed capture; `Rat=7` | **Confirmed** for the captured field |
| RAT mode option list | `/api/net/net-mode-list` | Documented; gated `100003` locally | **Pending confirmation** |
| LTE band capability | `/api/net/lte-band-info` | Mapped name in `docs/PHASE1_FINDINGS.md` §4 and `docs/PHASE5_JS_STATIC_ANALYSIS.md`; never captured | **Pending confirmation** |
| LTE/NR band frequency list | `/config/network/bandfreqlist.xml` | Static-resource name in `docs/PHASE1_FINDINGS.md` §4, `docs/PHASE5_JS_STATIC_ANALYSIS.md`, `docs/PHASE6_API_RISK_AUDIT.md`; never captured | **Pending confirmation** |
| NR band capability | — | **No documented endpoint in this repository** | **Unavailable — do not invent** |
| Serving cell | `/api/net/cell-info` | Mapped name in `docs/PHASE1_FINDINGS.md` §4; gated and unexercised | **Pending confirmation** |
| RSRP / RSRQ / SINR / RSSI | `/api/device/signal` | Name and metric list in `docs/PHASE1_FINDINGS.md` §4; gated and unexercised | **Pending confirmation** |
| Network type / signal bands | `/api/monitoring/status` | Documented; gated `125002` locally; requires login | **Pending confirmation** |

Important constraints:

- `/api/net/lte-band-info` is associated with the band-lock admin page. Its
  availability and side effects outside that page are unverified. A future
  collector must confirm it is read-only before use; otherwise it stays
  unavailable.
- `/config/network/*.xml` availability before and after login is unknown.
- No NR band-capability endpoint is documented. Do not invent one; NR
  capabilities remain unavailable until captured.
- `/api/monitoring/best-position-*`, `/api/net/handle-cell`,
  `/api/ntwk/celllock`, `/api/net/lock-freq`, `/api/net/register`,
  `/api/net/reconnect` and the other entries in `FORBIDDEN_PATHS` are **out of
  scope** for profile collection. They are scan/lock/registration paths.
- A response being HTTP 200 is not schema proof. Status codes `100003` and
  `125002` are recorded as gated data sources, not as empty/absent bands.

### 6.3 Promotion rules for future data

1. A captured band response becomes `confirmed` only when the endpoint, method,
   schema, field path and value are all verified and recorded.
2. A schema that is guessed, inferred from JavaScript alone, or unexercised
   remains `pending_confirmation` and **must not** create a confirmed slot.
3. A historical note or prior conversation remains `observed`, even if it names
   a specific band.
4. Feature flags never create or confirm a band slot.
5. Rat 7 never creates or confirms a specific band combination.
6. Conflicting captures at equal evidence strength are rejected, not resolved
   by preference.

### 6.4 Suggested ingestion boundary (not implemented)

A future collector can be added without changing the engine:

```text
bounded read-only responses with provenance
        -> schema-validated field extraction
        -> EvidenceFact / EvidenceGap
        -> build_profile_from_evidence()
        -> existing Best Pair ranking / combination API
```

The extraction and profile-building functions are already pure and local, so
live ingestion can be added behind them later without changing scoring rules or
promoting observed evidence.

## 7. Tests and verification

Focused suite:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_bestpair.py -q
```

The focused tests cover:

- confirmed identity, PLMN and RAT extraction with exact provenance;
- six curated feature flags, and the absence of confirmed band facts;
- observed-only n78 with a real repository-document locator;
- gated `100003` / `125002` responses recorded as gaps;
- missing LTE/NR/generic band captures reported as unavailable;
- confirmed/observed separation in the built profile;
- engine consumption of the evidence profile (observed band excluded);
- incomplete `EvidenceFact` provenance rejection;
- malformed XML, namespaced XML, invalid PLMN and invalid flag values;
- fixture contradiction detection and successful corroboration;
- contradictory duplicate facts and conflicting band capabilities;
- repository-relative source paths and no network imports in `evidence.py`.

Full suite is run once after the focused suite. Exact results are reported in
the Phase 9 final report.

## 8. Safety boundary

- No modem connection, HTTP request, authentication or credential collection.
- No JavaScript download or execution.
- No scanning, band/cell locking, reconnect, reboot or configuration change.
- No external network access and no push.
- No invented band, endpoint or response schema.
- Phase 9 changes are left uncommitted for review.

Phase 10 is not started.

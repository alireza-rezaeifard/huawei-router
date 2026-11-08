# Phase 10 Offline Parser — Independent Code Review

**Review type:** read-only, offline, independent code review  
**Repository:** `E:\repos\huawei-router`  
**Branch:** `phase-3-js-analysis`  
**Baseline HEAD:** `04df48b8f94c8249e45624e5d1bdfc8285121a92` (`phase 9: add evidence-based device capability profile`)  
**Review date:** 2026-11-08  
**Reviewer:** OpenCode agent (ECC-assisted)

**Verdict: CHANGES REQUESTED — not approved as-is.**

No Critical or High findings were identified. The core Phase 10 invariants hold on the real captures: the 13 Phase 9 facts are unchanged, the profile is identical, `n78` remains `observed`, no band slot is confirmed, gated responses remain gaps, and no endpoint, scoring, network, authentication, or JavaScript surface changed. Five Medium findings must be corrected before approval; the remaining findings are Low-severity hardening or test-quality issues.

---

## 1. Scope and method

### 1.1 Files reviewed

| File | Review focus |
|---|---|
| `src/huawei_tower/bestpair/evidence.py` | Five fail-closed parsers, schema closure, provenance, contradiction handling, profile construction |
| `src/huawei_tower/bestpair/__init__.py` | Public exports and backward compatibility |
| `tests/test_capture_parsers.py` | All 32 new tests, negative coverage, fixture realism |
| `docs/PHASE10_STATIC_API_DISCOVERY.md` | Accuracy against the implemented state and stale claims |

Supporting files read for context:

- `src/huawei_tower/modem/api.py` — authoritative allowlist/default-deny (unchanged)
- `src/huawei_tower/bestpair/engine.py` — scoring/ranking (unchanged)
- `src/huawei_tower/modem/xmlutil.py` — shared XML parser behavior
- `docs/PHASE1_FINDINGS.md` — historical `n78` context
- `evidence/raw/*` — real sanitized captures
- `tests/test_bestpair.py` — existing Phase 9 expectations

### 1.2 Method

1. Read the four target files in full and compared `evidence.py` against the Phase 9 version at `HEAD`.
2. Ran the Phase 9 implementation from a temporary `git archive` of `HEAD` against the same repository captures and compared facts, gaps, and profile structurally.
3. Ran focused, read-only probes in temporary directories for the risky edge cases: XML roots, namespaces, attributes, duplicate elements, entities, JSON duplicate keys, Unicode digits, integer ranges, booleans, PLMN/RAT validation, source-path resolution, and provenance ambiguity.
4. Inspected all 32 new tests and measured coverage with `pytest-cov`.
5. Confirmed no network, modem, authentication, token, JavaScript, allowlist, or scoring change.
6. Ran the full suite, `git diff --check`, and `git status --short --branch` after writing this document.

No source or test file was modified. No repository file other than this document was created. All probes used temporary directories outside the repository.

---

## 2. Findings summary

| ID | Severity | Finding | Location |
|---|---|---|---|
| F-01 | **Medium** | JSON duplicate keys are silently collapsed to the last value | `evidence.py:812-817` |
| F-02 | **Medium** | Unicode numeric digits are accepted; a non-decimal digit can raise a raw `ValueError` | `evidence.py:251-252, 536, 676-679, 772, 1152` |
| F-03 | **Medium** | Recorded HTTP status and leading junk are ignored; an error body can become confirmed facts | `evidence.py:413-418, 809-813` |
| F-04 | **Medium** | Any line containing `n78`, including a negation, becomes an observed band fact | `evidence.py:990-1018` |
| F-05 | **Medium** | The highest-risk fail-closed branches are not exercised by the 32 new tests | `tests/test_capture_parsers.py`; `evidence.py` branches below |
| F-06 | Low | Root text, child tail text, and nested content under unused optional tags are silently ignored | `evidence.py:442-465, 468-491, 570-581` |
| F-07 | Low | `source_file` accepts POSIX-absolute and Windows drive-relative paths | `evidence.py:277-284` |
| F-08 | Low | Invalid UTF-8 is silently replaced with `U+FFFD` instead of failing closed | `evidence.py:404-410` |
| F-09 | Low | Internal XML entities expand when the payload starts with `<?xml`; expansion/DoS risk | `evidence.py:413-418`; `xmlutil.py:9-14` |
| F-10 | Low | PLMN validation is length-only; `00000` and leading-zero MCCs are accepted | `evidence.py:251, 676-677` |
| F-11 | Low | RAT validation accepts any `0..255`; no known-mode allowlist | `evidence.py:678-679, 1152` |
| F-12 | Low | Login numeric fields have no range validation | `evidence.py:535-540, 771-772` |
| F-13 | Low | A non-string `OperatorName` is reported as “missing” | `evidence.py:832-836` |
| F-14 | Low | Control characters in `OperatorName` are accepted | `evidence.py:838-843` |
| F-15 | Low | Fixture schema is not closed; unknown fixture fields are silently ignored | `evidence.py:897-930, 950-969` |
| F-16 | Low | Same-name/value/status facts with different provenance are silently collapsed | `evidence.py:375-385` |
| F-17 | Low | Tests assert explanation prose and use a weak locator check | `tests/test_capture_parsers.py:162, 356, 363, 375` |
| F-18 | Low | Synthetic fixtures under-represent the real capture schemas | `tests/test_capture_parsers.py:32-67` |
| F-19 | Low | Phase 10 audit document status and line references are stale | `docs/PHASE10_STATIC_API_DISCOVERY.md:3-5, 88, 104, 627` |
| F-20 | Low | Path-denial test checks allowlist membership, not actual default-deny behavior | `tests/test_capture_parsers.py:448-472` |
| I-01 | Informational | `assert` is used for type narrowing after validation | `evidence.py:496, 599, 607-612, 669, 675, 715, 722, 750` |
| I-02 | Informational | Untracked `.claude/` is unrelated ECC configuration and must not enter the Phase 10 commit | repository root |
| I-03 | Informational | `parse_module_switch` is all-or-nothing on the six feature flags | `evidence.py:191, 717` |
| I-04 | Informational | Non-empty `OperatorName` is deliberately marked `observed`, not `confirmed` | `evidence.py:844` |
| I-05 | Informational | Profile notes mention “Rat 7” unconditionally, even when `rat_mode` differs | `evidence.py:1213-1218` |

---

## 3. Positive verification (what is correct)

### 3.1 Parser correctness

The five closed schemas exactly match the direct children of the real sanitized captures:

| Capture | Real direct children | Closed schema | Result |
|---|---:|---:|---|
| `_api_device_basic_information.xml` | 8 | 8 | exact match |
| `_api_net_current-plmn.xml` | 6 | 6 | exact match |
| `_api_global_module-switch.xml` | 93 | 93 | exact match |
| `_api_user_state-login.xml` | 12 | 12 | exact match |
| `_api_app_operatorinfo.xml` | 1 JSON field | 1 JSON field | exact match |

Verified controls:

- **Unknown direct XML children are rejected** by `_require_response_root` (`evidence.py:570-576`). The tests cover this for all four XML parsers.
- **Duplicate direct XML children are rejected** by `_validate_tree` (`evidence.py:453-464`). Verified with a repeated `<spreadname_en>`.
- **Namespaced roots and children are rejected** (`evidence.py:444-447`, `456-459`). Verified with `xmlns="urn:x"`.
- **Attributes on `<response>` and on direct children are rejected** (`evidence.py:565-580`). Verified with `foo="bar"`.
- **Malformed XML is rejected** as `EvidenceExtractionError` (`evidence.py:433-438`).
- **Malformed JSON is rejected** as `EvidenceExtractionError` (`evidence.py:812-817`).
- **Non-object JSON is rejected** (`evidence.py:818-821`), and unknown JSON fields are rejected (`evidence.py:823-827`).
- **Missing required XML fields are rejected** (`evidence.py:584-590`, `468-491`).
- **Empty required XML values are rejected** (`evidence.py:486-490`).
- **Gated `<error>` roots are rejected by the parsed-capture parsers** with the recorded code (`evidence.py:555-560`). Verified for `100003`, `125002`, and `100002`.
- **Empty optional login values become explicit gaps** (`evidence.py:755-770`).
- **Empty `OperatorName` becomes an explicit gap**, not an invented fact (`evidence.py:854-867`).
- **Missing optional captures become explicit gaps** for operator info, login state, fixtures, gated sources, and band-capability sources.
- **Provenance is present on every fact and gap**: `source_file`, `locator`, and `explanation` are validated by `EvidenceFact` and `EvidenceGap` (`evidence.py:287-342`).
- **Locators match the accepted structure** for every parser: `/response/<tag>`, `/OperatorName`, `/error/code`, and `line <n>` for the historical `n78` line.

### 3.2 Evidence integrity

- `Rat=7` produces only `network.rat_mode="7"`. It produces no `band.*` fact and no confirmed slot.
- `nrProductEnable=1` produces only `feature.nrProductEnable="1"`. It produces no `band.*` fact and no confirmed slot.
- Historical `n78` remains `observed` and is never promoted (`evidence.py:1003-1018`).
- The built profile has `rat_mode=7`, `confirmed_slots=()`, and one observed `NR n78` slot.
- Gated responses (`100003`, `125002`, `100002`) are reported as unavailable gaps only.
- Missing LTE/NR/generic band captures and `config/network/bandfreqlist.xml` are explicit gaps only.
- Contradiction machinery exists in three places: fixture corroboration (`_corroborate`, `evidence.py:504-517`), duplicate fact values/status (`DeviceEvidence.fact`, `evidence.py:375-385`), and duplicate/contradictory band slots (`evidence.py:1186-1196`).
- No parser emits a `band.*` fact from a feature flag, RAT mode, PLMN, operator label, login state, or gated response.

### 3.3 Backward compatibility with Phase 9

The Phase 9 implementation was extracted from `HEAD` into a temporary archive and run against the same repository captures. Structural comparison:

| Metric | Phase 9 HEAD | Phase 10 working tree |
|---|---:|---:|
| Facts | 13 | 23 |
| Gaps | 11 | 14 |
| Facts only in Phase 9 | 0 | — |
| Facts only in Phase 10 | — | 10 `login.*` facts |
| Changed Phase 9 facts | 0 | 0 |
| Gaps only in Phase 9 | 0 | — |
| Gaps only in Phase 10 | — | `data source: USB tethering switch`, `login.userlevel`, `login.username` |
| Changed Phase 9 gaps | 0 | 0 |
| `DeviceBandProfile` | baseline | **identical** |

All 13 Phase 9 facts retain their names, values, statuses, source files, and locators. The 10 new facts are login metadata only. All 11 Phase 9 gaps are preserved. The profile — device name, PLMN, RAT mode, slots, confirmed/observed split, and notes — is identical.

Public surface:

- Existing exports remain in `__init__.py`.
- Five new exports are additive: `parse_basic_information`, `parse_current_plmn`, `parse_module_switch`, `parse_operator_info`, `parse_state_login`.
- `DeviceEvidence`, `EvidenceFact`, and `EvidenceGap` contracts are unchanged.
- `collect_device_facts` still requires the same basic-information, PLMN, module-switch, and Phase 1 document sources; fixtures, login, and operator captures remain optional.
- `repository_device_profile` still returns the same profile type and values.
- `src/huawei_tower/bestpair/engine.py` has no diff from `HEAD`.
- The full suite passes, including the existing Phase 9 Best Pair tests.

### 3.4 Security and scope

- `evidence.py` imports only `json`, `re`, `dataclasses`, `pathlib`, `typing`, `..modem.errors`, `..modem.xmlutil`, and `.engine`. No network module.
- `tests/test_capture_parsers.py` imports only `json`, `pathlib`, `pytest`, `huawei_tower.bestpair`, and `huawei_tower.modem.api`.
- No `requests`, `urllib`, `http`, `socket`, `aiohttp`, `httpx`, `subprocess`, `eval`, `exec`, JavaScript, token, cookie, or authentication handling was added to the reviewed files.
- `git diff HEAD -- src/huawei_tower/modem/api.py` is empty: `SAFE_GET_ENDPOINTS`, `GATED_GET_ENDPOINTS`, and `FORBIDDEN_PATHS` are unchanged; default-deny remains at `api.py:256-266`.
- `git diff HEAD -- src/huawei_tower/bestpair/engine.py` is empty: no scoring or ranking change.
- `/api/app/operatorinfo` remains default-denied; it is not in `SAFE_GET_ENDPOINTS` or `GATED_GET_ENDPOINTS`.
- No new band capability is inferred. No observed fact is promoted to confirmed.

### 3.5 Test suite

- The new file contains exactly 32 tests.
- New-test coverage of `evidence.py`: **85%** (66 missed statements).
- Full-suite coverage of `evidence.py`: **90%** (44 missed statements).
- Full suite: **240 passed**.
- The new tests cover acceptance, provenance, malformed XML/JSON, missing required fields, unknown fields, gated error roots, missing band captures, RAT-mode-only behavior, no NR-band inference from `nrProductEnable`, `n78` observed-only, empty optional gaps, empty/missing operator gaps, observed operator behavior, and endpoint denial.

The test-quality findings below concern branches that remain untested, not the correctness of the branches that are tested.

---

## 4. Findings

### F-01 — JSON duplicate keys are silently collapsed to the last value

**Severity:** Medium  
**Location:** `src/huawei_tower/bestpair/evidence.py:812-817` (`json.loads` at line 813)

**Reproducer:** write this as `evidence/raw/_api_app_operatorinfo.xml` and call `parse_operator_info(repo_root)`:

```json
{"OperatorName": "A", "OperatorName": "B"}
```

**Expected:** the parser rejects the ambiguous payload with `EvidenceExtractionError`, because duplicate keys make the captured field value indeterminate.

**Actual:** `json.loads` keeps the last value, and the parser returns a single observed fact:

```text
network.operator_name = "B" (observed)
```

The first value is silently discarded. This violates the fail-closed and “no silent discarding of contradictory information” requirements.

**Recommended correction:** parse with an `object_pairs_hook` that raises on any duplicate key, and translate that failure to `EvidenceExtractionError`. Add a regression test using the duplicate-key payload above.

---

### F-02 — Unicode numeric digits are accepted; a non-decimal digit raises a raw `ValueError`

**Severity:** Medium  
**Location:** `evidence.py:251-252` (`_PLMN_RE`, `_ERROR_CODE_RE`), `:536` (`_require_integer`), `:676-679` (PLMN/RAT), `:772` (login numeric tags), `:1152` (profile RAT)

**Reproducer A — Unicode PLMN accepted as confirmed:**

```xml
<response><Numeric>٤٣٢١١</Numeric><Rat>7</Rat></response>
```

`_PLMN_RE = re.compile(r"^\d{5,6}$")` uses Unicode-aware `\d`, so the Arabic-Indic digits match. The parser returns:

```text
network.plmn = "٤٣٢١١" (confirmed)
```

**Reproducer B — Unicode RAT accepted and stored unnormalized:**

```xml
<response><Numeric>43211</Numeric><Rat>٧</Rat></response>
```

`"٧".isdigit()` is true and `int("٧")` is 7, so the parser accepts it and stores `network.rat_mode = "٧"`. The profile later converts it to integer 7, creating a value/provenance inconsistency.

**Reproducer C — superscript digit raises a raw exception:**

```xml
<response><Numeric>43211</Numeric><Rat>²</Rat></response>
```

`"²".isdigit()` is true, but `int("²")` raises:

```text
ValueError: invalid literal for int() with base 10: '²'
```

This escapes the `EvidenceExtractionError` contract. The same pattern exists at `evidence.py:1152` in `build_profile_from_evidence`.

**Expected:** only ASCII decimal digits are accepted, and every malformed value raises `EvidenceExtractionError` (or `EvidenceValidationError` in the profile layer), never a raw `ValueError`.

**Actual:** non-ASCII decimal digits are accepted; a non-decimal Unicode digit raises `ValueError`.

**Recommended correction:** use ASCII-only patterns (`re.fullmatch(r"[0-9]+", value)` or `re.ASCII`), reject any non-ASCII digit before calling `int`, and normalize stored numeric values to ASCII. Apply the same fix to `_PLMN_RE`, `_ERROR_CODE_RE`, `_require_integer`, the RAT checks, and the profile-layer RAT check. Add tests for Arabic-Indic, full-width, and superscript digits.

---

### F-03 — Recorded HTTP status and leading junk are ignored; an error body can become confirmed facts

**Severity:** Medium  
**Location:** `evidence.py:413-418` (`_payload_start`), `:809-813` (JSON `text.find("{")`)

**Reproducer A — XML body recorded under HTTP 500:**

```text
HTTP/1.1 500 Internal Server Error
Content-Type: text/xml

<response><productfamily>LTE</productfamily><classify>cpe</classify><devicename>H158-381</devicename><spreadname_en>5G CPE Pro 5</spreadname_en></response>
```

`_payload_start` searches for `<?xml`, `<response`, `<error`, or `<` and ignores everything before the body. `parse_basic_information` returns four confirmed facts.

**Reproducer B — JSON body recorded under HTTP 500:**

```text
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{"OperatorName":"Evil"}
```

`parse_operator_info` finds the `{` and returns `network.operator_name = "Evil"` as observed.

**Expected:** the parser validates the recorded status line and rejects non-2xx captures. At minimum, a capture with an explicit error status must not produce facts, even if the body happens to look like a valid response.

**Actual:** the status line is ignored entirely; only the body is parsed. Any leading text before the first `<` or `{` is also ignored.

**Recommended correction:** parse the optional leading status line, accept only `HTTP 200`/2xx, and reject `4xx`/`5xx` with `EvidenceExtractionError`. Require the payload to begin after a validated header block (or at the start of the file), rather than searching for the first `<` or `{` anywhere. Add tests for `HTTP 500` with otherwise-valid XML and JSON.

---

### F-04 — Any line containing `n78`, including a negation, becomes an observed band fact

**Severity:** Medium  
**Location:** `evidence.py:990-1018` (`_line_containing(doc_text, "n78")`)

**Reproducer:** set `docs/PHASE1_FINDINGS.md` to:

```text
There is no n78 support and no NR capability.
```

and call `collect_device_facts(repo_root)`.

**Expected:** no `band.nr.n78` fact is emitted, or an explicit gap/contradiction is reported, because the document denies `n78` support.

**Actual:** the substring match finds `n78` and emits:

```text
band.nr.n78 = "n78" (observed)
```

The observed slot is not rankable, so the immediate capability impact is limited, but the fact is unsupported and contradicts the document. This is an evidence-integrity false positive.

**Recommended correction:** require an affirmative, structured observation marker rather than a bare substring. For example, parse a dedicated “observed bands” section or require a phrase such as `observed: n78`; at minimum, detect common negations (`no n78`, `n78 not`, `without n78`) and refuse to emit the fact. Add tests for affirmative and negative documents.

---

### F-05 — The highest-risk fail-closed branches are not exercised by the 32 new tests

**Severity:** Medium  
**Location:** `tests/test_capture_parsers.py` (all 32 tests); uncovered branches in `evidence.py`

**Coverage evidence:**

- New tests alone: `evidence.py` 85% covered, 66 missed statements.
- Full suite: `evidence.py` 90% covered, 44 missed statements.

The following fail-closed branches are not exercised by the new tests (some remain uncovered even by the full suite):

| Branch | Location | Why it matters |
|---|---|---|
| Namespaced child rejection | `evidence.py:456-459` | Namespace handling is a stated risk |
| Duplicate XML child rejection | `evidence.py:460-463` | Duplicate-field rejection is a stated requirement |
| `<response>` attribute rejection | `evidence.py:565-568` | Attribute handling is a stated risk |
| Child attribute rejection | `evidence.py:577-580` | Attribute handling is a stated risk |
| Invalid integer rejection | `evidence.py:536-539` | Invalid-type rejection |
| Invalid RAT rejection | `evidence.py:678-679` | RAT validation |
| No JSON payload | `evidence.py:810-811` | Malformed-input rejection |
| Non-dict JSON | `evidence.py:818-821` | Invalid-type rejection |
| Non-string `OperatorName` | `evidence.py:832-836` | Invalid-type rejection |
| Fixture `<error>` contradiction | `evidence.py:899-902` | Contradictory evidence fails closed |
| PLMN fixture `<error>` contradiction | `evidence.py:952-955` | Contradictory evidence fails closed |
| Present but unverified gated response | `evidence.py:1073-1084` | Gated response must not become a fact |
| Present band capture | `evidence.py:1089-1101` | Band capture must not be parsed without review |
| Duplicate band evidence | `evidence.py:1194-1196` | Contradictory/duplicate evidence fails closed |

**Expected:** each fail-closed branch has at least one negative test that proves the parser rejects the input and does not emit a fact.

**Actual:** the tests cover malformed XML/JSON, missing fields, unknown tags, and gated `<error>` roots, but not the namespace, attribute, duplicate-element, invalid-integer, invalid-RAT, non-dict JSON, fixture-contradiction, present-gated-response, present-band-capture, or duplicate-band branches. This gives false confidence in exactly the branches the Phase 10 document calls out as risks.

**Recommended correction:** add focused tests for each row above, using the same temporary-repository helper. For the fixture and band branches, construct a complete temporary repository so `collect_device_facts` reaches the branch. Assert both the exception type/message and the absence of a fact.

---

### F-06 — Root text, child tail text, and nested content under unused optional tags are silently ignored

**Severity:** Low  
**Location:** `evidence.py:442-465` (`_validate_tree`), `:468-491` (`_child_text`), `:570-581` (`_require_response_root`)

**Reproducer A — root text:**

```xml
<response>IGNORED<productfamily>LTE</productfamily><classify>cpe</classify><devicename>H158-381</devicename><spreadname_en>5G CPE Pro 5</spreadname_en></response>
```

**Reproducer B — child tail:**

```xml
<response><productfamily>LTE</productfamily>TAIL<classify>cpe</classify><devicename>H158-381</devicename><spreadname_en>5G CPE Pro 5</spreadname_en></response>
```

**Reproducer C — nested content under an unused optional tag:**

```xml
<response><productfamily>LTE</productfamily><classify>cpe</classify><devicename>H158-381</devicename><spreadname_en>5G CPE Pro 5</spreadname_en><multimode><x>1</x></multimode></response>
```

**Expected:** unexpected character data or nested structure is rejected, because the parser claims a closed, leaf-only schema.

**Actual:** all three are accepted. `_validate_tree` checks tags, namespaces, and duplicates but not `root.text` or `child.tail`; `_child_text` checks `len(node)` only for tags it reads; `_require_response_root` checks tags and attributes but not text/tail. The unused optional fields (`multimode`, `restore_default_status`, `sim_save_pin_enable`, `spreadname_zh`, the 87 non-feature module-switch tags, and the optional PLMN/login tags) can contain arbitrary nested content that is never inspected.

**Recommended correction:** reject non-whitespace `root.text` and `child.tail` in `_validate_tree`; in `_require_response_root`, require every allowed child to be a leaf with text only (or explicitly allowlist the few tags that may contain children). Add tests for root text, child tail, and nested optional content.

---

### F-07 — `source_file` accepts POSIX-absolute and Windows drive-relative paths

**Severity:** Low  
**Location:** `evidence.py:277-284` (`_require_source_file`)

**Reproducer:**

```python
EvidenceFact("n", "v", "confirmed", "/abs/x", "/x", "e")
EvidenceFact("n", "v", "confirmed", "C:x", "/x", "e")
```

**Expected:** both are rejected with `EvidenceValidationError`, because provenance must be repository-relative.

**Actual:** both are accepted. On Windows, `Path("/abs/x").is_absolute()` is false and `..` is not in its parts, so `/abs/x` survives and `as_posix()` returns `/abs/x`. `Path("C:x")` is drive-relative, not absolute, and also survives.

**Recommended correction:** reject `path.anchor`, `path.drive`, and any leading `/` or `\` explicitly; use `PurePosixPath` for the repository-relative form and require a non-empty first part that is not a drive. Add tests for `/abs/x`, `C:x`, `C:/x`, and `a/../../b`.

---

### F-08 — Invalid UTF-8 is silently replaced with `U+FFFD`

**Severity:** Low  
**Location:** `evidence.py:404-410` (`_read_text`, `errors="replace"`)

**Reproducer:** write a basic-information capture with a raw `0xFF` byte inside the device name:

```python
data = BASIC.encode("utf-8").replace(b"H158-381", b"H158-\xff381")
```

**Expected:** decoding fails closed with `EvidenceExtractionError`, because the capture is not valid UTF-8.

**Actual:** the invalid byte becomes `�` and the parser returns:

```text
device.model = "H158-�381" (confirmed)
```

The fact is confirmed despite not being a faithful reading of the capture.

**Recommended correction:** read with `errors="strict"` and catch `UnicodeDecodeError`, translating it to `EvidenceExtractionError` with the relative path. Add a regression test using an invalid byte.

---

### F-09 — Internal XML entities expand when the payload starts with `<?xml`

**Severity:** Low  
**Location:** `evidence.py:413-418` (`_payload_start`); `src/huawei_tower/modem/xmlutil.py:9-14` (`ET.fromstring`)

**Reproducer:**

```xml
<?xml version="1.0"?><!DOCTYPE response [<!ENTITY x "LTE">]><response><productfamily>&x;</productfamily><classify>cpe</classify><devicename>H158-381</devicename><spreadname_en>5G CPE Pro 5</spreadname_en></response>
```

**Expected:** a captured response containing a `DOCTYPE`/entity declaration is rejected, because a real modem response does not need entities and entity expansion is an unnecessary parser capability.

**Actual:** the parser accepts the document and resolves `&x;` to `LTE`. External entities (`SYSTEM "file:///..."`) are rejected by ElementTree, so this is not XXE, but internal entity expansion remains. A sufficiently large entity chain can consume CPU/memory (billion-laughs style). Without an XML declaration, `_payload_start` skips the `DOCTYPE` and the entity reference fails as malformed; with `<?xml`, it expands.

**Recommended correction:** reject `<!DOCTYPE` and `<!ENTITY` before parsing (case-insensitive), or use a parser configured to forbid DTDs/entities. This is a pre-existing shared-parser behavior, but Phase 10 now feeds it captured evidence. Add a test for a DOCTYPE-bearing payload.

---

### F-10 — PLMN validation is length-only; `00000` and leading-zero MCCs are accepted

**Severity:** Low  
**Location:** `evidence.py:251` (`_PLMN_RE`), `:676-677` (`parse_current_plmn`)

**Reproducer:**

```xml
<response><Numeric>00000</Numeric><Rat>7</Rat></response>
```

and:

```xml
<response><Numeric>043211</Numeric><Rat>7</Rat></response>
```

**Expected:** implausible PLMNs are rejected, at least all-zero and leading-zero MCCs, because they cannot identify a real network.

**Actual:** both are accepted as confirmed `network.plmn` facts. `_PLMN_RE` only checks 5–6 digits.

**Recommended correction:** validate the MCC/MNC structure: MCC is three digits and not all zero; reject a leading-zero MCC; optionally validate the MCC against the assigned range and MNC length. Add tests for `00000`, `043211`, and valid `43211`/`432111`.

---

### F-11 — RAT validation accepts any `0..255`; no known-mode allowlist

**Severity:** Low  
**Location:** `evidence.py:678-679` (`parse_current_plmn`), `:1152` (`build_profile_from_evidence`)

**Reproducer:**

```xml
<response><Numeric>43211</Numeric><Rat>255</Rat></response>
```

**Expected:** either only known Huawei RAT mode values are accepted, or the value is explicitly documented as an opaque numeric mode with no interpretation beyond the known `7` NSA case.

**Actual:** `255` is accepted as a confirmed `network.rat_mode` fact and becomes `rat_mode=255` in the profile.

**Recommended correction:** define an allowlist of known modes (at minimum the values the firmware uses) and reject unknown values, or document the opaque numeric contract and keep the “mode only, never a band” explanation. Add tests for the boundary values `0`, `7`, `255`, and `256`.

---

### F-12 — Login numeric fields have no range validation

**Severity:** Low  
**Location:** `evidence.py:535-540` (`_require_integer`), `:771-772` (`parse_state_login`)

**Reproducer:**

```xml
<response>...<accounts_number>999999999</accounts_number>...</response>
```

**Expected:** per-field range validation, at least for non-negative counts such as `accounts_number`, `firstlogin`, `lockstatus`, and `remainwaittime`.

**Actual:** `_require_integer` checks only `-?\d+`; any magnitude is accepted and stored as a confirmed `login.*` fact.

**Recommended correction:** add per-field bounds (for example, `accounts_number >= 0`, `firstlogin`/`lockstatus` in `{0,1}`, `remainwaittime >= 0`) or explicitly document these fields as opaque numeric metadata. Add tests for negative and oversized values.

---

### F-13 — A non-string `OperatorName` is reported as “missing”

**Severity:** Low  
**Location:** `evidence.py:832-836`

**Reproducer:**

```json
{"OperatorName": 123}
```

**Expected:** an error explaining that `OperatorName` must be a string.

**Actual:** `EvidenceExtractionError: missing OperatorName field in evidence/raw/_api_app_operatorinfo.xml`, even though the field is present.

**Recommended correction:** use a distinct message such as “OperatorName must be a string” and add a test for a non-string value.

---

### F-14 — Control characters in `OperatorName` are accepted

**Severity:** Low  
**Location:** `evidence.py:838-843`

**Reproducer:**

```json
{"OperatorName": "A\u0000B"}
```

**Expected:** the parser rejects C0 control characters, because they are not plausible display text and can corrupt downstream output.

**Actual:** the value is stripped (the NUL survives) and returned as an observed fact:

```text
network.operator_name = "A\x00B" (observed)
```

**Recommended correction:** reject Unicode category `Cc` (at least NUL, CR, LF, and other C0 controls) in text fields, or normalize/reject control characters explicitly. Add a test for `\u0000` and `\n`.

---

### F-15 — Fixture schema is not closed; unknown fixture fields are silently ignored

**Severity:** Low  
**Location:** `evidence.py:897-930` (device fixture), `:950-969` (PLMN fixture)

**Reproducer:** add `evidence/fixtures/device_basic_information.xml`:

```xml
<response><DeviceName>H158-381</DeviceName><ProductFamily>LTE</ProductFamily><Classify>cpe</Classify><SpreadName>5G CPE Pro 5</SpreadName><Bands>n78</Bands></response>
```

and call `collect_device_facts(repo_root)`.

**Expected:** the fixture is either validated against a closed schema or reported as an explicit gap/contradiction because it contains an unrecognized field.

**Actual:** the fixture is accepted, the four expected fields corroborate the raw capture, and `<Bands>n78</Bands>` is silently ignored. A fixture with all expected fields missing also produces no gap; `_child_text(..., required=False)` returns `None` and `_corroborate` returns early.

**Recommended correction:** apply a fixture-specific `_require_response_root` allowlist (for example `DeviceName`, `ProductFamily`, `Classify`, `SpreadName`), reject unknown/duplicate/attributed fixture children, and emit a gap when a fixture provides no corroborating fields. Add tests for an extra fixture field and an empty fixture.

---

### F-16 — Same-name/value/status facts with different provenance are silently collapsed

**Severity:** Low  
**Location:** `evidence.py:375-385` (`DeviceEvidence.fact`)

**Reproducer:**

```python
a = EvidenceFact("n", "v", "confirmed", "evidence/raw/a.xml", "/response/x", "e")
b = EvidenceFact("n", "v", "confirmed", "evidence/raw/b.xml", "/response/y", "e2")
DeviceEvidence((a, b)).fact("n")
```

**Expected:** either both facts are returned, or the differing provenance is reported as an ambiguity/contradiction.

**Actual:** `fact("n")` returns `a`; `b` is silently ignored because only `value` and `status` are compared.

**Recommended correction:** compare `source_file` and `locator` as well, or return all matches and let the caller decide. Add a test for same value/status with different provenance.

---

### F-17 — Tests assert explanation prose and use a weak locator check

**Severity:** Low  
**Location:** `tests/test_capture_parsers.py:162`, `:356`, `:363`, `:375`

**Reproducer:** change the explanation wording in `evidence.py` without changing behavior:

- `"Rat 7 is the LTE+NR NSA mode"` → `"RAT 7 means LTE+NR NSA"`  
- `"does not prove"` → `"cannot prove"`  
- `"no band is invented"` → `"no band is fabricated"`

**Expected:** behavior-focused tests continue to pass.

**Actual:** the tests fail because they assert substrings of the explanation prose:

```python
assert "no band is invented" in gaps[name].explanation
assert "mode only" in rat.explanation
assert "does not prove" in flag.explanation
```

Separately, `test_provenance_survives_every_parser` checks only that `fact.locator.startswith("/")`; it does not verify that the locator points to the actual element or field.

**Recommended correction:** assert values, statuses, fact-name prefixes, and the absence of `band.*` facts instead of explanation wording. For provenance, assert the exact expected locator per fact (for example `"/response/devicename"`, `"/response/Numeric"`, `"/OperatorName"`), and add a test that the locator resolves to the expected node in the capture.

---

### F-18 — Synthetic fixtures under-represent the real capture schemas

**Severity:** Low  
**Location:** `tests/test_capture_parsers.py:32-67`

**Reproducer:** compare the synthetic fixtures with the real captures:

| Fixture | Synthetic fields | Real fields |
|---|---:|---:|
| `_BASIC_VALID` | 4 | 8 |
| `_PLMN_VALID` | 2 | 6 |
| `_MODULE_VALID` | 6 | 93 |
| `_LOGIN_VALID` | 12 | 12 |

**Expected:** at least one test per parser exercises the full real schema, or the test asserts that the closed schema equals the real capture's direct children.

**Actual:** the synthetic fixtures are minimal. The real-capture test at `tests/test_capture_parsers.py:128-144` mitigates this for acceptance, but the negative tests only mutate the minimal fixtures. A regression that rejects a real optional field (for example, one of the 87 non-feature module-switch tags) would not be caught by the synthetic tests unless it also affects the six feature flags.

**Recommended correction:** add a test that asserts `set(_MODULE_SWITCH_TAGS)` equals the real capture's direct children (and similarly for the other schemas), or build the negative fixtures by copying a real capture and mutating one field. This is a test-quality improvement, not a production defect.

---

### F-19 — Phase 10 audit document status and line references are stale

**Severity:** Low  
**Location:** `docs/PHASE10_STATIC_API_DISCOVERY.md:3-5`, `:88`, `:104`, `:627`

**Reproducer:** read the document after the implementation exists in the working tree:

```text
Status: audit complete. No implementation, no live device contact, no source change.
...
Phase 10 implementation is not started and must not begin without explicit approval.
...
- No uncommitted source, test, evidence, or endpoint-allowlist change exists.
...
- No source, test, allowlist, or Git configuration change; no commit, push, ...
```

**Expected:** the document reflects the current state: implementation is present and pending review; source and tests are modified; the working tree is not clean. Historical audit-time statements can remain if clearly marked as historical, but the status block must not contradict the repository.

**Actual:** the status block says “No implementation” and “not started”; the scope-discipline section says no uncommitted source/test change exists. Both are false for the current working tree. Additionally, line 627 cites `evidence.py:40`, `:613-644`; the profile/provenance code has moved, so the second citation no longer points to the described code.

**Recommended correction:** update the status to “implementation complete, pending independent review,” or add a dated addendum that records the implementation state and preserves the audit-time text as historical. Recompute the `evidence.py` line references or replace them with symbol names. Do not rewrite the audit’s historical findings; add a clearly separated update section.

---

### F-20 — Path-denial test checks allowlist membership, not actual default-deny behavior

**Severity:** Low  
**Location:** `tests/test_capture_parsers.py:448-472`

**Reproducer:** add an alternative allow path to `ReadOnlyModemClient` that does not use `SAFE_GET_ENDPOINTS` (hypothetically), or change `_classify` to approve `/api/app/operatorinfo` while leaving the dictionaries unchanged.

**Expected:** the test proves the actual gate rejects the path, not merely that the path is absent from two dictionaries.

**Actual:** the test asserts:

```python
assert path not in SAFE_GET_ENDPOINTS
assert "/api/app/operatorinfo" not in GATED_GET_ENDPOINTS
```

It does not call `_classify` or assert the default-deny branch. The current implementation is correct, but the test is weaker than the invariant it claims to protect.

**Recommended correction:** call `ReadOnlyModemClient._classify(path)` (a pure method; no network) and assert a rejection reason for `/api/app/operatorinfo`, the band paths, and the forbidden paths. Keep the dictionary-membership assertions as a secondary check. Add a test for an arbitrary unknown path to prove default-deny.

---

### I-01 — `assert` is used for type narrowing after validation

**Severity:** Informational  
**Location:** `evidence.py:496, 599, 607-612, 669, 675, 715, 722, 750`

**Observation:** several parsers use `assert root is not None` or `assert value is not None` after a required helper has already validated the value. Today the helpers guarantee the condition, so the asserts are not input validation and cannot fire for valid inputs. Under `python -O`, the asserts are stripped; the code still works because the preceding helpers raise on failure.

**Recommendation:** replace the asserts with explicit `if ...: raise EvidenceExtractionError(...)` or a typed cast, so the failure mode does not depend on `assert` semantics. This is a maintainability hardening item, not a current defect.

---

### I-02 — Untracked `.claude/` is unrelated ECC configuration

**Severity:** Informational  
**Location:** repository root

**Observation:** `git status --short --branch` shows `?? .claude/`. This directory contains the project ECC marketplace/plugin configuration used for this review. It is not part of the Phase 10 parser implementation.

**Recommendation:** do not include `.claude/` in the Phase 10 commit. Either leave it untracked, add it to `.gitignore` if it is intentionally local, or commit it separately with its own rationale. This is repository hygiene, not a code finding.

---

### I-03 — `parse_module_switch` is all-or-nothing on the six feature flags

**Severity:** Informational  
**Location:** `evidence.py:191` (`_MODULE_SWITCH_REQUIRED = _FEATURE_FLAGS`), `:717`

**Observation:** if a future capture omits any one of `nrProductEnable`, `oneKeyCheckEnable`, `bestsignal_enable`, `celllock_enabled`, `antenna_enabled`, or `sa_enable`, the entire module-switch parse fails rather than emitting a gap for the missing flag. This is conservative and matches the current real capture (all six present), but it makes the parser brittle to firmware variation.

**Recommendation:** decide explicitly whether these six are required or optional. If optional, emit a gap per missing flag; if required, document the firmware dependency and keep the current fail-closed behavior. No change is required for Phase 10 approval.

---

### I-04 — Non-empty `OperatorName` is deliberately marked `observed`, not `confirmed`

**Severity:** Informational  
**Location:** `evidence.py:844`

**Observation:** a non-empty `OperatorName` from a captured response is marked `observed`, even though the module’s general definition says a direct value from a captured read-only response is `confirmed`. This is conservative: the operator endpoint is app-level and the real capture is empty, so `observed` is the safer label. It is not a defect, but the inconsistency should be intentional and documented.

**Recommendation:** keep `observed` unless the operator endpoint is independently verified. Add a comment explaining why this captured field is not promoted to `confirmed`, so a future maintainer does not “fix” it.

---

### I-05 — Profile notes mention “Rat 7” unconditionally

**Severity:** Informational  
**Location:** `evidence.py:1213-1218`

**Observation:** `build_profile_from_evidence` always includes the sentence “Rat 7 proves the LTE+NR NSA mode only, never specific band combinations,” even when `rat_mode` is absent or a different value. This is pre-existing Phase 9 text, but it can mislead when the profile’s `rat_mode` is not 7.

**Recommendation:** make the note conditional on `rat_mode == 7`, or phrase it generically (“RAT mode alone never proves a band combination”). This is a clarity improvement, not a Phase 10 regression.

---

## 5. Test-quality review (all 32 tests)

### 5.1 Test inventory

| Group | Tests | Assessment |
|---|---:|---|
| Acceptance and provenance | 3 | Good: covers all five parsers, real captures, and source/locator presence. |
| Malformed XML/JSON | 5 | Good: one malformed XML case per XML parser, one malformed JSON case. |
| Missing required fields | 6 | Good: covers basic, PLMN, module-switch, login, operator, and missing capture. |
| Unknown fields | 5 | Good: covers unknown XML tags for all four XML parsers and unknown JSON field. |
| Gated error stubs | 4 | Good for the three codes and gap explanations; only tests the basic-information parser with an `<error>` root. |
| Unavailable band evidence | 4 | Good: missing band captures, RAT-mode-only, `nrProductEnable`, `n78` observed. |
| Explicit gaps | 4 | Good: empty login values, empty operator, missing operator, non-empty operator observed. |
| Policy invariants | 1 | Partially good: checks allowlist membership, not actual `_classify` behavior. |

### 5.2 Missing negative tests

The following negative cases are absent (see F-05 for the full table):

- Namespaced child element.
- Duplicate XML child element.
- Attribute on `<response>` or a child.
- Invalid integer in a login field.
- Invalid RAT (including Unicode superscript).
- JSON payload with no `{`.
- JSON top-level array/string/number/null.
- Non-string `OperatorName`.
- Duplicate JSON key.
- Fixture `<error>` contradiction.
- PLMN fixture `<error>` contradiction.
- Present but unverified gated response.
- Present band-capability capture.
- Duplicate band evidence.
- Absolute/POSIX-absolute `source_file`.
- Invalid UTF-8 capture.
- `DOCTYPE`/entity-bearing capture.
- Root text, child tail, nested optional content.
- `HTTP 500` status with a valid body.

### 5.3 Tests that assert implementation details

- `tests/test_capture_parsers.py:356` — `"no band is invented" in gap.explanation`.
- `tests/test_capture_parsers.py:363` — `"mode only" in rat.explanation`.
- `tests/test_capture_parsers.py:375` — `"does not prove" in flag.explanation`.
- `tests/test_capture_parsers.py:162` — locator check is only `startswith("/")`.

These are coupled to wording rather than behavior. Replace with value/status/name assertions and exact locators.

### 5.4 Synthetic fixtures that do not represent real captures

The minimal fixtures at `tests/test_capture_parsers.py:32-67` cover 4/8 basic fields, 2/6 PLMN fields, and 6/93 module-switch fields. The real-capture acceptance test at lines 128–144 mitigates this, but the negative tests mutate only the minimal fixtures. A schema regression affecting an optional real field would not be caught. See F-18.

### 5.5 False confidence

The new tests are strong on the “happy path” and on unknown/missing fields, but the Medium test-coverage finding (F-05) means the suite overstates fail-closed coverage. The 85%/90% statement counts are useful, but the uncovered lines are disproportionately the risky rejection branches. The review should not treat “32 tests, 85% coverage” as proof that every stated risk is tested.

### 5.6 Important parser behavior not covered

- XML attribute rejection (implementation correct; untested).
- XML namespace rejection at the child level (implementation correct; untested).
- Duplicate XML child rejection (implementation correct; untested).
- JSON duplicate-key ambiguity (implementation missing; untested).
- Unicode digit handling (implementation missing; untested).
- HTTP status handling (implementation missing; untested).
- Fixture contradiction (implementation correct; untested).
- Present-but-unparsed band capture (implementation correct; untested).
- Duplicate band evidence (implementation correct; untested).
- `source_file` path resolution edge cases (implementation partially missing; untested).

---

## 6. Specific risk checklist

| Risk | Result | Evidence |
|---|---|---|
| XML root validation | **Pass** | `_validate_tree` accepts only `response`/`error`; namespaced/unknown roots rejected. |
| Namespace handling | **Pass (untested)** | Namespaced root and child tags rejected; no test. |
| Attribute handling | **Pass (untested)** | Attributes on `<response>` and direct children rejected; no test. |
| Duplicate XML elements | **Pass (untested)** | Duplicate direct children rejected; no test. |
| JSON duplicate keys | **Fail** | Last value wins silently (F-01). |
| Unicode and whitespace normalization | **Partial** | Whitespace stripped; Unicode digits accepted (F-02). |
| Integer parsing and range | **Partial** | Syntax checked; RAT has 0–255; login fields unbounded (F-02, F-11, F-12). |
| Boolean parsing | **Pass** | `_validate_flag` accepts only `"0"`/`"1"`; tests cover feature flags. |
| PLMN validation | **Partial** | 5–6 digits; no MCC/MNC semantics (F-10). |
| RAT validation | **Partial** | Numeric range only; no allowlist; raw `ValueError` on superscript (F-02, F-11). |
| XML entity/parser behavior | **Partial** | External entities rejected; internal entities expand with `<?xml` (F-09). |
| Path traversal/source resolution | **Partial** | `..` and `C:/x` rejected; `/abs/x` and `C:x` accepted (F-07). |
| Provenance locator stability | **Pass** | Exact locators for accepted structures; `n78` line number; tests only weakly check. |

---

## 7. Security and scope verification

### 7.1 No network or modem access

- No network module is imported by `evidence.py`, `__init__.py`, or the new tests.
- No `ReadOnlyModemClient` was instantiated during this review.
- No HTTP, HTTPS, DNS, socket, scan, login, SCRAM, reconnect, reboot, lock, or configuration operation was performed.
- The only HTTP-like strings used were synthetic local fixtures (`HTTP/1.1 500 ...`) to test the parser’s status handling.
- `git archive` and `pytest` are local operations; the archive was written to a temporary directory outside the repository.
- `git diff HEAD -- src/huawei_tower/modem/api.py` is empty.
- `git diff HEAD -- src/huawei_tower/bestpair/engine.py` is empty.

### 7.2 No endpoint policy change

`SAFE_GET_ENDPOINTS`, `GATED_GET_ENDPOINTS`, and `FORBIDDEN_PATHS` are unchanged. `/api/app/operatorinfo` remains outside both allowlists and is therefore default-denied by `api.py:256-266`. The band, cell, signal, lock, registration, and `/config/**` paths remain gated, forbidden, or unknown exactly as at `HEAD`.

### 7.3 No authentication, token, or JavaScript handling

No authentication, token, cookie, session, SCRAM, or JavaScript execution code was added. The reviewed parser reads local files only. The raw capture’s `Set-Cookie` header is not parsed, not stored in a fact, and not quoted in this review.

### 7.4 No scoring or ranking change

`engine.py` is unchanged. The profile produced from the real captures is structurally identical to the Phase 9 profile. No new scoring input, weight, band slot, or rank behavior was introduced.

### 7.5 No new band capability

No parser emits a `band.*` fact. The only band fact is the historical `n78` observation from `docs/PHASE1_FINDINGS.md`, and it remains `observed`. The profile has zero confirmed slots. `Rat=7` and `nrProductEnable=1` remain mode/toggle facts only.

---

## 8. ECC usage report

### 8.1 ECC capabilities discovered

- Project configuration: `.claude/settings.json` enables the `ecc@ecc` marketplace plugin.
- Installed marketplace: `C:\Users\alireza\.claude\plugins\marketplaces\ecc` (v2.2.3).
- Relevant ECC skills found: `python-patterns`, `python-testing`, `security-review`, `verification-loop`, `change-impact`, `coding-standards`, `tdd-workflow`, `code-tour`, `codebase-onboarding`, `codehealth-mcp`.
- Relevant ECC agents found: `python-reviewer`, `code-reviewer`, `security-reviewer`, `pr-test-analyzer`, plus language-specific reviewers.
- Relevant ECC commands found: `code-review.md`, `python-review.md`, `security-review.md`, `test-coverage.md` (and other review/verification commands).

### 8.2 ECC skills actually invoked

| Skill | Contribution |
|---|---|
| `python-patterns` | Python error-handling, type-narrowing, `assert` usage, path handling, and readability review. |
| `python-testing` | Coverage measurement, negative-test design, fixture realism, and test-quality review. |
| `security-review` | Input validation, path traversal, XML/JSON parser risks, secret handling, and fail-closed review. |
| `verification-loop` | Test, diff, and status verification sequence. |
| `change-impact` | Baseline comparison against Phase 9, blast-radius analysis, and backward-compatibility review. |

### 8.3 ECC specialized agents attempted

| Agent | Result |
|---|---|
| `python-reviewer` | Failed: `Free usage limit reached. Free models work in OpenCode ... subscribe to OpenCode Go ...` |
| `code-reviewer` | Failed: same free-usage limit. |
| `security-reviewer` | Failed: same free-usage limit. |

No output from these agents was used. The review was completed with the loaded skills, the ECC command checklists, and independent probes.

### 8.4 ECC commands and workflows applied

- Read and applied the local `code-review.md` checklist (security issues, code quality, changed-file review).
- Read and applied the `python-review.md` checklist (typing, exceptions, testability, Pythonic structure).
- Read and applied the `security-review.md` checklist (input validation, secrets, path traversal, parser behavior).
- Read and applied the `test-coverage.md` guidance (coverage targets, missing negative tests, behavior-focused assertions).
- No ECC hooks were invoked; the project settings enable the plugin but define no project hooks.

### 8.5 Unavailable or incompatible ECC capabilities

- `ruff`, `mypy`, `black`, `isort`, and `bandit` are not installed in the project virtual environment. The `verification-loop` build/lint/type-check phases are therefore not applicable as written. Nothing was installed, because the task is read-only.
- The project has no build step or lint configuration in `pyproject.toml`; the applicable verification is `pytest`, coverage, `git diff --check`, and `git status`.
- ECC specialized subagents were unavailable due to the free-usage limit.

### 8.6 Conflicts with safety restrictions

ECC workflows suggest fixing findings, installing tooling, and running broader verification. The task explicitly forbids fixes, source/test changes, network access, modem access, and commits. The task restrictions took precedence: findings are reported only, no fix was applied, no tooling was installed, and no network or modem operation was performed.

---

## 9. Final verification

### 9.1 Full test suite

Command:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Result:

```text
240 passed
```

### 9.2 `git diff --check`

Command:

```powershell
git diff --check
```

Result: exit code `0`. The only output is the pre-existing informational warning:

```text
warning: in the working copy of 'src/huawei_tower/bestpair/__init__.py', LF will be replaced by CRLF the next time Git touches it
```

No whitespace errors were reported.

### 9.3 `git status --short --branch`

```text
## phase-3-js-analysis...origin/phase-3-js-analysis
 M src/huawei_tower/bestpair/__init__.py
 M src/huawei_tower/bestpair/evidence.py
?? .claude/
?? docs/PHASE10_STATIC_API_DISCOVERY.md
?? docs/PHASE10_CODE_REVIEW.md
?? tests/test_capture_parsers.py
```

Interpretation:

- `__init__.py` and `evidence.py` are the Phase 10 implementation changes under review.
- `tests/test_capture_parsers.py` is the new test file under review.
- `docs/PHASE10_STATIC_API_DISCOVERY.md` is the audit document under review.
- `docs/PHASE10_CODE_REVIEW.md` is this review deliverable.
- `.claude/` is unrelated ECC configuration and must not be included in the Phase 10 commit.

### 9.4 No source or test modification by this review

No source file, test file, capture, or endpoint policy was modified by this review. The only file created is `docs/PHASE10_CODE_REVIEW.md`. Temporary probe files were created outside the repository in the system temporary directory and are not part of the working tree.

### 9.5 No network or modem access

Confirmed: no network operation, no modem connection, no HTTP/HTTPS request, no DNS, no socket, no scan, no login, no token handling, no JavaScript execution, and no device access occurred during this review. All probes were local file reads and temporary-directory writes.

---

## 10. Approval status

**Not approved as-is.** The implementation is directionally correct and preserves the Phase 9 evidence model, but the five Medium findings should be resolved before approval:

1. Reject JSON duplicate keys (F-01).
2. Make numeric validation ASCII-only and ensure every invalid value raises `EvidenceExtractionError` (F-02).
3. Validate recorded HTTP status and reject error bodies (F-03).
4. Require an affirmative `n78` observation rather than a substring match (F-04).
5. Add negative tests for the untested fail-closed branches (F-05).

The Low findings are recommended hardening and test-quality improvements. No Critical or High finding blocks the design; the Medium findings block approval because they undermine the stated fail-closed and evidence-integrity guarantees.

**Stop point:** review complete. No fix, commit, push, reset, stash, checkout, network operation, or modem access was performed. Awaiting explicit approval before any change.

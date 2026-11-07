# Phase 8 - Offline Best Pair Core Workflow

Status: **Phase 8 core engine reconstructed and verified offline.**
Phase 9 and Phase 10 are **not** started.

This phase rebuilds the lost Best Pair engine from the repository evidence and
the previous product direction. It does not restart Phases 1-7 and does not
change the modem/API security layer.

## 1. Scope and files

Created:

| File | Purpose |
|---|---|
| `src/huawei_tower/bestpair/__init__.py` | Public Phase 8 API |
| `src/huawei_tower/bestpair/engine.py` | Pure-Python validated data model, ranking, and combination engine |
| `tests/test_bestpair.py` | Focused offline tests for validation, scoring, ranking, and combinations |
| `tools/bestpair_demo.py` | Offline demo using the evidence profile plus a clearly synthetic illustration |
| `docs/PHASE8_BEST_PAIR_WORKFLOW.md` | This workflow document |

Not modified: `src/huawei_tower/modem/*`, Phase 7 tests, evidence files, or
dependency manifests. No Phase 7.1 test was recreated.

The engine imports only `math`, `re`, `dataclasses`, and `typing`. It performs
no modem I/O, no HTTP, no socket access, and no JavaScript execution.

## 2. Evidence supporting the default profile

`evidence_minimal_profile()` is built only from evidence present in this
repository.

| Fact | Status | Source |
|---|---|---|
| Device is Huawei `H158-381` / `5G CPE Pro 5` | confirmed | `evidence/fixtures/device_basic_information.xml`, `evidence/raw/_api_device_basic_information.xml` |
| PLMN `43211` | confirmed | `evidence/raw/_api_net_current-plmn.xml` |
| Serving `Rat = 7` (LTE+NR NSA mode) | confirmed | `evidence/raw/_api_net_current-plmn.xml`, `docs/PHASE1_FINDINGS.md` |
| `nrProductEnable = 1` | confirmed feature flag | `evidence/raw/_api_global_module-switch.xml` |
| `oneKeyCheckEnable = 1` | confirmed feature flag | `evidence/raw/_api_global_module-switch.xml` |
| NR `n78` | **observed only** | prior session context recorded in `docs/PHASE1_FINDINGS.md`; no captured device capability response |
| LTE band capability | **not available** | `/api/net/lte-band-info`, `/config/network/bandfreqlist.xml`, and the net-mode endpoints were not captured/verified offline |
| Specific LTE/NR band combinations | **not available** | Rat 7 proves the mode only, never individual band compatibility |

The same feature-switch response also reports `bestsignal_enable=0`. That is a
product/UI toggle, not band capability evidence, and the offline engine does
not depend on it.

The default profile therefore contains exactly one slot:

```
NR n78  capability=observed
```

It contains **no confirmed slots and no invented LTE bands**. Consequently the
evidence profile produces no ranked candidates and no combinations. That is
the correct fail-closed result, not an engine failure.

Feature flags are never treated as band capability evidence. Rat 7 is never
treated as proof that every LTE/NR pairing is supported. `n78` is not promoted
to `confirmed`.

## 3. Data model and validation

All public data structures are frozen dataclasses and validate in
`__post_init__`. Invalid input raises `BestPairValidationError`.

### `BandSlot`

Fields: `rat`, `band`, `evidence_source`, `evidence_description`, `capability`.

- RAT must be `LTE` or `NR`.
- LTE bands use `B<number>` (1-99); NR bands use `n<number>` (1-999).
- Identifiers are normalized (`lte`/`b3` -> `LTE`/`B3`; `NR`/`N78` -> `NR`/`n78`).
- `capability` is exactly `confirmed` or `observed`.
- Evidence source and description must be non-empty.
- Only `confirmed` slots are eligible for ranking. `observed` slots are
  retained for transparent exclusion reporting.

### `DeviceBandProfile`

Fields: `device_name`, `slots`, `plmn`, `rat_mode`, `notes`.

- Device name must be non-empty.
- PLMN must be 5-6 digits when present.
- `rat_mode` must be an integer 0-255 when present.
- Duplicate `(rat, band)` slots are rejected.
- `confirmed_slots` and `observed_slots` expose the split explicitly.

### `SignalSnapshot`

Fields: `rsrp`, `rsrq`, `sinr`, `rssi`; each is `float | None`.

| Metric | Accepted range |
|---|---|
| RSRP | -140 to -40 |
| RSRQ | -20 to -1 |
| SINR | -20 to 30 |
| RSSI | -110 to -10 |

Booleans, strings, NaN, infinities, and out-of-range values are rejected.
`None` means the metric was not measured.

### `ScoringWeights`

Four non-negative finite weights whose sum must be 1 within `1e-9`.
Default:

```
RSRP 0.55, RSRQ 0.20, SINR 0.20, RSSI 0.05
```

### `CandidateFilter`

Fields: `required_metrics`, `min_coverage`.

- `required_metrics` must be non-empty, unique, and **must include `rsrp`**.
- `min_coverage` is the minimum fraction of total weight that must be measured
  (0..1); default `0.0`.

## 4. Normalization and candidate scoring

Each available metric is normalized linearly:

```
normalized = (value - low) / (high - low)
```

The candidate score is:

```
score = 100 * sum(weight[m] * normalized[m] for measured metrics only)
coverage = sum(weight[m] for measured metrics only)
```

Missing metrics contribute **zero**. Their weights are **not** redistributed.
For example, with the default weights, a candidate with perfect RSRP and no
other metric scores `55.00`, not `100.00`. A candidate with minimum RSRP and
perfect RSSI receives only the `5.00` RSSI contribution; the RSRP weight is
not redistributed.

Every `CandidateScore` carries a component breakdown with raw value, normalized
value, weight, contribution points, and availability. Its `metrics_available`
and `metrics_missing` tuple properties make partial measurements explicit.

Candidates are excluded with an explicit reason when:

- the profile has no evidence for the RAT/band;
- the profile has only `observed` evidence;
- a required metric (always including RSRP) is missing;
- weighted metric coverage is below `CandidateFilter.min_coverage`.

## 5. Ranking

`rank_candidates()` ranks only confirmed, sufficiently measured candidates.

- Default `top_per_rat = 3`; any positive integer is accepted.
- Ranking is sorted by descending score, then RAT (`LTE` before `NR`), then band
  number.
- At most `top_per_rat` candidates are retained per RAT.
- Excluded candidates are returned separately with reasons.

Ranking is signal-only and deterministic. It does not consider throughput,
load, interference, operator policy, or device settings.

## 6. LTE anchor + NR secondary combinations

Only this initial model is implemented:

```
LTE anchor + NR secondary
```

Combination generation requires all of the following:

1. `profile.rat_mode == 7` (the known LTE+NR NSA mode);
2. at least one eligible confirmed LTE candidate;
3. at least one eligible confirmed NR candidate;
4. each band slot is confirmed in the profile.

Rat 7 gates the **mode**, but individual band evidence still gates each slot.
No same-RAT carrier-aggregation combination is generated.

Pair scoring is deliberately stricter than averaging two candidate scores:

```
component[m] = weight[m] * (normalized_lte[m] + normalized_nr[m]) / 2 * 100
              only when BOTH members measured metric m
              otherwise 0

pair_score = sum(component[m])
pair_coverage = sum(weight[m] for metrics measured by BOTH members)
```

Thus a metric measured on only one member never inflates the pair score. A pair
with only RSRP measured on both sides has coverage `0.55` and cannot score
above `55.00` under the default weights.

With the evidence profile, no NR slot is confirmed and no LTE slot exists, so
the combination result is empty with explicit reasons.

## 7. Demo

All signal measurements in the demo are **synthetic fixtures, not modem
readings**. The demo performs no modem/network I/O.

```powershell
.\.venv\Scripts\python.exe tools\bestpair_demo.py
```

Useful variants:

```powershell
# Only the repository-evidence scenario
.\.venv\Scripts\python.exe tools\bestpair_demo.py --evidence-only

# Change the per-RAT retention limit
.\.venv\Scripts\python.exe tools\bestpair_demo.py --top-per-rat 2
```

The default output has two clearly separated scenarios:

1. **Repository evidence profile** - shows the confirmed/observed split, the
   observed-only n78 exclusion, empty ranking, and empty combinations with
   reasons.
2. **Illustrative synthetic profile** - uses hypothetical confirmed bands and
   synthetic measurements only to demonstrate ranking, component breakdown,
   pairing rules, and output formatting. It is explicitly labeled as not
   evidence and not a claim about the real H158-381.

Representative evidence-profile output:

```
Confirmed eligible slots: none
Observed but not eligible: NR n78

Ranking (top 3 per RAT, RSRP required):
  No eligible confirmed candidates. Ranking is empty by design.

Excluded candidates:
  NR n78  -> NR n78 has only observed evidence; confirmed capability is required for ranking

Combinations (LTE anchor + NR secondary):
  No combinations generated.
```

## 8. Tests and verification

Focused Phase 8 run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_bestpair.py -q
```

Result: **61 passed** (parameterized cases included).

Full suite, run once after the implementation:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Result: **187 passed in 0.49s, exit 0**.

The pre-Phase-8 baseline was 126 passing tests. Phase 8 adds 61 focused cases.
No existing test or production module was changed to make the suite pass.

The focused tests cover:

- RAT/band identity and capability validation;
- metric boundary and malformed-value rejection;
- weight and filter constraints;
- normalization endpoints and midpoint;
- missing-metric non-redistribution;
- explicit exclusion reasons;
- `top_per_rat` behavior and deterministic ordering;
- Rat 7 gating, confirmed-slot requirements, LTE-by-NR-only generation;
- both-members-measured pair scoring;
- a source check that the engine imports no network/modem modules.

## 9. Safety and limitations

- Strictly offline: no modem connection, HTTP request, authentication,
  credential collection, JavaScript download/execution, scanning, locking,
  reconnect, reboot, or configuration change.
- No commit or push was made.
- Phase 8 is a signal-only ranking engine. It does not validate live modem
  behavior and does not prove any real band capability.
- The default profile cannot rank or pair bands because the repository lacks
  confirmed band capability evidence. This is intentional.
- The illustrative demo bands (B3, B7, B20, n41) are synthetic and must never
  be cited as H158-381 capabilities.
- No carrier-aggregation model, no live measurement ingestion, and no
  persistence are implemented in Phase 8.

## 10. Phase boundary

Phase 8 stops here. Phase 9 (device capability profile and evidence extraction)
and Phase 10 (offline data ingestion workflow) are not implemented or started.

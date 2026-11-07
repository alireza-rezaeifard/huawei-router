"""Offline Best Pair engine for the Huawei H158-381.

This module is deliberately pure Python: it performs no modem I/O, imports no
HTTP or socket machinery, and never executes JavaScript. Callers supply a
device band profile and already-collected signal snapshots.

Evidence policy
---------------
A band is eligible for ranking only when its :class:`BandSlot` is marked
``confirmed``. ``observed`` evidence is retained for explanation and reporting
but is never promoted to a supported capability. Feature flags and the serving
RAT mode (Rat 7 = LTE+NR NSA) are evidence about the device mode only; they do
not prove that any specific LTE or NR band is supported.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Literal

CapabilityStatus = Literal["confirmed", "observed"]
Rat = Literal["LTE", "NR"]
MetricName = Literal["rsrp", "rsrq", "sinr", "rssi"]

METRIC_NAMES: tuple[MetricName, ...] = ("rsrp", "rsrq", "sinr", "rssi")

# Documented metric ranges. Values outside these bounds are malformed input.
METRIC_RANGES: dict[str, tuple[float, float]] = {
    "rsrp": (-140.0, -40.0),
    "rsrq": (-20.0, -1.0),
    "sinr": (-20.0, 30.0),
    "rssi": (-110.0, -10.0),
}

_RAT_ORDER: dict[str, int] = {"LTE": 0, "NR": 1}
_LTE_BAND_RE = re.compile(r"^[Bb](\d{1,3})$")
_NR_BAND_RE = re.compile(r"^[Nn](\d{1,3})$")
_PLMN_RE = re.compile(r"^\d{5,6}$")
_COMBINATION_MODEL = "LTE anchor + NR secondary"
_NSA_RAT_MODE = 7


class BestPairValidationError(ValueError):
    """Raised when Best Pair input fails closed validation."""


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _normalize_rat_band(rat: str, band: str) -> tuple[str, str]:
    if not isinstance(rat, str):
        raise BestPairValidationError("RAT must be a string")
    rat_normalized = rat.strip().upper()
    if rat_normalized not in _RAT_ORDER:
        raise BestPairValidationError(
            f"unsupported RAT {rat!r}; expected one of {tuple(_RAT_ORDER)}"
        )

    if not isinstance(band, str):
        raise BestPairValidationError("band must be a string")
    band_text = band.strip()

    if rat_normalized == "LTE":
        match = _LTE_BAND_RE.fullmatch(band_text)
        if match is None:
            raise BestPairValidationError(
                f"invalid LTE band {band!r}; expected B<number>"
            )
        number = int(match.group(1))
        if not 1 <= number <= 99:
            raise BestPairValidationError(f"LTE band out of range: {band!r}")
        return "LTE", f"B{number}"

    match = _NR_BAND_RE.fullmatch(band_text)
    if match is None:
        raise BestPairValidationError(f"invalid NR band {band!r}; expected n<number>")
    number = int(match.group(1))
    if not 1 <= number <= 999:
        raise BestPairValidationError(f"NR band out of range: {band!r}")
    return "NR", f"n{number}"


def _validate_metric_value(metric: str, value: object) -> float:
    if metric not in METRIC_RANGES:
        raise BestPairValidationError(f"unknown signal metric {metric!r}")
    if not _is_number(value):
        raise BestPairValidationError(
            f"{metric} must be a finite number or None, got {type(value).__name__}"
        )
    number = float(value)
    if not math.isfinite(number):
        raise BestPairValidationError(f"{metric} must be finite")
    low, high = METRIC_RANGES[metric]
    if not low <= number <= high:
        raise BestPairValidationError(
            f"{metric}={number} outside documented range [{low}, {high}]"
        )
    return number


def normalize_metric(metric: str, value: float) -> float:
    """Normalize one documented metric to the inclusive 0..1 scale."""
    number = _validate_metric_value(metric, value)
    low, high = METRIC_RANGES[metric]
    return (number - low) / (high - low)


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _clamp_score(value: float) -> float:
    return min(100.0, max(0.0, value))


@dataclass(frozen=True)
class BandSlot:
    """One RAT/band capability with its evidence provenance."""

    rat: str
    band: str
    evidence_source: str
    evidence_description: str
    capability: CapabilityStatus

    def __post_init__(self) -> None:
        rat, band = _normalize_rat_band(self.rat, self.band)
        object.__setattr__(self, "rat", rat)
        object.__setattr__(self, "band", band)

        for name in ("evidence_source", "evidence_description"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise BestPairValidationError(f"{name} must be non-empty")
            object.__setattr__(self, name, value.strip())

        if not isinstance(self.capability, str):
            raise BestPairValidationError("capability must be 'confirmed' or 'observed'")
        capability = self.capability.strip().lower()
        if capability not in ("confirmed", "observed"):
            raise BestPairValidationError(
                "capability must be 'confirmed' or 'observed'"
            )
        object.__setattr__(self, "capability", capability)

    @property
    def confirmed(self) -> bool:
        return self.capability == "confirmed"


@dataclass(frozen=True)
class DeviceBandProfile:
    """Device identity plus every band slot with its evidence status."""

    device_name: str
    slots: tuple[BandSlot, ...] = ()
    plmn: str | None = None
    rat_mode: int | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.device_name, str) or not self.device_name.strip():
            raise BestPairValidationError("device_name must be non-empty")
        object.__setattr__(self, "device_name", self.device_name.strip())

        if self.plmn is not None:
            if not isinstance(self.plmn, str) or not _PLMN_RE.fullmatch(self.plmn):
                raise BestPairValidationError("plmn must be 5-6 digits")
        if self.rat_mode is not None:
            if (
                isinstance(self.rat_mode, bool)
                or not isinstance(self.rat_mode, int)
                or not 0 <= self.rat_mode <= 255
            ):
                raise BestPairValidationError("rat_mode must be an integer 0..255")
        if not isinstance(self.notes, str):
            raise BestPairValidationError("notes must be a string")

        slots = tuple(self.slots)
        seen: set[tuple[str, str]] = set()
        for slot in slots:
            if not isinstance(slot, BandSlot):
                raise BestPairValidationError("slots must contain BandSlot values")
            key = (slot.rat, slot.band)
            if key in seen:
                raise BestPairValidationError(
                    f"duplicate band slot {slot.rat} {slot.band}"
                )
            seen.add(key)
        object.__setattr__(self, "slots", slots)

    @property
    def confirmed_slots(self) -> tuple[BandSlot, ...]:
        return tuple(slot for slot in self.slots if slot.confirmed)

    @property
    def observed_slots(self) -> tuple[BandSlot, ...]:
        return tuple(slot for slot in self.slots if not slot.confirmed)

    def slot_for(self, rat: str, band: str) -> BandSlot | None:
        rat_normalized, band_normalized = _normalize_rat_band(rat, band)
        for slot in self.slots:
            if slot.rat == rat_normalized and slot.band == band_normalized:
                return slot
        return None

    def supports(
        self, rat: str, band: str, *, require_confirmed: bool = True
    ) -> bool:
        slot = self.slot_for(rat, band)
        if slot is None:
            return False
        return slot.confirmed if require_confirmed else True


@dataclass(frozen=True)
class SignalSnapshot:
    """Measured signal metrics; ``None`` means the metric is unavailable."""

    rsrp: float | None = None
    rsrq: float | None = None
    sinr: float | None = None
    rssi: float | None = None

    def __post_init__(self) -> None:
        for metric in METRIC_NAMES:
            value = getattr(self, metric)
            if value is None:
                continue
            object.__setattr__(
                self, metric, _validate_metric_value(metric, value)
            )

    @property
    def available_metrics(self) -> tuple[MetricName, ...]:
        return tuple(
            metric for metric in METRIC_NAMES if getattr(self, metric) is not None
        )


@dataclass(frozen=True)
class BandCandidate:
    """A RAT/band candidate carrying one available signal snapshot."""

    rat: str
    band: str
    signal: SignalSnapshot
    label: str = ""

    def __post_init__(self) -> None:
        rat, band = _normalize_rat_band(self.rat, self.band)
        object.__setattr__(self, "rat", rat)
        object.__setattr__(self, "band", band)
        if not isinstance(self.signal, SignalSnapshot):
            raise BestPairValidationError("signal must be a SignalSnapshot")
        if not isinstance(self.label, str):
            raise BestPairValidationError("label must be a string")


@dataclass(frozen=True)
class ScoringWeights:
    """Configurable weights; the four values must sum to exactly 1."""

    rsrp: float = 0.55
    rsrq: float = 0.20
    sinr: float = 0.20
    rssi: float = 0.05

    def __post_init__(self) -> None:
        total = 0.0
        for metric in METRIC_NAMES:
            value = getattr(self, metric)
            if not _is_number(value):
                raise BestPairValidationError(f"{metric} weight must be a number")
            number = float(value)
            if not math.isfinite(number) or number < 0:
                raise BestPairValidationError(
                    f"{metric} weight must be finite and non-negative"
                )
            object.__setattr__(self, metric, number)
            total += number
        if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-9):
            raise BestPairValidationError(
                f"scoring weights must sum to 1.0 (got {total!r})"
            )


@dataclass(frozen=True)
class CandidateFilter:
    """Explicit minimum data requirements for ranking."""

    required_metrics: tuple[MetricName, ...] = ("rsrp",)
    min_coverage: float = 0.0

    def __post_init__(self) -> None:
        required = tuple(self.required_metrics)
        if not required:
            raise BestPairValidationError("required_metrics must not be empty")
        if len(set(required)) != len(required):
            raise BestPairValidationError("required_metrics contains duplicates")
        for metric in required:
            if metric not in METRIC_NAMES:
                raise BestPairValidationError(f"unknown required metric {metric!r}")
        if "rsrp" not in required:
            raise BestPairValidationError(
                "rsrp is mandatory: no candidate may be ranked without RSRP"
            )
        if not _is_number(self.min_coverage):
            raise BestPairValidationError("min_coverage must be a number")
        coverage = float(self.min_coverage)
        if not math.isfinite(coverage) or not 0.0 <= coverage <= 1.0:
            raise BestPairValidationError("min_coverage must be within 0..1")
        object.__setattr__(self, "required_metrics", required)
        object.__setattr__(self, "min_coverage", coverage)

    def missing_required(self, snapshot: SignalSnapshot) -> tuple[str, ...]:
        return tuple(
            metric
            for metric in self.required_metrics
            if getattr(snapshot, metric) is None
        )


DEFAULT_WEIGHTS = ScoringWeights()
DEFAULT_FILTER = CandidateFilter()


@dataclass(frozen=True)
class ScoreComponent:
    metric: str
    raw_value: float | None
    normalized: float | None
    weight: float
    contribution_points: float
    available: bool


@dataclass(frozen=True)
class CandidateScore:
    candidate: BandCandidate
    score: float
    coverage: float
    components: tuple[ScoreComponent, ...]

    @property
    def metrics_available(self) -> tuple[str, ...]:
        return tuple(c.metric for c in self.components if c.available)

    @property
    def metrics_missing(self) -> tuple[str, ...]:
        return tuple(c.metric for c in self.components if not c.available)


@dataclass(frozen=True)
class CandidateExclusion:
    candidate: BandCandidate
    reason: str


@dataclass(frozen=True)
class RankingResult:
    ranked: tuple[CandidateScore, ...]
    excluded: tuple[CandidateExclusion, ...]
    top_per_rat: int

    def candidates_for(self, rat: str) -> tuple[CandidateScore, ...]:
        rat_normalized = rat.strip().upper()
        return tuple(
            score for score in self.ranked if score.candidate.rat == rat_normalized
        )


@dataclass(frozen=True)
class CombinationComponent:
    metric: str
    lte_value: float | None
    nr_value: float | None
    normalized_lte: float | None
    normalized_nr: float | None
    weight: float
    contribution_points: float
    available: bool


@dataclass(frozen=True)
class CombinationScore:
    lte: CandidateScore
    nr: CandidateScore
    score: float
    coverage: float
    components: tuple[CombinationComponent, ...]

    @property
    def metrics_available(self) -> tuple[str, ...]:
        return tuple(c.metric for c in self.components if c.available)

    @property
    def metrics_missing(self) -> tuple[str, ...]:
        return tuple(c.metric for c in self.components if not c.available)


@dataclass(frozen=True)
class CombinationResult:
    combinations: tuple[CombinationScore, ...]
    skipped_reasons: tuple[str, ...] = ()
    rat_mode: int | None = None
    model: str = _COMBINATION_MODEL


@dataclass(frozen=True)
class BestPairAnalysis:
    profile: DeviceBandProfile
    ranking: RankingResult
    combinations: CombinationResult


def _band_sort_key(band: str) -> tuple[int, str]:
    return int(re.sub(r"\D", "", band)), band


def _score_sort_key(score: CandidateScore) -> tuple[float, int, int, str]:
    candidate = score.candidate
    band_number, band = _band_sort_key(candidate.band)
    return (-score.score, _RAT_ORDER[candidate.rat], band_number, band)


def evaluate_candidate(
    profile: DeviceBandProfile,
    candidate: BandCandidate,
    weights: ScoringWeights = DEFAULT_WEIGHTS,
    candidate_filter: CandidateFilter = DEFAULT_FILTER,
) -> CandidateScore | CandidateExclusion:
    """Evaluate one candidate, or return an explicit exclusion reason."""
    if not isinstance(profile, DeviceBandProfile):
        raise TypeError("profile must be a DeviceBandProfile")
    if not isinstance(candidate, BandCandidate):
        raise TypeError("candidate must be a BandCandidate")
    if not isinstance(weights, ScoringWeights):
        raise TypeError("weights must be a ScoringWeights")
    if not isinstance(candidate_filter, CandidateFilter):
        raise TypeError("candidate_filter must be a CandidateFilter")

    slot = profile.slot_for(candidate.rat, candidate.band)
    if slot is None:
        return CandidateExclusion(
            candidate,
            f"no profile evidence for {candidate.rat} {candidate.band}",
        )
    if not slot.confirmed:
        return CandidateExclusion(
            candidate,
            (
                f"{candidate.rat} {candidate.band} has only observed evidence; "
                "confirmed capability is required for ranking"
            ),
        )

    components: list[ScoreComponent] = []
    score = 0.0
    coverage = 0.0
    for metric in METRIC_NAMES:
        weight = float(getattr(weights, metric))
        raw_value = getattr(candidate.signal, metric)
        if raw_value is None:
            components.append(
                ScoreComponent(metric, None, None, weight, 0.0, False)
            )
            continue
        normalized = normalize_metric(metric, raw_value)
        contribution = weight * normalized * 100.0
        score += contribution
        coverage += weight
        components.append(
            ScoreComponent(
                metric, raw_value, normalized, weight, contribution, True
            )
        )

    missing = candidate_filter.missing_required(candidate.signal)
    if missing:
        return CandidateExclusion(
            candidate,
            "missing required signal metric(s): " + ", ".join(missing),
        )

    coverage = _clamp01(coverage)
    if coverage + 1e-12 < candidate_filter.min_coverage:
        return CandidateExclusion(
            candidate,
            (
                f"metric coverage {coverage:.3f} is below required minimum "
                f"{candidate_filter.min_coverage:.3f}"
            ),
        )

    return CandidateScore(
        candidate=candidate,
        score=_clamp_score(score),
        coverage=coverage,
        components=tuple(components),
    )


def rank_candidates(
    profile: DeviceBandProfile,
    candidates: tuple[BandCandidate, ...] | list[BandCandidate],
    weights: ScoringWeights = DEFAULT_WEIGHTS,
    candidate_filter: CandidateFilter = DEFAULT_FILTER,
    top_per_rat: int = 3,
) -> RankingResult:
    """Rank confirmed candidates, keeping at most ``top_per_rat`` per RAT."""
    if (
        isinstance(top_per_rat, bool)
        or not isinstance(top_per_rat, int)
        or top_per_rat <= 0
    ):
        raise BestPairValidationError("top_per_rat must be a positive integer")

    candidates_tuple = tuple(candidates)
    seen: set[tuple[str, str]] = set()
    for candidate in candidates_tuple:
        if not isinstance(candidate, BandCandidate):
            raise TypeError("candidates must contain BandCandidate values")
        key = (candidate.rat, candidate.band)
        if key in seen:
            raise BestPairValidationError(
                f"duplicate candidate {candidate.rat} {candidate.band}"
            )
        seen.add(key)

    eligible: list[CandidateScore] = []
    excluded: list[CandidateExclusion] = []
    for candidate in candidates_tuple:
        result = evaluate_candidate(profile, candidate, weights, candidate_filter)
        if isinstance(result, CandidateScore):
            eligible.append(result)
        else:
            excluded.append(result)

    eligible.sort(key=_score_sort_key)
    selected: list[CandidateScore] = []
    per_rat: dict[str, int] = {}
    for score in eligible:
        rat = score.candidate.rat
        if per_rat.get(rat, 0) >= top_per_rat:
            continue
        per_rat[rat] = per_rat.get(rat, 0) + 1
        selected.append(score)

    selected.sort(key=_score_sort_key)
    excluded.sort(
        key=lambda item: (
            _RAT_ORDER[item.candidate.rat],
            *_band_sort_key(item.candidate.band),
        )
    )
    return RankingResult(
        ranked=tuple(selected),
        excluded=tuple(excluded),
        top_per_rat=top_per_rat,
    )


def score_combination(
    lte: CandidateScore,
    nr: CandidateScore,
    weights: ScoringWeights = DEFAULT_WEIGHTS,
) -> CombinationScore:
    """Score an LTE anchor + NR secondary pair.

    A metric contributes only when BOTH members measured it. Missing metrics
    are never redistributed to the remaining weights.
    """
    if not isinstance(lte, CandidateScore) or lte.candidate.rat != "LTE":
        raise BestPairValidationError("lte must be a ranked LTE CandidateScore")
    if not isinstance(nr, CandidateScore) or nr.candidate.rat != "NR":
        raise BestPairValidationError("nr must be a ranked NR CandidateScore")

    components: list[CombinationComponent] = []
    score = 0.0
    coverage = 0.0
    for metric in METRIC_NAMES:
        weight = float(getattr(weights, metric))
        lte_value = getattr(lte.candidate.signal, metric)
        nr_value = getattr(nr.candidate.signal, metric)
        if lte_value is None or nr_value is None:
            components.append(
                CombinationComponent(
                    metric,
                    lte_value,
                    nr_value,
                    None,
                    None,
                    weight,
                    0.0,
                    False,
                )
            )
            continue
        normalized_lte = normalize_metric(metric, lte_value)
        normalized_nr = normalize_metric(metric, nr_value)
        normalized_pair = (normalized_lte + normalized_nr) / 2.0
        contribution = weight * normalized_pair * 100.0
        score += contribution
        coverage += weight
        components.append(
            CombinationComponent(
                metric,
                lte_value,
                nr_value,
                normalized_lte,
                normalized_nr,
                weight,
                contribution,
                True,
            )
        )

    return CombinationScore(
        lte=lte,
        nr=nr,
        score=_clamp_score(score),
        coverage=_clamp01(coverage),
        components=tuple(components),
    )


def generate_combinations(
    profile: DeviceBandProfile,
    ranking: RankingResult,
    weights: ScoringWeights = DEFAULT_WEIGHTS,
) -> CombinationResult:
    """Generate LTE-anchor + NR-secondary pairs only where evidence permits."""
    if not isinstance(profile, DeviceBandProfile):
        raise TypeError("profile must be a DeviceBandProfile")
    if not isinstance(ranking, RankingResult):
        raise TypeError("ranking must be a RankingResult")
    if not isinstance(weights, ScoringWeights):
        raise TypeError("weights must be a ScoringWeights")

    skipped: list[str] = []
    if profile.rat_mode != _NSA_RAT_MODE:
        skipped.append(
            "combination model requires Rat 7 (LTE+NR NSA); "
            f"profile rat_mode is {profile.rat_mode!r}"
        )
        return CombinationResult(
            combinations=(),
            skipped_reasons=tuple(skipped),
            rat_mode=profile.rat_mode,
        )

    lte_candidates = ranking.candidates_for("LTE")
    nr_candidates = ranking.candidates_for("NR")
    if not lte_candidates:
        skipped.append(
            "no eligible confirmed LTE anchor candidate was ranked"
        )
    if not nr_candidates:
        skipped.append(
            "no eligible confirmed NR secondary candidate was ranked"
        )
    if skipped:
        return CombinationResult(
            combinations=(),
            skipped_reasons=tuple(skipped),
            rat_mode=profile.rat_mode,
        )

    combinations: list[CombinationScore] = []
    for lte in lte_candidates:
        if not profile.supports(
            lte.candidate.rat, lte.candidate.band, require_confirmed=True
        ):
            skipped.append(
                f"LTE {lte.candidate.band} is not confirmed in the profile"
            )
            continue
        for nr in nr_candidates:
            if not profile.supports(
                nr.candidate.rat, nr.candidate.band, require_confirmed=True
            ):
                skipped.append(
                    f"NR {nr.candidate.band} is not confirmed in the profile"
                )
                continue
            combinations.append(score_combination(lte, nr, weights))

    combinations.sort(
        key=lambda item: (
            -item.score,
            *_band_sort_key(item.lte.candidate.band),
            *_band_sort_key(item.nr.candidate.band),
        )
    )
    return CombinationResult(
        combinations=tuple(combinations),
        skipped_reasons=tuple(dict.fromkeys(skipped)),
        rat_mode=profile.rat_mode,
    )


def analyze(
    profile: DeviceBandProfile,
    candidates: tuple[BandCandidate, ...] | list[BandCandidate],
    weights: ScoringWeights = DEFAULT_WEIGHTS,
    candidate_filter: CandidateFilter = DEFAULT_FILTER,
    top_per_rat: int = 3,
) -> BestPairAnalysis:
    """Run ranking and combination generation for one offline snapshot set."""
    ranking = rank_candidates(
        profile,
        candidates,
        weights=weights,
        candidate_filter=candidate_filter,
        top_per_rat=top_per_rat,
    )
    combinations = generate_combinations(profile, ranking, weights=weights)
    return BestPairAnalysis(
        profile=profile,
        ranking=ranking,
        combinations=combinations,
    )


def evidence_minimal_profile() -> DeviceBandProfile:
    """Conservative profile built only from evidence present in this repository.

    - Device identity and PLMN: Phase 1 findings / captured XML.
    - Rat 7: LTE+NR NSA serving mode (not a band-capability claim).
    - nrProductEnable=1: NR product feature flag (not a band claim).
    - NR n78: observed in prior session context, never confirmed by a captured
      device capability response.
    - LTE bands: no verified capability endpoint/schema or captured response,
      so no LTE band is invented.
    """
    return DeviceBandProfile(
        device_name="Huawei H158-381",
        plmn="43211",
        rat_mode=7,
        slots=(
            BandSlot(
                rat="NR",
                band="n78",
                evidence_source=(
                    "prior discovery context (docs/PHASE1_FINDINGS.md); "
                    "not a captured device capability response"
                ),
                evidence_description=(
                    "Previously reported as observed only; no LTE/NR band "
                    "capability XML is available in the offline evidence set."
                ),
                capability="observed",
            ),
        ),
        notes=(
            "Rat 7 proves LTE+NR NSA mode, not individual band support. "
            "nrProductEnable=1 and oneKeyCheckEnable=1 are feature flags, not "
            "band capabilities. No confirmed LTE or NR band is available, so "
            "the evidence profile cannot produce ranked candidates or pairs."
        ),
    )

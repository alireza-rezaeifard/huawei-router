from __future__ import annotations

import math
from pathlib import Path

import pytest

from huawei_tower.bestpair import (
    DEFAULT_FILTER,
    DEFAULT_WEIGHTS,
    EVIDENCE_SOURCES,
    BandCandidate,
    BandSlot,
    BestPairValidationError,
    CandidateExclusion,
    CandidateFilter,
    CandidateScore,
    DeviceBandProfile,
    DeviceEvidence,
    EvidenceContradictionError,
    EvidenceExtractionError,
    EvidenceFact,
    EvidenceValidationError,
    ScoringWeights,
    SignalSnapshot,
    analyze,
    build_profile_from_evidence,
    collect_device_facts,
    evaluate_candidate,
    evidence_minimal_profile,
    generate_combinations,
    normalize_metric,
    rank_candidates,
    repository_device_profile,
    score_combination,
)
from huawei_tower.bestpair import engine as engine_module
from huawei_tower.bestpair import evidence as evidence_module


def slot(rat: str, band: str, capability: str = "confirmed") -> BandSlot:
    return BandSlot(
        rat=rat,
        band=band,
        evidence_source="test-only capability evidence",
        evidence_description="Synthetic evidence constructed for unit tests.",
        capability=capability,  # type: ignore[arg-type]
    )


def profile(*slots: BandSlot, rat_mode: int | None = 7) -> DeviceBandProfile:
    return DeviceBandProfile(
        device_name="Test Device",
        slots=tuple(slots),
        rat_mode=rat_mode,
    )


def candidate(
    rat: str,
    band: str,
    *,
    rsrp: float | None = -90.0,
    rsrq: float | None = -10.0,
    sinr: float | None = 10.0,
    rssi: float | None = -60.0,
) -> BandCandidate:
    return BandCandidate(
        rat=rat,
        band=band,
        signal=SignalSnapshot(rsrp=rsrp, rsrq=rsrq, sinr=sinr, rssi=rssi),
    )


# ---------------------------------------------------------------------------
# Data validation
# ---------------------------------------------------------------------------


def test_band_slot_normalizes_valid_identifiers():
    lte = slot("lte", "b3")
    nr = BandSlot("NR", "N78", "source", "description", "CONFIRMED")  # type: ignore[arg-type]

    assert (lte.rat, lte.band, lte.capability) == ("LTE", "B3", "confirmed")
    assert (nr.rat, nr.band, nr.capability) == ("NR", "n78", "confirmed")


@pytest.mark.parametrize(
    ("rat", "band"),
    [
        ("LTE", "n78"),
        ("NR", "B3"),
        ("WCDMA", "B1"),
        ("LTE", "3"),
        ("NR", "78"),
        ("LTE", "B100"),
    ],
)
def test_band_slot_rejects_mismatched_or_invalid_identity(rat, band):
    with pytest.raises(BestPairValidationError):
        slot(rat, band)


@pytest.mark.parametrize("capability", ["verified", "", "CONFIRMED?"])
def test_band_slot_rejects_unsupported_capability_status(capability):
    with pytest.raises(BestPairValidationError):
        slot("LTE", "B3", capability)


def test_band_slot_requires_evidence_provenance():
    with pytest.raises(BestPairValidationError):
        BandSlot("LTE", "B3", " ", "description", "confirmed")
    with pytest.raises(BestPairValidationError):
        BandSlot("LTE", "B3", "source", "", "confirmed")


def test_device_profile_rejects_duplicates_and_bad_metadata():
    with pytest.raises(BestPairValidationError):
        profile(slot("LTE", "B3"), slot("LTE", "b3"))
    with pytest.raises(BestPairValidationError):
        DeviceBandProfile("Test", plmn="1234")
    with pytest.raises(BestPairValidationError):
        DeviceBandProfile("Test", rat_mode=True)  # type: ignore[arg-type]


def test_profile_support_requires_confirmed_evidence():
    observed = slot("NR", "n78", "observed")
    test_profile = profile(observed)

    assert test_profile.supports("NR", "n78", require_confirmed=False) is True
    assert test_profile.supports("NR", "n78", require_confirmed=True) is False
    assert test_profile.supports("NR", "n41") is False
    assert test_profile.confirmed_slots == ()
    assert test_profile.observed_slots == (observed,)


def test_evidence_minimal_profile_is_conservative():
    test_profile = evidence_minimal_profile()

    assert test_profile.device_name == "Huawei H158-381"
    assert test_profile.plmn == "43211"
    assert test_profile.rat_mode == 7
    assert test_profile.confirmed_slots == ()
    assert [
        (item.rat, item.band, item.capability) for item in test_profile.slots
    ] == [("NR", "n78", "observed")]
    assert not any(item.rat == "LTE" for item in test_profile.slots)
    assert "Rat 7 proves LTE+NR NSA mode" in test_profile.notes


@pytest.mark.parametrize(
    ("metric", "value"),
    [
        ("rsrp", -140),
        ("rsrp", -40),
        ("rsrq", -20),
        ("rsrq", -1),
        ("sinr", -20),
        ("sinr", 30),
        ("rssi", -110),
        ("rssi", -10),
    ],
)
def test_signal_snapshot_accepts_documented_boundaries(metric, value):
    snapshot = SignalSnapshot(**{metric: value})
    assert getattr(snapshot, metric) == float(value)


@pytest.mark.parametrize(
    ("metric", "value"),
    [
        ("rsrp", -140.1),
        ("rsrp", -39.9),
        ("rsrq", -20.1),
        ("rsrq", -0.9),
        ("sinr", -20.1),
        ("sinr", 30.1),
        ("rssi", -110.1),
        ("rssi", -9.9),
    ],
)
def test_signal_snapshot_rejects_out_of_range_metrics(metric, value):
    with pytest.raises(BestPairValidationError):
        SignalSnapshot(**{metric: value})


@pytest.mark.parametrize("bad_value", [True, "1", math.nan, math.inf])
def test_signal_snapshot_rejects_malformed_values(bad_value):
    with pytest.raises(BestPairValidationError):
        SignalSnapshot(rsrp=bad_value)  # type: ignore[arg-type]


def test_scoring_weights_must_sum_to_one():
    assert ScoringWeights(rsrp=0.25, rsrq=0.25, sinr=0.25, rssi=0.25)
    for weights in (
        dict(rsrp=0.5, rsrq=0.2, sinr=0.2, rssi=0.2),
        dict(rsrp=0.5, rsrq=0.2, sinr=0.2, rssi=-0.1),
        dict(rsrp=1.0, rsrq=0.0, sinr=0.0, rssi=True),
        dict(rsrp=math.nan, rsrq=0.0, sinr=0.0, rssi=0.0),
    ):
        with pytest.raises(BestPairValidationError):
            ScoringWeights(**weights)  # type: ignore[arg-type]


def test_candidate_filter_requires_rsrp_and_valid_options():
    assert CandidateFilter().required_metrics == ("rsrp",)
    with pytest.raises(BestPairValidationError):
        CandidateFilter(required_metrics=("rsrq",))
    with pytest.raises(BestPairValidationError):
        CandidateFilter(required_metrics=("rsrp", "rsrp"))
    with pytest.raises(BestPairValidationError):
        CandidateFilter(required_metrics=("rsrp", "unknown"))  # type: ignore[arg-type]
    with pytest.raises(BestPairValidationError):
        CandidateFilter(min_coverage=1.1)


# ---------------------------------------------------------------------------
# Normalization and single-candidate scoring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("metric", "low", "high"),
    [
        ("rsrp", -140, -40),
        ("rsrq", -20, -1),
        ("sinr", -20, 30),
        ("rssi", -110, -10),
    ],
)
def test_normalize_metric_maps_endpoints_and_midpoint(metric, low, high):
    assert normalize_metric(metric, low) == 0.0
    assert normalize_metric(metric, high) == 1.0
    assert normalize_metric(metric, (low + high) / 2) == pytest.approx(0.5)


def test_normalize_metric_rejects_unknown_metric_and_bad_values():
    with pytest.raises(BestPairValidationError):
        normalize_metric("bogus", 0)
    with pytest.raises(BestPairValidationError):
        normalize_metric("rsrp", -200)


def test_perfect_metrics_score_100_with_full_coverage():
    result = evaluate_candidate(
        profile(slot("LTE", "B3")),
        candidate(
            "LTE",
            "B3",
            rsrp=-40,
            rsrq=-1,
            sinr=30,
            rssi=-10,
        ),
    )

    assert isinstance(result, CandidateScore)
    assert result.score == pytest.approx(100.0)
    assert result.coverage == pytest.approx(1.0)
    assert result.metrics_available == ("rsrp", "rsrq", "sinr", "rssi")
    assert result.metrics_missing == ()


def test_missing_metrics_are_not_redistributed():
    test_profile = profile(slot("LTE", "B3"))

    rsrp_only = evaluate_candidate(
        test_profile,
        candidate(
            "LTE",
            "B3",
            rsrp=-40,
            rsrq=None,
            sinr=None,
            rssi=None,
        ),
    )
    rssi_focus = evaluate_candidate(
        test_profile,
        candidate(
            "LTE",
            "B3",
            rsrp=-140,
            rsrq=None,
            sinr=None,
            rssi=-10,
        ),
    )

    assert isinstance(rsrp_only, CandidateScore)
    assert rsrp_only.score == pytest.approx(55.0)
    assert rsrp_only.coverage == pytest.approx(0.55)
    assert isinstance(rssi_focus, CandidateScore)
    assert rssi_focus.score == pytest.approx(5.0)
    assert rssi_focus.coverage == pytest.approx(0.60)


def test_component_breakdown_marks_missing_metrics_as_zero_contribution():
    result = evaluate_candidate(
        profile(slot("LTE", "B3")),
        candidate("LTE", "B3", rsrp=-90, rsrq=None, sinr=None, rssi=None),
    )

    assert isinstance(result, CandidateScore)
    components = {component.metric: component for component in result.components}
    assert components["rsrp"].available is True
    assert components["rsrp"].normalized == pytest.approx(0.5)
    assert components["rsrp"].contribution_points == pytest.approx(27.5)
    for metric in ("rsrq", "sinr", "rssi"):
        assert components[metric].available is False
        assert components[metric].normalized is None
        assert components[metric].contribution_points == 0.0


def test_filter_excludes_candidate_missing_required_rsrp():
    result = evaluate_candidate(
        profile(slot("LTE", "B3")),
        candidate("LTE", "B3", rsrp=None),
    )

    assert isinstance(result, CandidateExclusion)
    assert "missing required signal metric(s): rsrp" in result.reason


def test_filter_excludes_candidate_below_minimum_coverage():
    result = evaluate_candidate(
        profile(slot("LTE", "B3")),
        candidate("LTE", "B3", rsrp=-90, rsrq=None, sinr=None, rssi=None),
        candidate_filter=CandidateFilter(min_coverage=0.8),
    )

    assert isinstance(result, CandidateExclusion)
    assert "below required minimum" in result.reason


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


def test_ranking_excludes_bands_absent_from_profile():
    result = rank_candidates(profile(), [candidate("LTE", "B3")])

    assert result.ranked == ()
    assert "no profile evidence for LTE B3" in result.excluded[0].reason


def test_ranking_excludes_observed_only_bands():
    result = rank_candidates(
        evidence_minimal_profile(),
        [candidate("NR", "n78")],
    )

    assert result.ranked == ()
    assert "only observed evidence" in result.excluded[0].reason


def test_top_per_rat_defaults_to_three_and_is_configurable():
    lte_slots = tuple(slot("LTE", band) for band in ("B1", "B3", "B5", "B7", "B8"))
    candidates = [
        candidate("LTE", band, rsrp=-80 - index)
        for index, band in enumerate(("B1", "B3", "B5", "B7", "B8"))
    ]
    test_profile = profile(*lte_slots)

    default_result = rank_candidates(test_profile, candidates)
    custom_result = rank_candidates(test_profile, candidates, top_per_rat=2)

    assert default_result.top_per_rat == 3
    assert len(default_result.ranked) == 3
    assert len(custom_result.ranked) == 2
    with pytest.raises(BestPairValidationError):
        rank_candidates(test_profile, candidates, top_per_rat=0)
    with pytest.raises(BestPairValidationError):
        rank_candidates(test_profile, candidates, top_per_rat=True)  # type: ignore[arg-type]


def test_ranking_is_sorted_descending_and_deterministic():
    test_profile = profile(slot("LTE", "B3"), slot("LTE", "B7"))
    candidates = [
        candidate("LTE", "B3", rsrp=-100),
        candidate("LTE", "B7", rsrp=-80),
    ]

    first = rank_candidates(test_profile, candidates)
    second = rank_candidates(test_profile, candidates)

    assert [item.candidate.band for item in first.ranked] == ["B7", "B3"]
    assert [item.score for item in first.ranked] == [
        item.score for item in second.ranked
    ]
    assert all(0.0 <= item.score <= 100.0 for item in first.ranked)


def test_ranking_rejects_duplicate_candidates():
    with pytest.raises(BestPairValidationError):
        rank_candidates(
            profile(slot("LTE", "B3")),
            [candidate("LTE", "B3"), candidate("LTE", "b3")],
        )


# ---------------------------------------------------------------------------
# Combinations
# ---------------------------------------------------------------------------


def lte_nr_profile(*, rat_mode: int | None = 7) -> DeviceBandProfile:
    return profile(
        slot("LTE", "B3"),
        slot("LTE", "B7"),
        slot("NR", "n78"),
        slot("NR", "n41"),
        rat_mode=rat_mode,
    )


def test_no_combinations_without_rat_7_mode():
    test_profile = lte_nr_profile(rat_mode=6)
    ranking = rank_candidates(
        test_profile,
        [candidate("LTE", "B3"), candidate("NR", "n78")],
    )

    result = generate_combinations(test_profile, ranking)

    assert result.combinations == ()
    assert "requires Rat 7" in result.skipped_reasons[0]


def test_no_combinations_without_both_rats():
    test_profile = profile(slot("LTE", "B3"))
    ranking = rank_candidates(test_profile, [candidate("LTE", "B3")])

    result = generate_combinations(test_profile, ranking)

    assert result.combinations == ()
    assert any("NR secondary" in reason for reason in result.skipped_reasons)


def test_combination_requires_confirmed_nr_band():
    observed_profile = profile(
        slot("LTE", "B3"),
        slot("NR", "n78", "observed"),
    )
    ranking = rank_candidates(
        observed_profile,
        [candidate("LTE", "B3"), candidate("NR", "n78")],
    )

    result = generate_combinations(observed_profile, ranking)

    assert [item.candidate.band for item in ranking.ranked] == ["B3"]
    assert result.combinations == ()
    assert any("NR secondary" in reason for reason in result.skipped_reasons)


def test_combination_generation_is_lte_by_nr_only():
    test_profile = lte_nr_profile()
    candidates = [
        candidate("LTE", "B3"),
        candidate("LTE", "B7", rsrp=-100),
        candidate("NR", "n78"),
        candidate("NR", "n41", rsrp=-110),
    ]
    ranking = rank_candidates(test_profile, candidates)

    result = generate_combinations(test_profile, ranking)

    assert len(result.combinations) == 4
    assert all(item.lte.candidate.rat == "LTE" for item in result.combinations)
    assert all(item.nr.candidate.rat == "NR" for item in result.combinations)


def test_top_per_rat_limits_combination_candidates():
    test_profile = lte_nr_profile()
    candidates = [
        candidate("LTE", "B3"),
        candidate("LTE", "B7", rsrp=-100),
        candidate("NR", "n78"),
        candidate("NR", "n41", rsrp=-110),
    ]
    ranking = rank_candidates(test_profile, candidates, top_per_rat=1)

    result = generate_combinations(test_profile, ranking)

    assert len(result.combinations) == 1


def test_pair_metric_contributes_only_when_both_members_measure_it():
    test_profile = profile(slot("LTE", "B3"), slot("NR", "n78"))
    ranking = rank_candidates(
        test_profile,
        [
            candidate(
                "LTE",
                "B3",
                rsrp=-40,
                rsrq=None,
                sinr=None,
                rssi=None,
            ),
            candidate(
                "NR",
                "n78",
                rsrp=-140,
                rsrq=None,
                sinr=None,
                rssi=None,
            ),
        ],
    )

    result = generate_combinations(test_profile, ranking)

    assert len(result.combinations) == 1
    combination = result.combinations[0]
    assert combination.score == pytest.approx(27.5)
    assert combination.coverage == pytest.approx(0.55)
    assert combination.metrics_available == ("rsrp",)
    assert combination.metrics_missing == ("rsrq", "sinr", "rssi")


def test_pair_score_ignores_one_sided_metric_measurements():
    lte_score = evaluate_candidate(
        profile(slot("LTE", "B3")),
        candidate(
            "LTE",
            "B3",
            rsrp=-40,
            rsrq=-1,
            sinr=None,
            rssi=None,
        ),
    )
    nr_score = evaluate_candidate(
        profile(slot("NR", "n78")),
        candidate(
            "NR",
            "n78",
            rsrp=-40,
            rsrq=None,
            sinr=None,
            rssi=None,
        ),
    )
    assert isinstance(lte_score, CandidateScore)
    assert isinstance(nr_score, CandidateScore)

    combo = score_combination(lte_score, nr_score)

    assert combo.coverage == pytest.approx(0.55)
    components = {component.metric: component for component in combo.components}
    assert components["rsrq"].available is False
    assert components["rsrq"].contribution_points == 0.0
    assert combo.score == pytest.approx(55.0)


def test_combinations_are_sorted_by_score():
    test_profile = profile(slot("LTE", "B3"), slot("NR", "n78"), slot("NR", "n41"))
    ranking = rank_candidates(
        test_profile,
        [
            candidate("LTE", "B3", rsrp=-90),
            candidate("NR", "n78", rsrp=-40),
            candidate("NR", "n41", rsrp=-140),
        ],
    )

    result = generate_combinations(test_profile, ranking)

    assert [item.nr.candidate.band for item in result.combinations] == [
        "n78",
        "n41",
    ]
    assert result.combinations[0].score > result.combinations[1].score


def test_analyze_runs_ranking_and_combinations():
    test_profile = profile(slot("LTE", "B3"), slot("NR", "n78"))
    analysis = analyze(
        test_profile,
        [candidate("LTE", "B3"), candidate("NR", "n78")],
    )

    assert analysis.profile is test_profile
    assert len(analysis.ranking.ranked) == 2
    assert len(analysis.combinations.combinations) == 1


def test_engine_module_has_no_network_or_modem_io_imports():
    source = Path(engine_module.__file__).read_text(encoding="utf-8")

    for forbidden in (
        "import requests",
        "import socket",
        "from ..modem",
        "import urllib",
    ):
        assert forbidden not in source
    assert "DEFAULT_WEIGHTS" in source
    assert DEFAULT_FILTER.required_metrics == ("rsrp",)
    assert DEFAULT_WEIGHTS.rsrp == 0.55


# ---------------------------------------------------------------------------
# Phase 9 evidence extraction
# ---------------------------------------------------------------------------

_MINIMAL_MODULE_SWITCH = (
    "<response>"
    "<nrProductEnable>1</nrProductEnable>"
    "<oneKeyCheckEnable>1</oneKeyCheckEnable>"
    "<bestsignal_enable>0</bestsignal_enable>"
    "<celllock_enabled>1</celllock_enabled>"
    "<antenna_enabled>1</antenna_enabled>"
    "<sa_enable>1</sa_enable>"
    "</response>"
)


def _minimal_repo(tmp_path: Path) -> Path:
    raw = tmp_path / "evidence" / "raw"
    fixtures = tmp_path / "evidence" / "fixtures"
    docs = tmp_path / "docs"
    raw.mkdir(parents=True)
    fixtures.mkdir(parents=True)
    docs.mkdir(parents=True)
    (raw / "_api_device_basic_information.xml").write_text(
        "<response>"
        "<productfamily>LTE</productfamily>"
        "<classify>cpe</classify>"
        "<devicename>H158-381</devicename>"
        "<spreadname_en>5G CPE Pro 5</spreadname_en>"
        "</response>",
        encoding="utf-8",
    )
    (raw / "_api_net_current-plmn.xml").write_text(
        "<response><Numeric>43211</Numeric><Rat>7</Rat></response>",
        encoding="utf-8",
    )
    (raw / "_api_global_module-switch.xml").write_text(
        _MINIMAL_MODULE_SWITCH, encoding="utf-8"
    )
    (docs / "PHASE1_FINDINGS.md").write_text(
        "Prior context mentions n78 only.\n", encoding="utf-8"
    )
    return tmp_path


def test_collect_device_facts_extracts_confirmed_identity_with_provenance():
    evidence = collect_device_facts()

    model = evidence.require_fact("device.model")
    assert (model.value, model.status) == ("H158-381", "confirmed")
    assert model.source_file == "evidence/raw/_api_device_basic_information.xml"
    assert model.locator == "/response/devicename"
    assert "corroborated" in model.explanation

    assert evidence.require_fact("device.product_family").value == "LTE"
    assert evidence.require_fact("device.classify").value == "cpe"
    assert evidence.require_fact("device.product_name").value == "5G CPE Pro 5"
    assert evidence.require_fact("device.classify").status == "confirmed"


def test_collect_device_facts_extracts_plmn_and_rat_mode():
    evidence = collect_device_facts()

    plmn = evidence.require_fact("network.plmn")
    rat = evidence.require_fact("network.rat_mode")
    assert (plmn.value, plmn.status) == ("43211", "confirmed")
    assert plmn.locator == "/response/Numeric"
    assert (rat.value, rat.status) == ("7", "confirmed")
    assert rat.locator == "/response/Rat"
    assert "mode only" in rat.explanation


def test_feature_flags_are_confirmed_but_never_band_evidence():
    evidence = collect_device_facts()

    flags = {
        fact.name: fact
        for fact in evidence.facts
        if fact.name.startswith("feature.")
    }
    assert set(flags) == {
        "feature.nrProductEnable",
        "feature.oneKeyCheckEnable",
        "feature.bestsignal_enable",
        "feature.celllock_enabled",
        "feature.antenna_enabled",
        "feature.sa_enable",
    }
    assert flags["feature.nrProductEnable"].value == "1"
    assert flags["feature.bestsignal_enable"].value == "0"
    for fact in flags.values():
        assert fact.status == "confirmed"
        assert fact.source_file == "evidence/raw/_api_global_module-switch.xml"
        assert "does not prove" in fact.explanation

    confirmed_band_facts = [
        fact
        for fact in evidence.facts
        if fact.name.startswith("band.") and fact.confirmed
    ]
    assert confirmed_band_facts == []


def test_observed_n78_fact_points_to_a_repository_document():
    evidence = collect_device_facts()

    n78 = evidence.require_fact("band.nr.n78")
    assert (n78.value, n78.status) == ("n78", "observed")
    assert n78.source_file == "docs/PHASE1_FINDINGS.md"
    assert n78.locator.startswith("line ")
    assert "observed" in n78.explanation
    assert "never promoted" in n78.explanation
    assert n78.confirmed is False


def test_gated_responses_are_gaps_not_band_evidence():
    evidence = collect_device_facts()

    gaps = {gap.name: gap for gap in evidence.gaps}
    rat_mode_gap = gaps["data source: RAT mode configuration"]
    assert rat_mode_gap.source_file == "evidence/raw/_api_net_net-mode.xml"
    assert rat_mode_gap.locator == "/error/code"
    assert "100003" in rat_mode_gap.explanation
    assert rat_mode_gap.status == "unavailable"

    monitoring_gap = gaps["data source: serving cell and monitoring status"]
    assert "125002" in monitoring_gap.explanation

    assert not any(
        fact.name.startswith("band.")
        and "net-mode" in fact.source_file
        for fact in evidence.facts
    )


def test_missing_band_captures_are_reported_as_unavailable():
    evidence = collect_device_facts()

    gaps = {gap.name: gap for gap in evidence.gaps}
    for name in (
        "band capability: LTE band capability",
        "band capability: NR band capability",
        "band capability: generic band capability",
        "band capability: LTE/NR band frequency list",
    ):
        assert name in gaps
        assert gaps[name].status == "unavailable"
        assert "no band is invented" in gaps[name].explanation


def test_extracted_profile_keeps_confirmed_and_observed_separate():
    test_profile = repository_device_profile()

    assert test_profile.device_name == "H158-381"
    assert test_profile.plmn == "43211"
    assert test_profile.rat_mode == 7
    assert test_profile.confirmed_slots == ()
    assert [
        (slot.rat, slot.band, slot.capability) for slot in test_profile.slots
    ] == [("NR", "n78", "observed")]
    assert "No confirmed band slot" in test_profile.notes
    assert "never promoted" in test_profile.notes


def test_engine_consumes_evidence_profile_without_ranking_observed_bands():
    test_profile = repository_device_profile()

    analysis = analyze(test_profile, [candidate("NR", "n78")])

    assert analysis.ranking.ranked == ()
    assert len(analysis.ranking.excluded) == 1
    assert "only observed evidence" in analysis.ranking.excluded[0].reason
    assert analysis.combinations.combinations == ()
    assert any(
        "no eligible confirmed NR secondary candidate" in reason
        for reason in analysis.combinations.skipped_reasons
    )


def test_evidence_fact_requires_complete_provenance():
    base = dict(
        name="device.model",
        value="H158-381",
        status="confirmed",
        source_file="evidence/raw/_api_device_basic_information.xml",
        locator="/response/devicename",
        explanation="Example.",
    )
    assert EvidenceFact(**base).confirmed is True

    for field in ("name", "value", "locator", "explanation"):
        broken = dict(base)
        broken[field] = "   "
        with pytest.raises(EvidenceValidationError):
            EvidenceFact(**broken)  # type: ignore[arg-type]

    for bad_source in ("C:/secret.xml", "../outside.xml"):
        broken = dict(base)
        broken["source_file"] = bad_source
        with pytest.raises(EvidenceValidationError):
            EvidenceFact(**broken)  # type: ignore[arg-type]

    for bad_status in ("verified", "CURRENT", ""):
        broken = dict(base)
        broken["status"] = bad_status
        with pytest.raises(EvidenceValidationError):
            EvidenceFact(**broken)  # type: ignore[arg-type]


def test_device_evidence_rejects_mislabeled_objects():
    fact = collect_device_facts().require_fact("device.model")
    with pytest.raises(EvidenceValidationError):
        DeviceEvidence(facts=(fact, "not-a-fact"))  # type: ignore[arg-type]


def test_contradictory_duplicate_facts_fail_closed():
    evidence = collect_device_facts()
    model = evidence.require_fact("device.model")
    contradicted = DeviceEvidence(
        facts=(
            model,
            EvidenceFact(
                name="device.model",
                value="H158-999",
                status="confirmed",
                source_file="evidence/fixtures/device_basic_information.xml",
                locator="/response/DeviceName",
                explanation="Conflicting fixture value.",
            ),
        )
    )

    with pytest.raises(EvidenceContradictionError):
        build_profile_from_evidence(contradicted)


def test_build_profile_rejects_conflicting_band_capabilities():
    def band_fact(status: str) -> EvidenceFact:
        return EvidenceFact(
            name="band.nr.n78",
            value="n78",
            status=status,  # type: ignore[arg-type]
            source_file="docs/PHASE1_FINDINGS.md",
            locator="line 15",
            explanation="Synthetic conflict.",
        )

    evidence = DeviceEvidence(
        facts=(
            EvidenceFact(
                name="device.model",
                value="H158-381",
                status="confirmed",
                source_file="evidence/raw/_api_device_basic_information.xml",
                locator="/response/devicename",
                explanation="Model.",
            ),
            band_fact("observed"),
            band_fact("confirmed"),
        )
    )

    with pytest.raises(EvidenceContradictionError):
        build_profile_from_evidence(evidence)


def test_build_profile_rejects_observed_identity_and_malformed_band_names():
    observed_model = DeviceEvidence(
        facts=(
            EvidenceFact(
                name="device.model",
                value="H158-381",
                status="observed",
                source_file="docs/PHASE1_FINDINGS.md",
                locator="line 4",
                explanation="Historical only.",
            ),
        )
    )
    with pytest.raises(EvidenceValidationError):
        build_profile_from_evidence(observed_model)

    malformed_band = DeviceEvidence(
        facts=(
            EvidenceFact(
                name="device.model",
                value="H158-381",
                status="confirmed",
                source_file="evidence/raw/_api_device_basic_information.xml",
                locator="/response/devicename",
                explanation="Model.",
            ),
            EvidenceFact(
                name="band.n78",
                value="n78",
                status="observed",
                source_file="docs/PHASE1_FINDINGS.md",
                locator="line 15",
                explanation="Malformed fact name.",
            ),
        )
    )
    with pytest.raises(EvidenceValidationError):
        build_profile_from_evidence(malformed_band)


def test_missing_required_evidence_file_fails_closed(tmp_path):
    root = _minimal_repo(tmp_path)
    (root / "evidence/raw/_api_global_module-switch.xml").unlink()

    with pytest.raises(EvidenceExtractionError, match="missing"):
        collect_device_facts(root)


def test_malformed_xml_evidence_fails_closed(tmp_path):
    root = _minimal_repo(tmp_path)
    (root / "evidence/raw/_api_device_basic_information.xml").write_text(
        "<response><devicename>H158-381</response>", encoding="utf-8"
    )

    with pytest.raises(EvidenceExtractionError, match="malformed XML"):
        collect_device_facts(root)


def test_namespaced_xml_is_rejected(tmp_path):
    root = _minimal_repo(tmp_path)
    (root / "evidence/raw/_api_net_current-plmn.xml").write_text(
        '<response xmlns="urn:example"><Numeric>43211</Numeric><Rat>7</Rat></response>',
        encoding="utf-8",
    )

    with pytest.raises(EvidenceExtractionError, match="namespaced"):
        collect_device_facts(root)


def test_invalid_plmn_and_feature_flag_values_fail_closed(tmp_path):
    root = _minimal_repo(tmp_path)
    (root / "evidence/raw/_api_net_current-plmn.xml").write_text(
        "<response><Numeric>123</Numeric><Rat>7</Rat></response>",
        encoding="utf-8",
    )
    with pytest.raises(EvidenceExtractionError, match="invalid PLMN"):
        collect_device_facts(root)

    root = _minimal_repo(tmp_path / "second")
    (root / "evidence/raw/_api_global_module-switch.xml").write_text(
        _MINIMAL_MODULE_SWITCH.replace(
            "<nrProductEnable>1</nrProductEnable>",
            "<nrProductEnable>2</nrProductEnable>",
        ),
        encoding="utf-8",
    )
    with pytest.raises(EvidenceExtractionError, match="must be 0 or 1"):
        collect_device_facts(root)


def test_fixture_contradiction_is_rejected(tmp_path):
    root = _minimal_repo(tmp_path)
    (root / "evidence/fixtures/device_basic_information.xml").write_text(
        "<response><DeviceName>H158-999</DeviceName></response>",
        encoding="utf-8",
    )

    with pytest.raises(EvidenceContradictionError, match="device model"):
        collect_device_facts(root)


def test_fixture_corroboration_is_accepted(tmp_path):
    root = _minimal_repo(tmp_path)
    (root / "evidence/fixtures/device_basic_information.xml").write_text(
        "<response>"
        "<ProductFamily>LTE</ProductFamily>"
        "<Classify>cpe</Classify>"
        "<DeviceName>H158-381</DeviceName>"
        "<SpreadName>5G CPE Pro 5</SpreadName>"
        "</response>",
        encoding="utf-8",
    )
    (root / "evidence/fixtures/current_plmn.xml").write_text(
        "<response><Numeric>43211</Numeric><Rat>7</Rat></response>",
        encoding="utf-8",
    )

    evidence = collect_device_facts(root)

    assert evidence.require_fact("device.model").value == "H158-381"
    assert evidence.require_fact("network.plmn").value == "43211"


def test_evidence_sources_are_repository_relative():
    for source in EVIDENCE_SOURCES:
        path = Path(source)
        assert not path.is_absolute()
        assert ".." not in path.parts


def test_evidence_module_has_no_network_imports():
    source = Path(evidence_module.__file__).read_text(encoding="utf-8")

    for forbidden in (
        "import requests",
        "import socket",
        "import urllib",
        "http.client",
        "https://",
        "http://",
    ):
        assert forbidden not in source

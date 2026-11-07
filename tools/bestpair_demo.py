from __future__ import annotations

import argparse

from huawei_tower.bestpair import (
    BandCandidate,
    BandSlot,
    BestPairAnalysis,
    DeviceBandProfile,
    SignalSnapshot,
    analyze,
    evidence_minimal_profile,
)

_HEADER = "=" * 78
_METRIC_UNITS = {"rsrp": "dBm", "rsrq": "dB", "sinr": "dB", "rssi": "dBm"}


def _slot_line(slot: BandSlot) -> str:
    return (
        f"{slot.rat} {slot.band:<4} capability={slot.capability:<9} "
        f"source={slot.evidence_source}"
    )


def _print_profile(profile: DeviceBandProfile) -> None:
    print(f"Device: {profile.device_name}")
    print(f"PLMN:   {profile.plmn if profile.plmn is not None else 'unknown'}")
    print(f"RAT mode: {profile.rat_mode!r}")
    print(f"Notes:  {profile.notes}")
    print()
    print("Profile slots:")
    if not profile.slots:
        print("  (none)")
    for slot in profile.slots:
        print("  " + _slot_line(slot))
    print()
    print(
        "Confirmed eligible slots: "
        + (
            ", ".join(f"{slot.rat} {slot.band}" for slot in profile.confirmed_slots)
            or "none"
        )
    )
    print(
        "Observed but not eligible: "
        + (
            ", ".join(f"{slot.rat} {slot.band}" for slot in profile.observed_slots)
            or "none"
        )
    )


def _print_ranking(analysis: BestPairAnalysis) -> None:
    ranking = analysis.ranking
    print()
    print(f"Ranking (top {ranking.top_per_rat} per RAT, RSRP required):")
    if not ranking.ranked:
        print("  No eligible confirmed candidates. Ranking is empty by design.")
    for index, score in enumerate(ranking.ranked, start=1):
        candidate = score.candidate
        print(
            f"  {index}. {candidate.rat} {candidate.band:<4} "
            f"score={score.score:6.2f}/100 coverage={score.coverage:6.1%}"
        )
        for component in score.components:
            if not component.available:
                print(
                    f"       {component.metric:<4} missing "
                    f"(weight {component.weight:.2f}, contribution 0.00)"
                )
                continue
            unit = _METRIC_UNITS.get(component.metric, "")
            print(
                f"       {component.metric:<4} {component.raw_value:7.2f} {unit:<3} "
                f"norm={component.normalized:5.3f} "
                f"weight={component.weight:.2f} "
                f"contribution={component.contribution_points:5.2f}"
            )
        print(f"       available={score.metrics_available}")
        print(f"       missing={score.metrics_missing}")

    print()
    print("Excluded candidates:")
    if not ranking.excluded:
        print("  (none)")
    for exclusion in ranking.excluded:
        print(
            f"  {exclusion.candidate.rat} {exclusion.candidate.band:<4} "
            f"-> {exclusion.reason}"
        )


def _print_combinations(analysis: BestPairAnalysis) -> None:
    result = analysis.combinations
    print()
    print(f"Combinations ({result.model}):")
    if not result.combinations:
        print("  No combinations generated.")
    for index, combination in enumerate(result.combinations, start=1):
        print(
            f"  {index}. LTE {combination.lte.candidate.band} + "
            f"NR {combination.nr.candidate.band}: "
            f"score={combination.score:6.2f}/100 "
            f"coverage={combination.coverage:6.1%}"
        )
        print(f"     paired metrics={combination.metrics_available}")
        print(f"     unpaired metrics={combination.metrics_missing}")
    if result.skipped_reasons:
        print("  Reasons / limitations:")
        for reason in result.skipped_reasons:
            print(f"    - {reason}")


def _run_evidence_profile(top_per_rat: int) -> None:
    print(_HEADER)
    print("SCENARIO 1 - REPOSITORY EVIDENCE PROFILE")
    print("Signal values in this scenario are SYNTHETIC fixtures, not modem readings.")
    print(_HEADER)
    profile = evidence_minimal_profile()
    _print_profile(profile)
    print()

    # Deliberately synthetic measurement for the observed-only n78 slot.
    candidates = [
        BandCandidate(
            rat="NR",
            band="n78",
            signal=SignalSnapshot(rsrp=-92.0, rsrq=-11.0, sinr=7.0, rssi=-70.0),
            label="SYNTHETIC sample measurement (not a modem reading)",
        )
    ]
    analysis = analyze(profile, candidates, top_per_rat=top_per_rat)
    _print_ranking(analysis)
    _print_combinations(analysis)


def _illustrative_profile() -> DeviceBandProfile:
    """Hypothetical confirmed bands used only to exercise the scoring model."""

    def evidence_slot(rat: str, band: str) -> BandSlot:
        return BandSlot(
            rat=rat,
            band=band,
            evidence_source="SYNTHETIC demo fixture (not device evidence)",
            evidence_description=(
                "Hypothetical confirmed slot used only to demonstrate the "
                "Phase 8 engine; it is not a claim about the H158-381."
            ),
            capability="confirmed",
        )

    return DeviceBandProfile(
        device_name="ILLUSTRATIVE SYNTHETIC PROFILE (not H158-381 evidence)",
        rat_mode=7,
        slots=(
            evidence_slot("LTE", "B3"),
            evidence_slot("LTE", "B7"),
            evidence_slot("LTE", "B20"),
            evidence_slot("NR", "n78"),
            evidence_slot("NR", "n41"),
        ),
        notes=(
            "HYPOTHETICAL bands and SYNTHETIC signal values. This scenario is "
            "not modem evidence, not a capability claim, and not a "
            "recommendation for the real device."
        ),
    )


def _illustrative_candidates() -> list[BandCandidate]:
    # All values below are synthetic fixtures, not modem readings.
    return [
        BandCandidate(
            "LTE",
            "B20",
            SignalSnapshot(rsrp=-89.0, rsrq=-8.0, sinr=13.0, rssi=-60.0),
            label="SYNTHETIC",
        ),
        BandCandidate(
            "LTE",
            "B3",
            SignalSnapshot(rsrp=-95.0, rsrq=-10.0, sinr=8.0, rssi=-65.0),
            label="SYNTHETIC",
        ),
        BandCandidate(
            "LTE",
            "B7",
            SignalSnapshot(rsrp=-101.0, rsrq=-12.0, sinr=2.0, rssi=-72.0),
            label="SYNTHETIC",
        ),
        BandCandidate(
            "NR",
            "n78",
            SignalSnapshot(rsrp=-92.0, rsrq=-9.0, sinr=15.0, rssi=-68.0),
            label="SYNTHETIC",
        ),
        BandCandidate(
            "NR",
            "n41",
            SignalSnapshot(rsrp=-105.0, rsrq=-14.0, sinr=-1.0, rssi=-78.0),
            label="SYNTHETIC",
        ),
    ]


def _run_illustrative_profile(top_per_rat: int) -> None:
    print()
    print(_HEADER)
    print("SCENARIO 2 - ILLUSTRATIVE SYNTHETIC PROFILE (NOT DEVICE EVIDENCE)")
    print("Every band capability and signal value here is synthetic/hypothetical.")
    print("It exists only to demonstrate ranking and combination output.")
    print(_HEADER)
    profile = _illustrative_profile()
    _print_profile(profile)
    analysis = analyze(
        profile,
        _illustrative_candidates(),
        top_per_rat=top_per_rat,
    )
    _print_ranking(analysis)
    _print_combinations(analysis)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline Phase 8 Best Pair demo. Performs no modem/network I/O and "
            "uses synthetic signal values only."
        )
    )
    parser.add_argument(
        "--top-per-rat",
        type=int,
        default=3,
        help="candidates retained per RAT (default: 3)",
    )
    parser.add_argument(
        "--evidence-only",
        action="store_true",
        help="omit the clearly labeled illustrative synthetic scenario",
    )
    args = parser.parse_args()

    print("Best Pair offline demo - NO MODEM I/O")
    print("All signal measurements shown are SYNTHETIC, not modem readings.")
    _run_evidence_profile(args.top_per_rat)
    if not args.evidence_only:
        _run_illustrative_profile(args.top_per_rat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

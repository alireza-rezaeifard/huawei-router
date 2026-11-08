"""Offline tests for the Phase 10 fail-closed capture parsers.

Every test reads or writes only temporary local files. No modem, network,
authentication or JavaScript execution is involved.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from huawei_tower.bestpair import (
    EVIDENCE_SOURCES,
    EvidenceExtractionError,
    build_profile_from_evidence,
    collect_device_facts,
    parse_basic_information,
    parse_current_plmn,
    parse_module_switch,
    parse_operator_info,
    parse_state_login,
    repository_device_profile,
)
from huawei_tower.modem.api import (
    FORBIDDEN_PATHS,
    GATED_GET_ENDPOINTS,
    SAFE_GET_ENDPOINTS,
)

_BASIC_VALID = (
    "<response>"
    "<productfamily>LTE</productfamily>"
    "<classify>cpe</classify>"
    "<devicename>H158-381</devicename>"
    "<spreadname_en>5G CPE Pro 5</spreadname_en>"
    "</response>"
)
_PLMN_VALID = "<response><Numeric>43211</Numeric><Rat>7</Rat></response>"
_MODULE_VALID = (
    "<response>"
    "<nrProductEnable>1</nrProductEnable>"
    "<oneKeyCheckEnable>1</oneKeyCheckEnable>"
    "<bestsignal_enable>0</bestsignal_enable>"
    "<celllock_enabled>1</celllock_enabled>"
    "<antenna_enabled>1</antenna_enabled>"
    "<sa_enable>1</sa_enable>"
    "</response>"
)
_LOGIN_VALID = (
    "<response>"
    "<rsapadingtype>1</rsapadingtype>"
    "<wifipwdsamewithwebpwd>0</wifipwdsamewithwebpwd>"
    "<extern_password_type>1</extern_password_type>"
    "<remainwaittime>0</remainwaittime>"
    "<State>-1</State>"
    "<history_login_flag>0</history_login_flag>"
    "<userlevel></userlevel>"
    "<username></username>"
    "<password_type>4</password_type>"
    "<firstlogin>0</firstlogin>"
    "<lockstatus>0</lockstatus>"
    "<accounts_number>2</accounts_number>"
    "</response>"
)
_OPERATOR_VALID = '{"OperatorName":""}'


def _repo(tmp_path: Path) -> Path:
    raw = tmp_path / "evidence" / "raw"
    docs = tmp_path / "docs"
    raw.mkdir(parents=True)
    docs.mkdir(parents=True)
    (raw / "_api_device_basic_information.xml").write_text(
        _BASIC_VALID, encoding="utf-8"
    )
    (raw / "_api_net_current-plmn.xml").write_text(_PLMN_VALID, encoding="utf-8")
    (raw / "_api_global_module-switch.xml").write_text(
        _MODULE_VALID, encoding="utf-8"
    )
    (raw / "_api_user_state-login.xml").write_text(_LOGIN_VALID, encoding="utf-8")
    (raw / "_api_app_operatorinfo.xml").write_text(_OPERATOR_VALID, encoding="utf-8")
    (docs / "PHASE1_FINDINGS.md").write_text(
        "Prior context mentions n78 only.\n", encoding="utf-8"
    )
    return tmp_path


def _replace(tmp_path: Path, name: str, body: str) -> Path:
    root = _repo(tmp_path)
    (root / "evidence" / "raw" / name).write_text(body, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Accepted captures and provenance
# ---------------------------------------------------------------------------


def test_all_five_parsers_accept_valid_captures(tmp_path):
    root = _repo(tmp_path)

    identity = parse_basic_information(root)
    assert identity.require_fact("device.model").value == "H158-381"
    assert identity.require_fact("device.product_family").value == "LTE"
    assert identity.require_fact("device.classify").value == "cpe"
    assert identity.require_fact("device.product_name").value == "5G CPE Pro 5"

    plmn = parse_current_plmn(root)
    assert plmn.require_fact("network.plmn").value == "43211"
    assert plmn.require_fact("network.rat_mode").value == "7"

    switch = parse_module_switch(root)
    assert switch.require_fact("feature.nrProductEnable").value == "1"
    assert switch.require_fact("feature.sa_enable").value == "1"

    login = parse_state_login(root)
    assert login.require_fact("login.State").value == "-1"
    assert login.require_fact("login.password_type").value == "4"
    assert login.require_fact("login.accounts_number").value == "2"

    operator = parse_operator_info(root)
    assert operator.facts == ()
    assert operator.gaps[0].name == "operator display name"


def test_all_five_parsers_accept_the_repository_captures():
    identity = parse_basic_information()
    assert identity.require_fact("device.model").value == "H158-381"

    plmn = parse_current_plmn()
    assert plmn.require_fact("network.rat_mode").value == "7"

    switch = parse_module_switch()
    assert switch.require_fact("feature.nrProductEnable").value == "1"

    login = parse_state_login()
    assert login.require_fact("login.State").value == "-1"
    assert login.require_fact("login.accounts_number").value == "2"

    operator = parse_operator_info()
    assert operator.facts == ()
    assert operator.gaps[0].name == "operator display name"


def test_provenance_survives_every_parser(tmp_path):
    root = _repo(tmp_path)
    parsed = (
        parse_basic_information(root),
        parse_current_plmn(root),
        parse_module_switch(root),
        parse_state_login(root),
        parse_operator_info(root),
    )
    sources = set(EVIDENCE_SOURCES)
    for evidence in parsed:
        for fact in evidence.facts:
            assert fact.source_file in sources
            assert not Path(fact.source_file).is_absolute()
            assert ".." not in Path(fact.source_file).parts
            assert fact.locator.startswith("/")
            assert fact.explanation


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "parser,filename",
    (
        (parse_basic_information, "_api_device_basic_information.xml"),
        (parse_current_plmn, "_api_net_current-plmn.xml"),
        (parse_module_switch, "_api_global_module-switch.xml"),
        (parse_state_login, "_api_user_state-login.xml"),
    ),
)
def test_malformed_xml_fails_closed(tmp_path, parser, filename):
    root = _replace(tmp_path, filename, "<response><broken></response>")
    with pytest.raises(EvidenceExtractionError, match="malformed XML"):
        parser(root)


def test_malformed_json_fails_closed(tmp_path):
    root = _replace(
        tmp_path, "_api_app_operatorinfo.xml", '{"OperatorName": '
    )
    with pytest.raises(EvidenceExtractionError, match="malformed JSON"):
        parse_operator_info(root)


# ---------------------------------------------------------------------------
# Missing required fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "parser,filename,body,missing",
    (
        (
            parse_basic_information,
            "_api_device_basic_information.xml",
            "<response><productfamily>LTE</productfamily><classify>cpe"
            "</classify><spreadname_en>5G CPE Pro 5</spreadname_en></response>",
            "devicename",
        ),
        (
            parse_current_plmn,
            "_api_net_current-plmn.xml",
            "<response><Numeric>43211</Numeric></response>",
            "Rat",
        ),
        (
            parse_module_switch,
            "_api_global_module-switch.xml",
            _MODULE_VALID.replace(
                "<nrProductEnable>1</nrProductEnable>", ""
            ),
            "nrProductEnable",
        ),
        (
            parse_state_login,
            "_api_user_state-login.xml",
            _LOGIN_VALID.replace("<State>-1</State>", ""),
            "State",
        ),
    ),
)
def test_missing_required_field_fails_closed(
    tmp_path, parser, filename, body, missing
):
    root = _replace(tmp_path, filename, body)
    with pytest.raises(EvidenceExtractionError, match=missing):
        parser(root)


def test_missing_operator_field_fails_closed(tmp_path):
    root = _replace(tmp_path, "_api_app_operatorinfo.xml", "{}")
    with pytest.raises(EvidenceExtractionError, match="OperatorName"):
        parse_operator_info(root)


def test_missing_required_capture_fails_closed(tmp_path):
    root = _repo(tmp_path)
    (root / "evidence" / "raw" / "_api_net_current-plmn.xml").unlink()
    with pytest.raises(EvidenceExtractionError, match="missing"):
        parse_current_plmn(root)


# ---------------------------------------------------------------------------
# Unknown or unexpected fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "parser,filename,body,unexpected",
    (
        (
            parse_basic_information,
            "_api_device_basic_information.xml",
            _BASIC_VALID.replace("<classify>cpe</classify>", "<unexpected>1</unexpected>"),
            "unexpected",
        ),
        (
            parse_current_plmn,
            "_api_net_current-plmn.xml",
            _PLMN_VALID.replace("</response>", "<Bands>n78</Bands></response>"),
            "Bands",
        ),
        (
            parse_module_switch,
            "_api_global_module-switch.xml",
            _MODULE_VALID.replace(
                "</response>", "<nrBandInfo>n78</nrBandInfo></response>"
            ),
            "nrBandInfo",
        ),
        (
            parse_state_login,
            "_api_user_state-login.xml",
            _LOGIN_VALID.replace("</response>", "<nrBand>n78</nrBand></response>"),
            "nrBand",
        ),
    ),
)
def test_unknown_xml_field_fails_closed(
    tmp_path, parser, filename, body, unexpected
):
    root = _replace(tmp_path, filename, body)
    with pytest.raises(EvidenceExtractionError, match=unexpected):
        parser(root)


def test_unknown_json_field_fails_closed(tmp_path):
    root = _replace(
        tmp_path,
        "_api_app_operatorinfo.xml",
        json.dumps({"OperatorName": "", "Unexpected": "value"}),
    )
    with pytest.raises(EvidenceExtractionError, match="Unexpected"):
        parse_operator_info(root)


# ---------------------------------------------------------------------------
# Gated error stubs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", ("100003", "125002", "100002"))
def test_gated_error_stub_is_rejected_by_parser(tmp_path, code):
    root = _replace(
        tmp_path,
        "_api_device_basic_information.xml",
        f"<error><code>{code}</code></error>",
    )
    with pytest.raises(EvidenceExtractionError, match=code):
        parse_basic_information(root)


def test_gated_stub_codes_are_explicit_gaps():
    evidence = collect_device_facts()
    gaps = {gap.name: gap for gap in evidence.gaps}

    assert "100003" in gaps["data source: RAT mode configuration"].explanation
    assert (
        "125002"
        in gaps["data source: serving cell and monitoring status"].explanation
    )
    assert "100002" in gaps["data source: USB tethering switch"].explanation
    for name in (
        "data source: RAT mode configuration",
        "data source: serving cell and monitoring status",
        "data source: USB tethering switch",
    ):
        assert gaps[name].status == "unavailable"


# ---------------------------------------------------------------------------
# Unavailable band evidence
# ---------------------------------------------------------------------------


def test_missing_band_captures_are_explicit_gaps():
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


def test_rat_seven_is_mode_only_and_never_a_band():
    plmn = parse_current_plmn()
    rat = plmn.require_fact("network.rat_mode")
    assert rat.value == "7"
    assert "mode only" in rat.explanation
    assert not any(fact.name.startswith("band.") for fact in plmn.facts)

    profile = repository_device_profile()
    assert profile.rat_mode == 7
    assert profile.confirmed_slots == ()


def test_nr_product_enable_never_implies_nr_band_support():
    switch = parse_module_switch()
    flag = switch.require_fact("feature.nrProductEnable")
    assert (flag.value, flag.status) == ("1", "confirmed")
    assert "does not prove" in flag.explanation
    assert not any(fact.name.startswith("band.") for fact in switch.facts)

    profile = repository_device_profile()
    assert profile.confirmed_slots == ()

    evidence = collect_device_facts()
    assert not any(
        fact.name.startswith("band.") and fact.confirmed
        for fact in evidence.facts
    )


def test_n78_remains_observed_and_is_never_promoted():
    evidence = collect_device_facts()
    n78 = evidence.require_fact("band.nr.n78")
    assert (n78.value, n78.status) == ("n78", "observed")
    assert n78.confirmed is False

    profile = build_profile_from_evidence(evidence)
    assert [(slot.rat, slot.band, slot.capability) for slot in profile.slots] == [
        ("NR", "n78", "observed")
    ]
    assert profile.confirmed_slots == ()


# ---------------------------------------------------------------------------
# Explicit gaps instead of invented values
# ---------------------------------------------------------------------------


def test_empty_optional_login_values_are_gaps(tmp_path):
    root = _repo(tmp_path)
    login = parse_state_login(root)
    gap_names = {gap.name for gap in login.gaps}
    assert "login.username" in gap_names
    assert "login.userlevel" in gap_names
    assert all(gap.status == "unavailable" for gap in login.gaps)


def test_empty_operator_name_is_a_gap_not_an_invented_fact(tmp_path):
    root = _repo(tmp_path)
    operator = parse_operator_info(root)
    assert operator.facts == ()
    assert operator.gaps[0].locator == "/OperatorName"
    assert "empty OperatorName" in operator.gaps[0].explanation


def test_missing_operator_capture_is_a_gap(tmp_path):
    root = _repo(tmp_path)
    (root / "evidence" / "raw" / "_api_app_operatorinfo.xml").unlink()
    operator = parse_operator_info(root)
    assert operator.facts == ()
    assert operator.gaps[0].locator == "(file not present)"


def test_non_empty_operator_name_stays_observed(tmp_path):
    root = _replace(
        tmp_path,
        "_api_app_operatorinfo.xml",
        json.dumps({"OperatorName": "Example Operator"}),
    )
    operator = parse_operator_info(root)
    fact = operator.require_fact("network.operator_name")
    assert (fact.value, fact.status) == ("Example Operator", "observed")
    assert fact.confirmed is False


# ---------------------------------------------------------------------------
# Policy invariants (no allowlist change, default-deny preserved)
# ---------------------------------------------------------------------------


def test_phase10_paths_remain_denied():
    for path in (
        "/api/app/operatorinfo",
        "/api/net/lte-band-info",
        "/api/net/nr-band-info",
        "/api/net/band-info",
        "/api/net/cell-info",
        "/api/device/signal",
        "/config/network/bandfreqlist.xml",
    ):
        assert path not in SAFE_GET_ENDPOINTS

    for path in (
        "/api/net/lock-freq",
        "/api/net/net-mode",
        "/api/net/handle-cell",
        "/api/ntwk/celllock",
        "/api/net/register",
        "/api/net/plmn-list",
        "/api/monitoring/best-signal-position",
    ):
        assert path in FORBIDDEN_PATHS

    assert "/api/app/operatorinfo" not in GATED_GET_ENDPOINTS
    assert "/api/net/net-mode" not in GATED_GET_ENDPOINTS

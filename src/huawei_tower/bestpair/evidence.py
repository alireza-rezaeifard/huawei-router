"""Offline, evidence-backed device capability facts for Best Pair.

Scope guarantees (Phase 9):

- Reads only a fixed allowlist of sanitized local repository artifacts
  (``evidence/raw``, ``evidence/fixtures`` and ``docs/PHASE1_FINDINGS.md``).
- Performs no modem connection, HTTP request, authentication, JavaScript
  execution, scanning, locking, reconnect, reboot or configuration change.
- Never writes to, renames or deletes an input file.

Evidence policy
---------------
Every extracted fact carries explicit provenance: a repository-relative source
file, an XML element / JSON field locator, a status of ``confirmed`` or
``observed``, and a short explanation.

``confirmed`` means a direct value read from a captured read-only response or a
corroborated fixture. ``observed`` means historical context or an unverified
claim. Observed facts are retained for transparency but are never promoted to
confirmed, and only confirmed band facts can become rankable band slots.

Feature flags are product toggles, not band capabilities. ``Rat 7`` proves the
LTE+NR NSA *mode* only; it never proves a specific LTE/NR band combination. If a
gated or stub response is present, it is reported as an unavailable data source,
never as evidence of a supported band.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..modem.errors import ModemParseError
from ..modem.xmlutil import parse_xml
from .engine import BandSlot, BestPairValidationError, DeviceBandProfile

EvidenceStatus = Literal["confirmed", "observed"]

_RAW = "evidence/raw"
_FIXTURES = "evidence/fixtures"
_PHASE1_DOC = "docs/PHASE1_FINDINGS.md"

_DEVICE_RAW = f"{_RAW}/_api_device_basic_information.xml"
_DEVICE_FIXTURE = f"{_FIXTURES}/device_basic_information.xml"
_PLMN_RAW = f"{_RAW}/_api_net_current-plmn.xml"
_PLMN_FIXTURE = f"{_FIXTURES}/current_plmn.xml"
_MODULE_SWITCH_RAW = f"{_RAW}/_api_global_module-switch.xml"
_OPERATOR_RAW = f"{_RAW}/_api_app_operatorinfo.xml"

# Feature flags that are relevant to the product surface. They are recorded as
# product toggles only; none of them is band-capability evidence.
_FEATURE_FLAGS: tuple[str, ...] = (
    "nrProductEnable",
    "oneKeyCheckEnable",
    "bestsignal_enable",
    "celllock_enabled",
    "antenna_enabled",
    "sa_enable",
)

# Gated / stub captures: (source file, human label).
_GATED_SOURCES: tuple[tuple[str, str], ...] = (
    (f"{_RAW}/_api_device_information.xml", "firmware identity"),
    (f"{_RAW}/_api_version.xml", "firmware version"),
    (f"{_RAW}/_api_monitoring_status.xml", "serving cell and monitoring status"),
    (f"{_RAW}/_api_net_net-mode.xml", "RAT mode configuration"),
    (f"{_RAW}/_api_net_net-mode-list.xml", "RAT mode option list"),
    (f"{_RAW}/_api_config_global_config_xml.xml", "device configuration XML"),
)

# Band-capability captures that do not exist locally. Their absence is itself
# evidence that capability data is unavailable; it is never used to invent a
# band.
_BAND_CAPTURE_SOURCES: tuple[tuple[str, str], ...] = (
    ("LTE band capability", f"{_RAW}/_api_net_lte-band-info.xml"),
    ("NR band capability", f"{_RAW}/_api_net_nr-band-info.xml"),
    ("generic band capability", f"{_RAW}/_api_net_band-info.xml"),
    ("LTE/NR band frequency list", "config/network/bandfreqlist.xml"),
)

# The complete set of paths this module may read.
EVIDENCE_SOURCES: tuple[str, ...] = tuple(
    dict.fromkeys(
        (
            _DEVICE_RAW,
            _DEVICE_FIXTURE,
            _PLMN_RAW,
            _PLMN_FIXTURE,
            _MODULE_SWITCH_RAW,
            _OPERATOR_RAW,
            _PHASE1_DOC,
            *(source for source, _ in _GATED_SOURCES),
            *(source for _, source in _BAND_CAPTURE_SOURCES),
        )
    )
)

_PLMN_RE = re.compile(r"^\d{5,6}$")
_ERROR_CODE_RE = re.compile(r"^\d{3,6}$")


class EvidenceError(Exception):
    """Base error for offline evidence extraction."""


class EvidenceValidationError(EvidenceError, ValueError):
    """Raised when an evidence fact, gap or profile input is invalid."""


class EvidenceExtractionError(EvidenceError):
    """Raised when a local evidence file is malformed or unreadable."""


class EvidenceContradictionError(EvidenceExtractionError):
    """Raised when two local evidence sources disagree."""


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceValidationError(f"{name} must be a non-empty string")
    return value.strip()


def _require_source_file(value: object) -> str:
    text = _require_text("source_file", value)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise EvidenceValidationError(
            f"source_file must be repository-relative: {text!r}"
        )
    return path.as_posix()


@dataclass(frozen=True)
class EvidenceFact:
    """One extracted fact with explicit, auditable provenance."""

    name: str
    value: str
    status: EvidenceStatus
    source_file: str
    locator: str
    explanation: str

    def __post_init__(self) -> None:
        for field_name in ("name", "value", "locator", "explanation"):
            object.__setattr__(
                self, field_name, _require_text(field_name, getattr(self, field_name))
            )
        object.__setattr__(
            self, "source_file", _require_source_file(self.source_file)
        )

        if not isinstance(self.status, str):
            raise EvidenceValidationError(
                "status must be 'confirmed' or 'observed'"
            )
        status = self.status.strip().lower()
        if status not in ("confirmed", "observed"):
            raise EvidenceValidationError(
                "status must be 'confirmed' or 'observed'"
            )
        object.__setattr__(self, "status", status)

    @property
    def confirmed(self) -> bool:
        return self.status == "confirmed"


@dataclass(frozen=True)
class EvidenceGap:
    """A data source that is gated, stub, missing or schema-unverified."""

    name: str
    source_file: str
    locator: str
    explanation: str
    status: Literal["unavailable"] = "unavailable"

    def __post_init__(self) -> None:
        for field_name in ("name", "locator", "explanation"):
            object.__setattr__(
                self, field_name, _require_text(field_name, getattr(self, field_name))
            )
        object.__setattr__(
            self, "source_file", _require_source_file(self.source_file)
        )
        if self.status != "unavailable":
            raise EvidenceValidationError("gap status must be 'unavailable'")


@dataclass(frozen=True)
class DeviceEvidence:
    """All confirmed/observed facts plus explicit unavailable data sources."""

    facts: tuple[EvidenceFact, ...]
    gaps: tuple[EvidenceGap, ...] = ()

    def __post_init__(self) -> None:
        facts = tuple(self.facts)
        gaps = tuple(self.gaps)
        for fact in facts:
            if not isinstance(fact, EvidenceFact):
                raise EvidenceValidationError("facts must contain EvidenceFact values")
        for gap in gaps:
            if not isinstance(gap, EvidenceGap):
                raise EvidenceValidationError("gaps must contain EvidenceGap values")
        object.__setattr__(self, "facts", facts)
        object.__setattr__(self, "gaps", gaps)

    @property
    def confirmed_facts(self) -> tuple[EvidenceFact, ...]:
        return tuple(fact for fact in self.facts if fact.confirmed)

    @property
    def observed_facts(self) -> tuple[EvidenceFact, ...]:
        return tuple(fact for fact in self.facts if not fact.confirmed)

    def facts_named(self, name: str) -> tuple[EvidenceFact, ...]:
        return tuple(fact for fact in self.facts if fact.name == name)

    def fact(self, name: str) -> EvidenceFact | None:
        matches = self.facts_named(name)
        if not matches:
            return None
        first = matches[0]
        for other in matches[1:]:
            if other.value != first.value or other.status != first.status:
                raise EvidenceContradictionError(
                    f"contradictory evidence facts for {name!r}"
                )
        return first

    def require_fact(self, name: str) -> EvidenceFact:
        fact = self.fact(name)
        if fact is None:
            raise EvidenceValidationError(f"missing required evidence fact {name!r}")
        return fact


def _resolve_repo_root(repo_root: Path | str | None) -> Path:
    if repo_root is None:
        # evidence.py -> bestpair -> huawei_tower -> src -> repository root
        return Path(__file__).resolve().parents[3]
    root = Path(repo_root)
    if not root.is_dir():
        raise EvidenceValidationError(f"repository root is not a directory: {root}")
    return root.resolve()


def _read_text(repo_root: Path, relative_path: str) -> str:
    path = repo_root / relative_path
    if not path.is_file():
        raise EvidenceExtractionError(
            f"required evidence file missing: {relative_path}"
        )
    return path.read_text(encoding="utf-8-sig", errors="replace")


def _payload_start(text: str) -> int:
    for marker in ("<?xml", "<response", "<error", "<"):
        index = text.find(marker)
        if index >= 0:
            return index
    raise EvidenceExtractionError("no XML payload found")


def _load_xml(
    repo_root: Path, relative_path: str, *, required: bool = True
) -> object | None:
    path = repo_root / relative_path
    if not path.is_file():
        if required:
            raise EvidenceExtractionError(
                f"required evidence file missing: {relative_path}"
            )
        return None
    text = _read_text(repo_root, relative_path)
    start = _payload_start(text)
    try:
        root = parse_xml(text[start:])
    except ModemParseError as exc:
        raise EvidenceExtractionError(
            f"malformed XML evidence in {relative_path}"
        ) from exc
    return _validate_tree(root, relative_path)


def _validate_tree(root: object, relative_path: str) -> object:
    tag = getattr(root, "tag", None)
    if not isinstance(tag, str) or "}" in tag:
        raise EvidenceExtractionError(
            f"unexpected or namespaced root element in {relative_path}: {tag!r}"
        )
    if tag not in ("response", "error"):
        raise EvidenceExtractionError(
            f"unexpected root element <{tag}> in {relative_path}"
        )

    seen: set[str] = set()
    for child in root:
        child_tag = getattr(child, "tag", None)
        if not isinstance(child_tag, str) or "}" in child_tag:
            raise EvidenceExtractionError(
                f"namespaced or unsupported element in {relative_path}: {child_tag!r}"
            )
        if child_tag in seen:
            raise EvidenceExtractionError(
                f"ambiguous repeated element <{child_tag}> in {relative_path}"
            )
        seen.add(child_tag)
    return root


def _child_text(
    root: object,
    tag: str,
    relative_path: str,
    *,
    required: bool = True,
) -> str | None:
    node = root.find(tag)
    if node is None:
        if required:
            raise EvidenceExtractionError(
                f"missing direct child <{tag}> in {relative_path}"
            )
        return None
    if len(node):
        raise EvidenceExtractionError(
            f"unexpected nested XML under <{tag}> in {relative_path}"
        )
    text = (node.text or "").strip()
    if required and not text:
        raise EvidenceExtractionError(
            f"empty direct child <{tag}> in {relative_path}"
        )
    return text


def _error_code(root: object, relative_path: str) -> str:
    code = _child_text(root, "code", relative_path)
    assert code is not None
    if not _ERROR_CODE_RE.fullmatch(code):
        raise EvidenceExtractionError(
            f"invalid error code {code!r} in {relative_path}"
        )
    return code


def _corroborate(
    label: str,
    primary: str,
    primary_source: str,
    secondary: str | None,
    secondary_source: str,
) -> None:
    if secondary is None:
        return
    if primary != secondary:
        raise EvidenceContradictionError(
            f"{label} contradiction: {primary_source} reports {primary!r} "
            f"but {secondary_source} reports {secondary!r}"
        )


def _line_containing(text: str, needle: str) -> tuple[int, str] | None:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number, line.strip()
    return None


def _validate_flag(name: str, value: str, relative_path: str) -> str:
    if value not in ("0", "1"):
        raise EvidenceExtractionError(
            f"feature flag <{name}> in {relative_path} must be 0 or 1, got {value!r}"
        )
    return value


def collect_device_facts(repo_root: Path | str | None = None) -> DeviceEvidence:
    """Extract provenance-tagged facts from sanitized local evidence only.

    Required sources: the raw basic-information, current-PLMN and module-switch
    XML captures plus ``docs/PHASE1_FINDINGS.md``. Fixtures and gated responses
    are used for corroboration / gap reporting when present.
    """
    root_dir = _resolve_repo_root(repo_root)
    facts: list[EvidenceFact] = []
    gaps: list[EvidenceGap] = []

    # -- Device identity ---------------------------------------------------
    device_root = _load_xml(root_dir, _DEVICE_RAW)
    assert device_root is not None
    if getattr(device_root, "tag", None) == "error":
        raise EvidenceExtractionError(
            f"{_DEVICE_RAW} contains a gated error response, not identity data"
        )
    device_name = _child_text(device_root, "devicename", _DEVICE_RAW)
    product_family = _child_text(device_root, "productfamily", _DEVICE_RAW)
    classify = _child_text(device_root, "classify", _DEVICE_RAW)
    product_name = _child_text(device_root, "spreadname_en", _DEVICE_RAW)
    assert (
        device_name is not None
        and product_family is not None
        and classify is not None
        and product_name is not None
    )
    if len(device_name) > 64:
        raise EvidenceExtractionError(
            f"implausible device name in {_DEVICE_RAW}: {device_name!r}"
        )

    fixture_root = _load_xml(root_dir, _DEVICE_FIXTURE, required=False)
    if fixture_root is not None:
        if getattr(fixture_root, "tag", None) == "error":
            raise EvidenceContradictionError(
                f"{_DEVICE_FIXTURE} is an error response, not corroborating data"
            )
        _corroborate(
            "device model",
            device_name,
            _DEVICE_RAW,
            _child_text(fixture_root, "DeviceName", _DEVICE_FIXTURE, required=False),
            _DEVICE_FIXTURE,
        )
        _corroborate(
            "product family",
            product_family,
            _DEVICE_RAW,
            _child_text(fixture_root, "ProductFamily", _DEVICE_FIXTURE, required=False),
            _DEVICE_FIXTURE,
        )
        _corroborate(
            "device class",
            classify,
            _DEVICE_RAW,
            _child_text(fixture_root, "Classify", _DEVICE_FIXTURE, required=False),
            _DEVICE_FIXTURE,
        )
        _corroborate(
            "product name",
            product_name,
            _DEVICE_RAW,
            _child_text(fixture_root, "SpreadName", _DEVICE_FIXTURE, required=False),
            _DEVICE_FIXTURE,
        )
    else:
        gaps.append(
            EvidenceGap(
                name="device identity fixture corroboration",
                source_file=_DEVICE_FIXTURE,
                locator="(file not present)",
                explanation=(
                    "The sanitized identity fixture is unavailable, so the raw "
                    "capture is confirmed but not cross-checked."
                ),
            )
        )

    facts.extend(
        (
            EvidenceFact(
                name="device.model",
                value=device_name,
                status="confirmed",
                source_file=_DEVICE_RAW,
                locator="/response/devicename",
                explanation=(
                    "Device model read from the captured unauthenticated "
                    "basic-information response; corroborated by the identity "
                    "fixture when present."
                ),
            ),
            EvidenceFact(
                name="device.product_family",
                value=product_family,
                status="confirmed",
                source_file=_DEVICE_RAW,
                locator="/response/productfamily",
                explanation=(
                    "Product family reported by the device; descriptive "
                    "identity only, not a band capability."
                ),
            ),
            EvidenceFact(
                name="device.classify",
                value=classify,
                status="confirmed",
                source_file=_DEVICE_RAW,
                locator="/response/classify",
                explanation="Device class reported by the device.",
            ),
            EvidenceFact(
                name="device.product_name",
                value=product_name,
                status="confirmed",
                source_file=_DEVICE_RAW,
                locator="/response/spreadname_en",
                explanation="Marketing product name reported by the device.",
            ),
        )
    )

    # -- Network identity --------------------------------------------------
    plmn_root = _load_xml(root_dir, _PLMN_RAW)
    assert plmn_root is not None
    if getattr(plmn_root, "tag", None) == "error":
        raise EvidenceExtractionError(
            f"{_PLMN_RAW} contains a gated error response, not PLMN data"
        )
    numeric = _child_text(plmn_root, "Numeric", _PLMN_RAW)
    rat = _child_text(plmn_root, "Rat", _PLMN_RAW)
    assert numeric is not None and rat is not None
    if not _PLMN_RE.fullmatch(numeric):
        raise EvidenceExtractionError(
            f"invalid PLMN {numeric!r} in {_PLMN_RAW}"
        )
    if not rat.isdigit() or not 0 <= int(rat) <= 255:
        raise EvidenceExtractionError(
            f"invalid RAT mode {rat!r} in {_PLMN_RAW}"
        )

    plmn_fixture = _load_xml(root_dir, _PLMN_FIXTURE, required=False)
    if plmn_fixture is not None:
        if getattr(plmn_fixture, "tag", None) == "error":
            raise EvidenceContradictionError(
                f"{_PLMN_FIXTURE} is an error response, not corroborating data"
            )
        _corroborate(
            "PLMN",
            numeric,
            _PLMN_RAW,
            _child_text(plmn_fixture, "Numeric", _PLMN_FIXTURE, required=False),
            _PLMN_FIXTURE,
        )
        _corroborate(
            "RAT mode",
            rat,
            _PLMN_RAW,
            _child_text(plmn_fixture, "Rat", _PLMN_FIXTURE, required=False),
            _PLMN_FIXTURE,
        )
    else:
        gaps.append(
            EvidenceGap(
                name="PLMN fixture corroboration",
                source_file=_PLMN_FIXTURE,
                locator="(file not present)",
                explanation=(
                    "The sanitized PLMN fixture is unavailable, so the raw "
                    "capture is confirmed but not cross-checked."
                ),
            )
        )

    facts.extend(
        (
            EvidenceFact(
                name="network.plmn",
                value=numeric,
                status="confirmed",
                source_file=_PLMN_RAW,
                locator="/response/Numeric",
                explanation=(
                    "Serving PLMN only. It identifies the current network, "
                    "not a band capability."
                ),
            ),
            EvidenceFact(
                name="network.rat_mode",
                value=rat,
                status="confirmed",
                source_file=_PLMN_RAW,
                locator="/response/Rat",
                explanation=(
                    "Rat 7 is the LTE+NR NSA mode on Huawei MBB firmware. It "
                    "proves the mode only, never a specific band combination."
                ),
            ),
        )
    )

    # -- Product feature flags --------------------------------------------
    switch_root = _load_xml(root_dir, _MODULE_SWITCH_RAW)
    assert switch_root is not None
    if getattr(switch_root, "tag", None) == "error":
        raise EvidenceExtractionError(
            f"{_MODULE_SWITCH_RAW} contains a gated error response, not feature flags"
        )
    for flag in _FEATURE_FLAGS:
        raw_value = _child_text(switch_root, flag, _MODULE_SWITCH_RAW)
        assert raw_value is not None
        value = _validate_flag(flag, raw_value, _MODULE_SWITCH_RAW)
        facts.append(
            EvidenceFact(
                name=f"feature.{flag}",
                value=value,
                status="confirmed",
                source_file=_MODULE_SWITCH_RAW,
                locator=f"/response/{flag}",
                explanation=(
                    "Product feature toggle. It does not prove any supported "
                    "LTE or NR band and is not used to gate ranking."
                ),
            )
        )

    # -- Historical context documented in the repository -----------------
    doc_text = _read_text(root_dir, _PHASE1_DOC)

    n78_line = _line_containing(doc_text, "n78")
    if n78_line is None:
        gaps.append(
            EvidenceGap(
                name="historical n78 observation",
                source_file=_PHASE1_DOC,
                locator="(no line containing n78)",
                explanation=(
                    "No repository document records an n78 observation, so no "
                    "NR band fact is emitted."
                ),
            )
        )
    else:
        number, _ = n78_line
        facts.append(
            EvidenceFact(
                name="band.nr.n78",
                value="n78",
                status="observed",
                source_file=_PHASE1_DOC,
                locator=f"line {number}",
                explanation=(
                    "Historical prior-session context only. No captured device "
                    "capability response exists, so n78 stays observed and is "
                    "never promoted to confirmed."
                ),
            )
        )

    # -- Operator label (JSON stub) --------------------------------------
    operator_path = root_dir / _OPERATOR_RAW
    if operator_path.is_file():
        operator_text = _read_text(root_dir, _OPERATOR_RAW)
        start = operator_text.find("{")
        if start < 0:
            raise EvidenceExtractionError(
                f"no JSON payload found in {_OPERATOR_RAW}"
            )
        try:
            payload = json.loads(operator_text[start:])
        except json.JSONDecodeError as exc:
            raise EvidenceExtractionError(
                f"malformed JSON evidence in {_OPERATOR_RAW}"
            ) from exc
        if not isinstance(payload, dict):
            raise EvidenceExtractionError(
                f"unexpected JSON payload in {_OPERATOR_RAW}"
            )
        operator_name = payload.get("OperatorName")
        if not isinstance(operator_name, str):
            raise EvidenceExtractionError(
                f"missing OperatorName field in {_OPERATOR_RAW}"
            )
        if operator_name.strip():
            facts.append(
                EvidenceFact(
                    name="network.operator_name",
                    value=operator_name.strip(),
                    status="observed",
                    source_file=_OPERATOR_RAW,
                    locator="/OperatorName",
                    explanation=(
                        "Operator label reported by an app endpoint; not "
                        "independently verified and not a capability."
                    ),
                )
            )
        else:
            gaps.append(
                EvidenceGap(
                    name="operator display name",
                    source_file=_OPERATOR_RAW,
                    locator="/OperatorName",
                    explanation=(
                        "The sanitized capture contains an empty OperatorName, "
                        "so the display name is unavailable."
                    ),
                )
            )
    else:
        gaps.append(
            EvidenceGap(
                name="operator display name",
                source_file=_OPERATOR_RAW,
                locator="(file not present)",
                explanation="No operator-info capture is available.",
            )
        )

    # -- Gated / stub responses -------------------------------------------
    for relative_path, label in _GATED_SOURCES:
        gated_root = _load_xml(root_dir, relative_path, required=False)
        if gated_root is None:
            gaps.append(
                EvidenceGap(
                    name=f"data source: {label}",
                    source_file=relative_path,
                    locator="(file not present)",
                    explanation=(
                        "No local capture exists for this data source, so it is "
                        "unavailable and never treated as band evidence."
                    ),
                )
            )
            continue
        tag = getattr(gated_root, "tag", None)
        if tag == "error":
            code = _error_code(gated_root, relative_path)
            gaps.append(
                EvidenceGap(
                    name=f"data source: {label}",
                    source_file=relative_path,
                    locator="/error/code",
                    explanation=(
                        f"Gated/stub response code {code}. This records an "
                        "unavailable data source only, never a supported band."
                    ),
                )
            )
        else:
            gaps.append(
                EvidenceGap(
                    name=f"data source: {label}",
                    source_file=relative_path,
                    locator=f"/{tag}",
                    explanation=(
                        "A response is present but its schema is not verified "
                        "offline; it is not parsed as band capability evidence."
                    ),
                )
            )

    # -- Band capability captures ----------------------------------------
    for label, relative_path in _BAND_CAPTURE_SOURCES:
        path = root_dir / relative_path
        if path.is_file():
            gaps.append(
                EvidenceGap(
                    name=f"band capability: {label}",
                    source_file=relative_path,
                    locator="(file present)",
                    explanation=(
                        "A local capture exists but its response schema has not "
                        "been verified offline, so it is not parsed and never "
                        "treated as confirmed band capability."
                    ),
                )
            )
        else:
            gaps.append(
                EvidenceGap(
                    name=f"band capability: {label}",
                    source_file=relative_path,
                    locator="(file not present)",
                    explanation=(
                        "No local capture exists. Band capability remains "
                        "unavailable; no band is invented."
                    ),
                )
            )

    return DeviceEvidence(facts=tuple(facts), gaps=tuple(gaps))


def _confirmed_value(evidence: DeviceEvidence, name: str) -> str | None:
    fact = evidence.fact(name)
    if fact is None:
        return None
    if not fact.confirmed:
        raise EvidenceValidationError(
            f"{name} is observed, not confirmed; it cannot be used as identity data"
        )
    return fact.value


def build_profile_from_evidence(evidence: DeviceEvidence) -> DeviceBandProfile:
    """Build a validated profile from extracted facts, keeping statuses separate.

    Only ``band.*`` facts become band slots, and an observed fact can never
    become a confirmed slot. Bands absent from the evidence remain unavailable
    for ranking.
    """
    if not isinstance(evidence, DeviceEvidence):
        raise TypeError("evidence must be a DeviceEvidence")

    device_name = _confirmed_value(evidence, "device.model")
    if device_name is None:
        raise EvidenceValidationError(
            "cannot build a profile without a confirmed device.model fact"
        )

    plmn = _confirmed_value(evidence, "network.plmn")
    if plmn is not None and not _PLMN_RE.fullmatch(plmn):
        raise EvidenceValidationError(f"invalid PLMN in evidence: {plmn!r}")

    rat_value = _confirmed_value(evidence, "network.rat_mode")
    rat_mode: int | None = None
    if rat_value is not None:
        if not rat_value.isdigit() or not 0 <= int(rat_value) <= 255:
            raise EvidenceValidationError(
                f"invalid RAT mode in evidence: {rat_value!r}"
            )
        rat_mode = int(rat_value)

    slots: list[BandSlot] = []
    seen: dict[tuple[str, str], BandSlot] = {}
    for fact in evidence.facts:
        if not fact.name.startswith("band."):
            continue
        parts = fact.name.split(".")
        if len(parts) != 3:
            raise EvidenceValidationError(
                f"malformed band fact name {fact.name!r}; expected band.<rat>.<band>"
            )
        _, rat, band = parts
        try:
            slot = BandSlot(
                rat=rat,
                band=band,
                evidence_source=f"{fact.source_file} ({fact.locator})",
                evidence_description=fact.explanation,
                capability=fact.status,
            )
        except BestPairValidationError as exc:
            raise EvidenceValidationError(
                f"invalid band evidence fact {fact.name!r}: {exc}"
            ) from exc
        if fact.value.strip().lower() != slot.band.lower():
            raise EvidenceValidationError(
                f"band fact {fact.name!r} has value {fact.value!r} that does "
                f"not match its canonical band {slot.band!r}"
            )
        key = (slot.rat, slot.band)
        previous = seen.get(key)
        if previous is not None:
            if previous.capability != slot.capability:
                raise EvidenceContradictionError(
                    f"contradictory capability evidence for {slot.rat} {slot.band}: "
                    f"{previous.capability} vs {slot.capability}"
                )
            raise EvidenceContradictionError(
                f"duplicate band evidence for {slot.rat} {slot.band}"
            )
        seen[key] = slot
        slots.append(slot)

    confirmed_count = sum(1 for slot in slots if slot.confirmed)
    observed_count = len(slots) - confirmed_count
    if confirmed_count:
        band_summary = (
            f"{confirmed_count} confirmed band slot(s) and "
            f"{observed_count} observed band slot(s) were extracted."
        )
    else:
        band_summary = (
            "No confirmed band slot was extracted. No LTE or NR band is "
            "invented, so no band is eligible for ranking or pairing."
        )

    notes = (
        f"{band_summary} Feature flags are product toggles, not band "
        "capabilities. Rat 7 proves the LTE+NR NSA mode only, never specific "
        "band combinations. Observed facts are retained for transparency and "
        "are never promoted automatically."
    )

    try:
        return DeviceBandProfile(
            device_name=device_name,
            slots=tuple(slots),
            plmn=plmn,
            rat_mode=rat_mode,
            notes=notes,
        )
    except BestPairValidationError as exc:
        raise EvidenceValidationError(
            f"extracted evidence does not form a valid profile: {exc}"
        ) from exc


def repository_device_profile(
    repo_root: Path | str | None = None,
) -> DeviceBandProfile:
    """Collect local evidence and build its device profile in one step."""
    return build_profile_from_evidence(collect_device_facts(repo_root))

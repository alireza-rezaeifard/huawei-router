"""Offline static analysis of locally held firmware JavaScript evidence.

Scope guarantees (Phase 5):

- Reads ONLY the local files the caller explicitly passes in. No network,
  no sockets, no subprocess, no execution of the analyzed content: a plain
  ``bytes``-read + ``utf-8`` decode + documented regular-expression passes.
- Never writes to, renames, or deletes any input file.
- This is NOT a semantic/AST analyzer: the firmware bundles are minified
  single-line webpack outputs, so every finding is labeled ``candidate``
  (a string/identifier is present in the text) or ``unverified`` (a write
  HTTP method call is present). String presence is never treated as
  firmware truth; behavior claims require separate evidence.

Extraction kinds
----------------
endpoint               string literals under /api/, /config/, /html/, /js/,
                       /lib/, /css/ (candidate)
write_method_call      ``.post(``/``.put(``/``.delete(``/``.patch(``/
                       ``.request(`` invocation sites (unverified — the
                       target URL is usually in a different part of the
                       minified line)
auth_symbol            SCRAM/PBKDF2/HMAC identifier mentions (candidate)
session_material       token/cookie/CSRF identifier mentions (candidate);
                       only NAMES are captured, values never appear in
                       findings
module_ref             webpack/require/localStorage storage-name references
                       (candidate — storage names may look like secrets and
                       are therefore redacted defensively)
management_candidate   endpoint/operation names associated with scanning,
                       cell/band locking, registration or diagnostics
                       (candidate — presence is NOT proof of any operation)

All findings are redacted through :func:`huawei_tower.modem.security.
redact_secrets` plus a standalone opaque-string filter so no credential,
token, cookie, or key material can reach a report.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .security import redact_secrets

MAX_INPUT_BYTES = 32 * 1024 * 1024


class AnalysisInputError(ValueError):
    """Raised for invalid analysis input (fail-closed, no partial output)."""


@dataclass(frozen=True)
class Ref:
    file: str
    line: int
    offset: int


@dataclass
class Finding:
    kind: str
    value: str
    confidence: str
    refs: list[Ref] = field(default_factory=list)


# Documented regex passes. Each is a presence check on raw text only.
_PATTERN_ENDPOINT = (
    r'''["'](/(?:api|config|html|js|lib|css)/[A-Za-z0-9_.\-/]{1,120})["']'''
)
_PATTERN_WRITE_METHOD = r"\.(post|put|delete|patch|request)\s*\("
_PATTERN_AUTH = (
    r"\b(SCRAM|challenge_login|authentication_login|firstnonce|servernonce"
    r"|finalnonce|clientproof|serversignature|rsapubkeysig\w*|rsan|rsae"
    r"|PBKDF2|HmacSHA256|clientKey|serverKey|storedKey)\b"
)
_PATTERN_SESSION = (
    r"\b(RequestVerificationToken\w*|SesInfo|TokInfo|SessionID|Update-Cookie"
    r"|csrf_token|token\b\.substr|localStorage\b)\b"
)
_PATTERN_MODULE = (
    r"(webpackJsonp|__webpack_require__|require\s*\(|importScripts"
    r"|window\.webpackChunk\w*|i\.p\s*=)"
)
_PATTERN_MANAGEMENT = (
    r"\b(best-signal-position|best-position-status|best-position-result"
    r"|external-best-signal-position|onekey_diag|celllock|lock-freq|net-mode"
    r"|plmn-list|handle-cell|reconnect|mobilesearch|networkmode)\b"
)
_PATTERN_OPAQUE = (
    # Long hex or base64-ish standalone tokens are never reported verbatim.
    r"\b[0-9a-fA-F]{16,}\b|\b[A-Za-z0-9+/]{28,}={0,2}\b"
)

CONFIDENCE_BY_KIND = {
    "endpoint": "candidate",
    "write_method_call": "unverified",
    "auth_symbol": "candidate",
    "session_material": "candidate",
    "module_ref": "candidate",
    "management_candidate": "candidate",
}

_PATTERNS: dict[str, re.Pattern[str]] = {
    "endpoint": re.compile(_PATTERN_ENDPOINT),
    "write_method_call": re.compile(_PATTERN_WRITE_METHOD),
    "auth_symbol": re.compile(_PATTERN_AUTH),
    "session_material": re.compile(_PATTERN_SESSION),
    "module_ref": re.compile(_PATTERN_MODULE),
    "management_candidate": re.compile(_PATTERN_MANAGEMENT),
}

# Standalone opaque strings (long hex/base64 material) never appear verbatim.
_REDACT_OPAQUE = re.compile(_PATTERN_OPAQUE)


def _sanitize(value: str) -> str:
    return _REDACT_OPAQUE.sub("<redacted>", redact_secrets(value))


def _validate_and_read(
    path: str | Path,
    *,
    encoding_mode: str = "strict",
) -> tuple[str, bytes, str, str]:
    """Load one explicit local file; fail closed on any problem.

    ``encoding_mode='strict'`` (default) rejects non-UTF-8 bytes. The
    opt-in ``'replace'`` mode decodes with ``errors='replace'`` for minified
    firmware bundles that contain stray non-UTF-8 bytes; the replacement is
    then reported in the file metadata so results from such files can be
    weighed accordingly. Neither mode ever writes to the input.
    """
    file_path = Path(path)
    if not file_path.exists() or file_path.is_dir():
        raise AnalysisInputError(f"analysis input must be an existing file: {file_path}")
    size = file_path.stat().st_size
    if size == 0:
        raise AnalysisInputError(f"analysis input is empty: {file_path}")
    if size > MAX_INPUT_BYTES:
        raise AnalysisInputError(
            f"analysis input exceeds the {MAX_INPUT_BYTES} byte limit: {file_path}"
        )
    raw = file_path.read_bytes()
    if encoding_mode == "strict":
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AnalysisInputError(
                f"analysis input is not valid UTF-8: {file_path}"
            ) from exc
        encoding = "utf-8"
    elif encoding_mode == "replace":
        text = raw.decode("utf-8", errors="replace")
        encoding = "utf-8-errors=replace"
    else:
        raise AnalysisInputError(f"unknown encoding_mode: {encoding_mode!r}")
    return text, raw, str(file_path), encoding


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


def analyze_files(
    paths: Iterable[str | Path],
    *,
    encoding_mode: str = "strict",
) -> dict:
    """Static analysis of explicit local files; returns a JSON-ready report.

    Inputs are read once each; findings deduplicate per (kind, value) and
    accumulate file:line:offset references. No network I/O is possible: the
    only filesystem operation is reading the files the caller names.
    ``encoding_mode`` is passed to :func:`_validate_and_read` (strict by
    default; ``'replace'`` documented for bundles with stray bytes).
    """
    findings: dict[tuple[str, str], Finding] = {}
    files_meta: list[dict[str, object]] = []

    for path in paths:
        text, raw, name, encoding = _validate_and_read(path, encoding_mode=encoding_mode)
        digest = hashlib.sha256(raw).hexdigest()
        files_meta.append(
            {
                "file": name,
                "bytes": len(raw),
                "sha256": digest,
                "encoding": encoding,
                "lines": text.count("\n") + 1,
            }
        )
        starts = _line_starts(text)

        for kind, pattern in _PATTERNS.items():
            confidence = CONFIDENCE_BY_KIND[kind]
            for match in pattern.finditer(text):
                group = match.group(1) if match.groups() else match.group(0)
                value = _sanitize(group.strip())
                if not value or "<redacted>" == value:
                    continue
                offset = match.start()
                line = bisect.bisect_right(starts, offset)
                ref = Ref(file=name, line=line, offset=offset)
                key = (kind, value)
                entry = findings.get(key)
                if entry is None:
                    entry = Finding(kind=kind, value=value, confidence=confidence)
                    findings[key] = entry
                entry.refs.append(ref)

    grouped: dict[str, list[dict[str, object]]] = {}
    for (kind, _), finding in sorted(findings.items(), key=lambda item: item[0][1]):
        grouped.setdefault(kind, []).append(
            {
                "value": finding.value,
                "confidence": finding.confidence,
                "refs": [
                    {"file": r.file, "line": r.line, "offset": r.offset}
                    for r in finding.refs
                ],
            }
        )

    return {
        "meta": {
            "tool": "huawei_tower.modem.jsanalysis (offline static string analysis)",
            "disclaimer": (
                "Every finding is string/identifier presence only ('candidate' "
                "or 'unverified'); it is NOT proof of firmware behavior. "
                "Minified bundles concentrate many statements on few lines, "
                "so refs are file+line+byte-offset, not logical statements."
            ),
            "input_files": files_meta,
        },
        "findings": grouped,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def to_markdown(report: dict) -> str:
    """Human-readable rendering for review documents."""
    meta = report["meta"]
    lines: list[str] = [
        "# Offline JS static-analysis report",
        "",
        "> Generated by `huawei_tower.modem.jsanalysis`. **Every finding is",
        "> `candidate`/`unverified` string presence, never firmware truth.**",
        "",
        "## Input files",
        "",
        "| file | bytes | lines | sha256 |",
        "|---|---|---|---|",
    ]
    for f in meta["input_files"]:
        lines.append(f'| `{f["file"]}` | {f["bytes"]} | {f["lines"]} | `{f["sha256"][:16]}…` |')
    lines += ["", "## Findings", ""]
    kinds = report["findings"]
    if not kinds:
        lines.append("_No findings._")
    for kind, entries in kinds.items():
        confidence = entries[0]["confidence"] if entries else "-"
        lines.append(f"### `{kind}` — confidence: **{confidence}** ({len(entries)} unique values)")
        lines.append("")
        for entry in entries:
            refs = ", ".join(
                f"`{r['file'].split('/')[-1].split(chr(92))[-1]}:{r['line']}@{r['offset']}`"
                for r in entry["refs"][:6]
            )
            more = "" if len(entry["refs"]) <= 6 else f" (+{len(entry['refs']) - 6} more)"
            lines.append(f"- `{entry['value']}` — {refs}{more}")
        lines.append("")
    return "\n".join(lines)

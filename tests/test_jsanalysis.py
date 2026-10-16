from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from huawei_tower.modem.jsanalysis import (
    AnalysisInputError,
    MAX_INPUT_BYTES,
    analyze_files,
    to_markdown,
)

MINIFIED_EXAMPLE = (
    'var e=function(){var t=axios;t.get("/api/monitoring/status");'
    't.post("/api/user/challenge_login",{firstnonce:e});'
    'localStorage.setItem("n",v);window.webpackChunk.push;};'
)


@pytest.fixture()
def js_file(tmp_path: Path) -> Path:
    f = tmp_path / "sample.js"
    f.write_text(MINIFIED_EXAMPLE, encoding="utf-8", newline="\n")
    return f


def _report_for(tmp_path: Path, content: str) -> dict:
    f = tmp_path / "probe.js"
    f.write_text(content, encoding="utf-8", newline="\n")
    return analyze_files([f])


def test_extracts_endpoints_with_refs(js_file: Path):
    report = analyze_files([js_file])
    endpoints = {f["value"]: f for f in report["findings"]["endpoint"]}
    assert "/api/monitoring/status" in endpoints
    assert "/api/user/challenge_login" in endpoints
    entry = endpoints["/api/user/challenge_login"]
    assert entry["confidence"] == "candidate"
    ref = entry["refs"][0]
    assert ref["file"] == str(js_file)
    assert ref["line"] == 1  # minified single-line bundle
    assert ref["offset"] == MINIFIED_EXAMPLE.find('"/api/user/challenge_login"')


def test_write_method_call_labeled_unverified(js_file: Path):
    report = analyze_files([js_file])
    writes = {f["value"] for f in report["findings"]["write_method_call"]}
    assert writes == {"post"}


def test_auth_symbols_extracted(js_file: Path):
    report = analyze_files([js_file])
    symbols = {f["value"] for f in report["findings"]["auth_symbol"]}
    assert "firstnonce" in symbols
    assert "challenge_login" in symbols


def test_module_refs_and_localstorage_captured(js_file: Path):
    report = analyze_files([js_file])
    modules = {f["value"] for f in report["findings"]["module_ref"]}
    session = {f["value"] for f in report["findings"]["session_material"]}
    joined = " ".join(modules | session)
    assert "webpackChunk" in joined
    assert "localStorage" in joined


def test_secrets_are_redacted_in_findings(tmp_path: Path):
    report = _report_for(
        tmp_path,
        't.post("/api/user/login",{password:"hunter2",salt:'
        '"00112233445566778899aabbccddeeff"});',
    )
    blob = to_markdown(report)
    assert "hunter2" not in blob
    assert "00112233" not in blob
    assert "endpoint" in blob


def test_invalid_path_rejected_fail_closed(tmp_path: Path):
    with pytest.raises(AnalysisInputError):
        analyze_files([tmp_path / "definitely_missing.js"])
    with pytest.raises(AnalysisInputError):
        analyze_files([tmp_path])  # a directory, not a file


def test_empty_file_rejected_fail_closed(tmp_path: Path):
    f = tmp_path / "empty.js"
    f.write_bytes(b"")
    with pytest.raises(AnalysisInputError, match="empty"):
        analyze_files([f])


def test_invalid_encoding_rejected_fail_closed(tmp_path: Path):
    f = tmp_path / "binary.js"
    f.write_bytes(b"\xff\xfe\x00\x81invalid-utf8")
    with pytest.raises(AnalysisInputError, match="UTF-8"):
        analyze_files([f])


def test_oversize_file_rejected_fail_closed(tmp_path: Path, monkeypatch):
    f = tmp_path / "big.js"
    f.write_bytes(b"x" * 1024)
    monkeypatch.setattr("huawei_tower.modem.jsanalysis.MAX_INPUT_BYTES", 512)
    with pytest.raises(AnalysisInputError, match="exceeds"):
        analyze_files([f])


def test_input_files_are_never_modified(js_file: Path):
    before = js_file.read_bytes()
    before_stat = js_file.stat().st_mtime_ns
    analyze_files([js_file])
    assert js_file.read_bytes() == before
    assert js_file.stat().st_mtime_ns == before_stat


def test_report_digest_matches_actual_content(js_file: Path):
    report = analyze_files([js_file])
    meta = report["meta"]["input_files"][0]
    assert meta["sha256"] == hashlib.sha256(js_file.read_bytes()).hexdigest()
    assert meta["bytes"] == len(js_file.read_bytes())


def test_disable_network_and_produce_markdown_disclaimer(js_file: Path):
    report = analyze_files([js_file])
    md = to_markdown(report)
    assert "never firmware truth" in md
    assert "candidate" in md


def test_empty_findings_produce_empty_report(tmp_path: Path):
    report = _report_for(tmp_path, "var a = 1;\nvar b = 'plain string';\n")
    assert all(not entries for entries in report["findings"].values())
    assert "_No findings._" in to_markdown(report)


def test_line_numbers_across_multiple_lines(tmp_path: Path):
    content = 'var a = 1;\n// nothing\nvar c = axios.get("/api/pin/status");'
    report = _report_for(tmp_path, content)
    entry = {f["value"]: f for f in report["findings"]["endpoint"]}["/api/pin/status"]
    assert entry["refs"][0]["line"] == 3
    assert entry["refs"][0]["offset"] == content.find('"/api/pin/status"')


def test_module_never_imports_network_libraries():
    import inspect

    from huawei_tower.modem import jsanalysis

    source = inspect.getsource(jsanalysis)
    for banned in ("import requests", "import socket", "urllib", "httpx"):
        assert banned not in source


def test_replace_mode_is_explicit_and_lost_bytes_are_noted(tmp_path: Path):
    f = tmp_path / "lossy.js"
    f.write_bytes(b't.post("/api/net/lock-freq");\xff\xee')
    report = analyze_files([f], encoding_mode="replace")
    assert report["meta"]["input_files"][0]["encoding"] == "utf-8-errors=replace"
    assert any(
        f["value"] == "/api/net/lock-freq" for f in report["findings"]["endpoint"]
    )


def test_real_evidence_is_readable_and_unmodified_offline():
    """Run the analyzer against the actual in-repo evidence (read-only).

    This is the end-to-end guarantee that the tool works on real minified
    firmware bundles without touching them. Uses the documented
    ``encoding_mode='replace'`` because the in-repo bundles contain stray
    non-UTF-8 bytes (their metadata notes this). Skips harmlessly if the
    evidence directory is absent (fresh checkout).
    """
    evidence = Path(__file__).resolve().parents[1] / "evidence" / "raw"
    js_files = sorted(
        p
        for p in evidence.glob("*")
        if p.is_file()
        and (
            p.suffix in {".js", ".html"}
            or p.name.startswith(("js__", "lib_", "chunk_"))
        )
    )
    if not js_files:
        pytest.skip("no local evidence files present")
    snapshots = {p: p.read_bytes() for p in js_files}
    report = analyze_files(js_files, encoding_mode="replace")
    for path, data in snapshots.items():
        assert path.read_bytes() == data, f"evidence modified: {path}"
    assert report["meta"]["input_files"]
    # The analyzer must find familiar firmware symbols in the real bundles.
    md = to_markdown(report)
    assert "challenge_login" in md or "SCRAM" in md

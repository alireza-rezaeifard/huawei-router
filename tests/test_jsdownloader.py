from __future__ import annotations

from pathlib import Path

import pytest

from huawei_tower.modem.errors import ModemHTTPError
from huawei_tower.modem.jsdownloader import (
    APPROVED_ASSETS,
    AssetDownloadError,
    AuthenticatedDownloadAuthorization,
    JSAssetDownloader,
)


class StubResponse:
    def __init__(self, status_code: int = 200, body: bytes = b"", headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    def iter_content(self, chunk_size: int):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i: i + chunk_size]


class StubSession:
    """Offline stand-in for requests.Session (no sockets involved)."""

    def __init__(self, response: StubResponse | None = None):
        self.headers = {}
        self.calls: list[tuple[str, dict]] = []
        self._response = response if response is not None else StubResponse(200, b".js body")

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        return self._response

    def close(self):
        pass


@pytest.fixture()
def dest(tmp_path: Path) -> Path:
    out = tmp_path / "evidence_downloads"
    out.mkdir()
    return out


def test_approved_list_is_finite_and_dot_only():
    assert len(APPROVED_ASSETS) > 0
    for path, asset in APPROVED_ASSETS.items():
        assert path.startswith("/js/") or path.startswith("/lib/") or path == "/html/index.html"
        assert asset.category in {"ui_core", "library", "admin_chunk", "page"}
        assert asset.path == path


def test_plan_contains_destinations_under_dest_dir(dest: Path):
    dl = JSAssetDownloader("https://192.168.70.1", dest, dry_run=True)
    plan = dl.plan()
    assert plan
    for path, target in plan:
        assert str(target).startswith(str(dest))


def test_dry_run_makes_no_network_calls_and_writes_nothing(dest: Path):
    session = StubSession()
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session, dry_run=True)
    result = dl.fetch("/js/main.js")
    assert result is None
    assert session.calls == []
    assert not list(dest.iterdir())


def test_unapproved_path_is_rejected_before_any_network_call(dest: Path):
    session = StubSession()
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    for bad in ("/js/evil.js", "/api/secret", "/index.js", "", "/js/../etc/passwd.js"):
        with pytest.raises(AssetDownloadError):
            dl.fetch(bad)
    assert session.calls == []
    assert not list(dest.iterdir())


def test_admin_chunks_blocked_without_approved_authentication(dest: Path):
    session = StubSession()
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    admin_paths = [
        path
        for path, asset in APPROVED_ASSETS.items()
        if asset.requires_authenticated_session
    ]
    assert admin_paths, "approved list must still gate its admin chunks"
    for path in admin_paths:
        with pytest.raises(AssetDownloadError):
            dl.fetch(path)
    assert session.calls == []
    assert not list(dest.iterdir())


AUTH_ASSET = "/js/lockband.js"  # one of the admin chunks (offline stubs only)


def test_admin_chunk_rejected_even_after_failed_stale_state_spoof(dest: Path):
    """Old class attribute cannot be resurrected to open the gate."""
    session = StubSession()
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    dl.__dict__["authenticated_allowed"] = True
    with pytest.raises(AssetDownloadError):
        dl.fetch(AUTH_ASSET)
    assert session.calls == []


def test_admin_chunk_authorization_wrong_type_rejected_before_io(dest: Path):
    session = StubSession()
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    for fake in (True, "yes", object(), ("approved",), None):
        with pytest.raises(AssetDownloadError):
            dl.fetch(AUTH_ASSET, authorization=fake)
    assert session.calls == []
    assert not list(dest.iterdir())


def test_authorization_scoped_to_other_path_rejected_before_io(dest: Path):
    session = StubSession()
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    other = AuthenticatedDownloadAuthorization(
        approved_path="/js/celllock-celllock-vue.js",
        operator="reviewer",
        reason="authorization for an unrelated chunk",
    )
    with pytest.raises(AssetDownloadError):
        dl.fetch(AUTH_ASSET, authorization=other)
    assert session.calls == []


def test_invalid_authorization_construction_rejected(dest: Path):
    with pytest.raises(ValueError):
        AuthenticatedDownloadAuthorization(
            approved_path="/js/login.js",  # not an auth-required asset
            operator="reviewer",
            reason="x",
        )
    with pytest.raises(ValueError):
        AuthenticatedDownloadAuthorization(approved_path=AUTH_ASSET, operator="", reason="x")
    with pytest.raises(ValueError):
        AuthenticatedDownloadAuthorization(approved_path=AUTH_ASSET, operator="op", reason="  ")
    with pytest.raises(ValueError):
        AuthenticatedDownloadAuthorization(approved_path="/js/does/not/exist.js", operator="op", reason="x")


def test_valid_authorization_allows_offline_mocked_download_only(dest: Path):
    """Positive gate mechanic — StubSession only, never a live fetch."""
    session = StubSession(StubResponse(200, b"// offline mocked test body"))
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    auth = AuthenticatedDownloadAuthorization(
        approved_path=AUTH_ASSET,
        operator="offline-test",
        reason="unit test of the authorization mechanic; no network I/O",
    )
    stored = dl.fetch(AUTH_ASSET, authorization=auth)
    assert stored is not None
    assert stored.read_bytes() == b"// offline mocked test body"
    url, kwargs = session.calls[0]
    assert url == "https://192.168.70.1" + AUTH_ASSET
    assert kwargs["allow_redirects"] is False
    assert kwargs["verify"] is True


def test_download_gate_does_not_default_authorization(dest: Path):
    """The downloader must never synthesize an authorization itself."""
    session = StubSession()
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session, dry_run=True)
    with pytest.raises(AssetDownloadError):
        dl.fetch(AUTH_ASSET)


def test_redirects_are_refused(dest: Path):
    session = StubSession(StubResponse(307, b""))
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    with pytest.raises(AssetDownloadError):
        dl.fetch("/js/login.js")
    stored = list(dest.iterdir())
    assert stored == []


def test_http_error_statuses_raise(dest: Path):
    for status in (199, 201, 400, 401, 404, 500, 503):
        session = StubSession(StubResponse(status, b""))
        dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
        with pytest.raises(ModemHTTPError):
            dl.fetch("/js/login.js")


def test_huawei_xml_error_body_is_not_stored_as_asset(dest: Path):
    xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n<error><code>100003</code>'
        b"<message/></error>"
    )
    session = StubSession(StubResponse(200, xml))
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    with pytest.raises(AssetDownloadError):
        dl.fetch("/js/login.js")
    assert not list(dest.iterdir())


def test_oversized_response_is_refused_and_not_stored(dest: Path):
    session = StubSession(StubResponse(200, b"x" * (9 * 1024 * 1024)))
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session, max_asset_bytes=1024)
    with pytest.raises(AssetDownloadError):
        dl.fetch("/js/login.js")
    assert not list(dest.iterdir())


def test_successful_download_stores_exact_bytes_and_records_one_get_only_call(dest: Path):
    body = b"window.webpackJsonp=(window.webpackJsonp||[]).push([[5],{}]);"
    session = StubSession(StubResponse(200, body))
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    dest_file = dl.fetch("/js/login.js")
    assert dest_file is not None
    assert dest_file.read_bytes() == body
    assert len(session.calls) == 1
    url, kwargs = session.calls[0]
    assert url == "https://192.168.70.1/js/login.js"
    assert kwargs["allow_redirects"] is False
    assert url.startswith("https://192.168.70.1/")


def test_bad_base_url_rejected(dest: Path):
    for bad_url in ("http://192.168.70.1", "https:", "plain-host"):
        with pytest.raises(ValueError):
            JSAssetDownloader(bad_url, dest)


def test_tls_verification_cannot_be_disabled(dest: Path):
    session = StubSession()
    for bad in (False, None, 1, 0, ""):
        with pytest.raises(ValueError):
            JSAssetDownloader("https://192.168.70.1", dest, session=session, verify_tls=bad)
    assert session.calls == []


def test_tls_missing_ca_bundle_rejected_before_any_io(dest: Path, tmp_path: Path):
    session = StubSession()
    missing = tmp_path / "missing_ca.pem"
    with pytest.raises(ValueError):
        JSAssetDownloader("https://192.168.70.1", dest, session=session, verify_tls=str(missing))
    assert session.calls == []


def test_tls_ca_bundle_forwarded_without_disabling_verification(dest: Path, tmp_path: Path):
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    session = StubSession(StubResponse(200, b".js"))
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session, verify_tls=str(ca))
    dl.fetch("/js/login.js")
    forwarded = session.calls[0][1]["verify"]
    assert forwarded == str(ca.resolve())
    assert forwarded is not False


def test_session_without_get_rejects_early(dest: Path):
    dl = JSAssetDownloader("https://192.168.70.1", dest, dry_run=True)
    # plan() must not require a session
    dl.plan()

"""Phase 7 hardening tests — offline only, mocks and synthetic bytes.

Closes the gaps documented in docs/PHASE6_API_RISK_AUDIT.md §5:
G-1 (connect/trace verbs), G-2 (query/fragment rejection), G-3 (timeout
forwarding), G-4 (bounded streaming response read), G-5 (error-text
hygiene), G-6 (no response logging), plus the Phase 7 reclassification of
the two bootstrap endpoints and downloader temp-file determinism extras.

No test here (or anywhere in the suite) contacts any network: conftest.py
denies sockets and DNS for every test without an explicit ``network``
marker, and none exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import requests

from huawei_tower.modem.api import (
    FORBIDDEN_PATHS,
    GATED_GET_ENDPOINTS,
    SAFE_GET_ENDPOINTS,
    ReadOnlyModemClient,
)
from huawei_tower.modem.errors import ModemHTTPError, UnsafeOperationError


class RecordingResponse:
    """Synthetic streaming response faithful to the requests public contract.

    Implements the same ``content``/``_content``/``_content_consumed``
    caching protocol as ``requests.models.Response`` (pinned version
    contract, verified against requests 2.34.2:
    ``_content is False`` == not read yet; ``_content_consumed`` with an
    unread ``_content`` raises RuntimeError like requests does), so tests
    exercise what a REAL response would do — including proving that the
    client's cache publication prevents any re-read from the closed stream.
    """

    def __init__(self=None, status_code=200, body=b"", *, fail_after=None):
        self.status_code = status_code
        self._body = body
        self._fail_after = fail_after
        self.headers = {"Set-Cookie": "SessionID=SYNTHETIC-FAKE-VALUE"}
        self.closed = False
        self.iterated = False
        self.iteration_count = 0
        self.encoding = None
        self._content = False
        self._content_consumed = False

    def iter_content(self, chunk_size: int):
        self.iterated = True
        self.iteration_count += 1
        if self._fail_after is not None:
            yield self._body[: self._fail_after]
            raise requests.exceptions.ChunkedEncodingError("simulated drop")
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i: i + chunk_size]

    def close(self):
        self.closed = True

    @property
    def content(self) -> bytes:
        if self._content is False:
            if self._content_consumed:
                raise RuntimeError(
                    "The content for this response was already consumed"
                )
            self._content = b"".join(self.iter_content(65536)) or b""
        self._content_consumed = True
        return self._content

    @property
    def text(self) -> str:
        if not self.content:
            return ""
        return self.content.decode(self.encoding or "utf-8", errors="replace")


class RecordingSession:
    def __init__(self, response):
        self.headers = {}
        self.calls: list[tuple[tuple, dict]] = []
        self._response = response

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self._response

    def close(self):
        pass


def _client(session, **kw) -> ReadOnlyModemClient:
    return ReadOnlyModemClient(session=session, **kw)


# ---------------------------------------------------------------- G-1/verbs


def test_all_nine_write_and_unknown_verbs_blocked_fail_closed():
    session = RecordingSession(RecordingResponse(200, b"ok"))
    client = _client(session)
    for verb in (
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
        "connect",
        "trace",
    ):
        with pytest.raises(UnsafeOperationError, match="does not support"):
            getattr(client, verb)
    assert session.calls == [], "verb attempts must fail before any request"


def test_connect_and_trace_added_to_blocked_method_tuple():
    from huawei_tower.modem.api import _WRITE_METHODS

    assert "connect" in _WRITE_METHODS and "trace" in _WRITE_METHODS
    assert len(set(_WRITE_METHODS)) == len(_WRITE_METHODS)


# ------------------------------------------------- G-2 query/fragment paths


def test_query_strings_and_fragments_never_match_the_allowlist():
    session = RecordingSession(RecordingResponse(200, b"ok"))
    client = _client(session)
    approved = "/api/device/basic_information"
    for mutated in (
        approved + "?x=1",
        approved + "?x=1#f",
        approved + "#details",
        approved + "?",
        "/api/monitoring/check-notifications?keepalive=1",
    ):
        with pytest.raises(UnsafeOperationError, match="approved allowlist|Blocked endpoint"):
            client.get(mutated)
    assert session.calls == []


def test_query_string_on_bootstrap_entry_is_rejected_too():
    # Whether or not the base path is on any list, mutations are rejected.
    session = RecordingSession(RecordingResponse(200, b"ok"))
    client = _client(session)
    with pytest.raises(UnsafeOperationError):
        client.get("/api/webserver/SesTokInfo?q=1")
    assert session.calls == []


# --------------------------------------------------------------- G-3 timeouts


def test_default_timeout_is_forwarded_per_request():
    session = RecordingSession(RecordingResponse(200, b"ok"))
    client = _client(session)
    client.get("/api/device/basic_information")
    assert session.calls[0][1]["timeout"] == client.timeout == 8.0


def test_custom_timeout_is_forwarded_per_request():
    session = RecordingSession(RecordingResponse(200, b"ok"))
    client = _client(session, timeout=3.5)
    client.get("/api/device/basic_information")
    assert session.calls[0][1]["timeout"] == 3.5


def test_streaming_mode_is_declared_on_every_request():
    session = RecordingSession(RecordingResponse(200, b"ok"))
    client = _client(session)
    client.get("/api/device/basic_information")
    assert session.calls[0][1]["stream"] is True
    assert session.calls[0][1]["allow_redirects"] is False


# ------------------------------------------------------- G-4 bounded reads


def test_normal_size_response_materialized_as_before():
    body = b"<response><ok>1</ok></response>"
    response = RecordingResponse(200, body)
    client = _client(RecordingSession(response))
    result = client.get("/api/device/basic_information")
    assert result.status_code == 200
    # PUBLIC requests API: content/text must come from the cache published
    # by the client; neither access may re-read the closed stream.
    consumed_before = response.iteration_count
    assert result.content == body
    assert result.text == body.decode("utf-8")
    assert response.iteration_count == consumed_before, (
        "public content/text access must NOT re-read the closed stream"
    )
    assert response.closed
    assert response.iterated, "the bounded reader consumed the stream itself"


def test_empty_response_body_is_well_defined():
    """An HTTP 200 with a zero-length body yields b'' and an empty string."""
    response = RecordingResponse(200, b"")
    client = _client(RecordingSession(response))
    result = client.get("/api/device/basic_information")
    assert result.status_code == 200
    assert result.content == b""
    assert result.text == ""
    assert response.closed


def test_oversized_response_abandoned_while_streaming():
    body = b"A" * 256
    response = RecordingResponse(200, body)
    client = _client(RecordingSession(response), max_response_bytes=64)
    with pytest.raises(ModemHTTPError, match="max_response_bytes"):
        client.get("/api/device/basic_information")
    assert response.closed, "connection must be released after the limit trip"
    client2 = _client(RecordingSession(RecordingResponse(200, body)), max_response_bytes=64)
    with pytest.raises(ModemHTTPError):
        client2.get("/api/device/basic_information")


def test_exact_limit_passes_bytewise_and_off_limit_fails():
    body = b"B" * 64  # == limit: allowed (total must EXCEED the limit to fail)
    client = _client(RecordingSession(RecordingResponse(200, body)), max_response_bytes=64)
    result = client.get("/api/device/basic_information")
    assert result._content == body
    with pytest.raises(ModemHTTPError, match="max_response_bytes"):
        _client(RecordingSession(RecordingResponse(200, body + b"C")), max_response_bytes=64).get(
            "/api/device/basic_information"
        )


def test_limit_can_be_explicitly_disabled_but_only_deliberately():
    body = b"D" * 512
    client = _client(RecordingSession(RecordingResponse(200, body)), max_response_bytes=None)
    result = client.get("/api/device/basic_information")
    assert result._content == body


def test_invalid_max_response_bytes_rejected_before_any_io():
    session = RecordingSession(RecordingResponse(200, b"ok"))
    for bad in (0, -1, 1.5, True, "64"):
        with pytest.raises(ValueError, match="max_response_bytes"):
            _client(session, max_response_bytes=bad)
    assert session.calls == []


def test_interrupted_stream_raises_and_closes():
    response = RecordingResponse(200, b"E" * 128, fail_after=64)
    client = _client(RecordingSession(response))
    with pytest.raises(ModemHTTPError, match="interrupted"):
        client.get("/api/device/basic_information")
    assert response.closed


def test_only_requests_exceptions_translated_and_connection_still_released():
    """Documented policy: a NON-requests exception during streaming is a
    programming/middleware defect and must propagate UNCHANGED — it is never
    disguised as ModemHTTPError — but the response connection is still
    released unconditionally."""
    class BuggyMiddlewareResponse(RecordingResponse):
        def iter_content(self, chunk_size: int):
            self.iterated = True
            yield b"F" * 16
            raise ValueError("defective middleware, not a transport failure")

    response = BuggyMiddlewareResponse(200, b"F" * 256)
    client = _client(RecordingSession(response))
    with pytest.raises(ValueError, match="defective middleware"):
        client.get("/api/device/basic_information")
    assert response.closed, "even non-requests exceptions must release the connection"

    # Contrast: a requests-family exception IS translated.
    dropped = RecordingResponse(200, b"E" * 128, fail_after=64)
    client2 = _client(RecordingSession(dropped))
    with pytest.raises(ModemHTTPError, match="interrupted"):
        client2.get("/api/device/basic_information")


# --------------------------------------------------------- G-5 error hygiene


SYNTHETIC_SECRET_FRAME = b"<Error>SYNTHETIC-COOKIE-BODY</Error>"


def test_http_error_text_never_embeds_body_or_headers():
    response = RecordingResponse(500, SYNTHETIC_SECRET_FRAME)
    client = _client(RecordingSession(response))
    with pytest.raises(ModemHTTPError) as info:
        client.get("/api/device/basic_information")
    message = str(info.value)
    assert "500" in message
    assert "SYNTHETIC-COOKIE-BODY" not in message
    assert "Set-Cookie" not in message
    assert "SessionID" not in message


def test_non_200_responses_are_never_even_streamed():
    response = RecordingResponse(403, SYNTHETIC_SECRET_FRAME)
    client = _client(RecordingSession(response))
    with pytest.raises(ModemHTTPError):
        client.get("/api/device/basic_information")
    assert response.iterated is False, "non-200 body must stay unread"
    assert response.closed


def test_classified_dangerous_paths_yield_no_endpoint_data_in_errors():
    session = RecordingSession(RecordingResponse(200, b"ok"))
    client = _client(session)
    for path in FORBIDDEN_PATHS:
        with pytest.raises(UnsafeOperationError) as info:
            client.get(path)
        text = str(info.value)
        assert path in text  # the PATH is fine to expose
        assert "<Error>" not in text  # but never any fabricated content
    assert session.calls == []


# ------------------------------------------------------------- G-6 no logging


def test_modem_client_and_downloader_never_log_responses():
    import inspect

    from huawei_tower.modem import api, jsdownloader

    for module in (api, jsdownloader):
        source = inspect.getsource(module)
        for banned in ("print(", "logging", "logger", "getLogger", ".debug(", ".warning(", ".critical(", ".error(", "log_message"):
            assert banned not in source, f"{module.__name__} contains {banned!r}"


def test_session_secret_names_never_appear_in_client_source_logging_context():
    """No code path in api.py prints or formats cookies/tokens (source scan)."""
    import inspect

    from huawei_tower.modem import api

    source = inspect.getsource(api)
    # FIXME-guard: ensure no response-content formatting exists at all.
    for banned in ("response.text", "response.content", "response.headers", "response.cookies"):
        assert banned not in source


# ----------------------------------- Phase 7 bootstrap reclassification


def test_bootstrap_endpoints_are_gated_state_allocating_not_unconditionally_read_only():
    for path in ("/api/webserver/SesTokInfo", "/api/webserver/token"):
        gated = GATED_GET_ENDPOINTS[path]
        assert gated.classification == "state_allocating"
        assert gated.reason.strip()
    assert "/api/webserver/SesTokInfo" not in SAFE_GET_ENDPOINTS
    assert "/api/webserver/token" not in SAFE_GET_ENDPOINTS


def test_client_refuses_bootstrap_endpoints_and_every_classified_entry():
    session = RecordingSession(RecordingResponse(200, b"ok"))
    client = _client(session)
    for path in GATED_GET_ENDPOINTS:
        with pytest.raises(UnsafeOperationError):
            client.get(path)
    assert session.calls == []


def test_safe_allowlist_remains_strictly_verified_and_unexpanded():
    expected = {
        "/api/device/basic_information",
        "/api/net/current-plmn",
        "/api/monitoring/traffic-statistics",
        "/api/dialup/connection",
        "/api/dialup/mobile-dataswitch",
        "/api/pin/status",
        "/api/user/state-login",
        "/api/global/module-switch",
        "/api/monitoring/check-notifications",
    }
    assert set(SAFE_GET_ENDPOINTS) == expected, "Tier-1 set must not expand silently"
    for endpoint in SAFE_GET_ENDPOINTS.values():
        assert endpoint.verified_read_only is True


# ------------------------------------------- session wiring (regression focus)


def test_falsey_injected_session_is_used_even_after_a_full_get():
    calls: list[str] = []

    class FalseyRecordingSession(RecordingSession):
        def __init__(self):
            super().__init__(RecordingResponse(200, b"ok"))

        def __bool__(self):
            return False

        def get(self, *args, **kwargs):  # record then delegate
            calls.append("used")
            return super().get(*args, **kwargs)

    falsey = FalseyRecordingSession()
    client = _client(falsey)
    result = client.get("/api/device/basic_information")
    assert result.status_code == 200
    assert client._session is falsey, "falsey session object identity preserved"
    assert calls == ["used"], "the falsey session was actually the one used"


def test_internally_created_session_has_no_env_inheritance_and_own_headers():
    client = ReadOnlyModemClient()  # no session injected; real requests.Session
    assert client._session.trust_env is False
    assert client._session.headers["User-Agent"].startswith("H158-381-BestPair/")


# --------------------------------------------- downloader determinism extras


@pytest.fixture()
def dest(tmp_path: Path) -> Path:
    out = tmp_path / "evidence_downloads"
    out.mkdir()
    return out


_DL_ERROR_XML = b'<?xml version="1.0" encoding="UTF-8"?><error><code>100003</code></error>'


class _DLStubResponse:
    def __init__(self, status_code=200, body=b""):
        self.status_code = status_code
        self._body = body
        self.headers = {}

    def iter_content(self, chunk_size: int):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i: i + chunk_size]


class _DLStubSession:
    def __init__(self, response):
        self.headers = {}
        self.calls: list[tuple[str, dict]] = []
        self._response = response

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._response

    def close(self):
        pass


def _downloader(dest: Path):
    from huawei_tower.modem.jsdownloader import JSAssetDownloader

    return JSAssetDownloader(
        "https://192.168.70.1",
        dest,
        session=_DLStubSession(_DLStubResponse(200, b"// body")),
    )


def test_sequential_same_destination_publication_never_clobbers(dest: Path):
    from huawei_tower.modem.jsdownloader import AssetDownloadError

    first = _downloader(dest).fetch("/js/login.js")
    assert first is not None
    before = first.read_bytes()
    before_mtime = first.stat().st_mtime_ns
    with pytest.raises(AssetDownloadError, match="already exists"):
        _downloader(dest).fetch("/js/login.js")
    assert first.read_bytes() == before
    assert first.stat().st_mtime_ns == before_mtime
    assert [p.name for p in dest.glob("*.part")] == [], "no temp leftovers"


def test_error_download_paths_leave_no_part_files(dest: Path):
    from huawei_tower.modem.errors import ModemHTTPError
    from huawei_tower.modem.jsdownloader import (
        JSAssetDownloader,
        AssetDownloadError,
    )

    # XML error body: refused as non-asset, nothing stored.
    session = _DLStubSession(_DLStubResponse(200, _DL_ERROR_XML))
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session)
    with pytest.raises(AssetDownloadError, match="XML response"):
        dl.fetch("/js/login.js")
    assert [p.name for p in dest.glob("*.part")] == []

    # Oversize: refused mid-stream, nothing stored.
    session = _DLStubSession(_DLStubResponse(200, b"x" * 4096))
    dl = JSAssetDownloader("https://192.168.70.1", dest, session=session, max_asset_bytes=128)
    with pytest.raises(AssetDownloadError, match="size limit"):
        dl.fetch("/js/login.js")
    assert [p.name for p in dest.glob("*.part")] == []

    # Non-200: error raised, nothing stored.
    dl = JSAssetDownloader(
        "https://192.168.70.1",
        dest,
        session=_DLStubSession(_DLStubResponse(500, b"// never stored")),
    )
    with pytest.raises(ModemHTTPError, match="HTTP"):
        dl.fetch("/js/login.js")
    assert [p.name for p in dest.glob("*.part")] == []

    # Unpublished.approved path: rejected before any I/O, nothing stored.
    dl2 = JSAssetDownloader(
        "https://192.168.70.1",
        dest,
        session=_DLStubSession(_DLStubResponse(200, b"// ok")),
    )
    with pytest.raises(AssetDownloadError, match="not on the approved asset list"):
        dl2.fetch("/js/not-approved.js")
    assert [p.name for p in dest.glob("*.part")] == []
    assert not dest.joinpath("js_login.js").exists()

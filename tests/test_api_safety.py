from __future__ import annotations

import pytest
import requests

from huawei_tower.modem.api import (
    FORBIDDEN_PATHS,
    GATED_GET_ENDPOINTS,
    SAFE_GET_ENDPOINTS,
    ReadOnlyModemClient,
)
from huawei_tower.modem.errors import ModemHTTPError, UnsafeOperationError


class NoNetworkSession:
    """A session that never performs I/O; any call is immediately recorded."""

    def __init__(self):
        self.headers = {}
        self.calls: list[tuple[tuple, dict]] = []

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("Network must not be called in this test")

    def close(self):
        pass


def test_unapproved_get_is_blocked_before_network():
    session = NoNetworkSession()
    client = ReadOnlyModemClient(session=session)
    with pytest.raises(UnsafeOperationError):
        client.get("/api/monitoring/best-position-status")
    assert session.calls == []


def test_scan_start_endpoint_is_blocked():
    session = NoNetworkSession()
    client = ReadOnlyModemClient(session=session)
    with pytest.raises(UnsafeOperationError):
        client.get("/api/monitoring/best-signal-position")
    assert session.calls == []


def test_all_forbidden_paths_are_blocked_before_any_io():
    session = NoNetworkSession()
    client = ReadOnlyModemClient(session=session)
    assert len(FORBIDDEN_PATHS) > 0
    for path in FORBIDDEN_PATHS:
        with pytest.raises(UnsafeOperationError):
            client.get(path)
    assert session.calls == []


def test_write_or_cell_lock_endpoints_are_not_accessible():
    session = NoNetworkSession()
    client = ReadOnlyModemClient(session=session)
    for path in (
        "/api/net/lock-freq",
        "/api/ntwk/celllock",
        "/api/net/reconnect",
        "/api/user/authentication_login",
        "/api/dialup/dial",
        "/api/net/plmn-list",
    ):
        with pytest.raises(UnsafeOperationError):
            client.get(path)
    assert session.calls == []


def test_allowlist_matches_exactly_not_loosely():
    """Trailing slashes, query strings and case changes must all be rejected."""
    session = NoNetworkSession()
    client = ReadOnlyModemClient(session=session)
    approved = "/api/device/basic_information"
    for mutated in (
        approved + "/",
        approved + "?x=1",
        approved.upper(),
        "api/device/basic_information",
        "/api/device/../device/basic_information",
        "//api/device/basic_information",
    ):
        with pytest.raises(UnsafeOperationError):
            client.get(mutated)
    assert session.calls == []


def test_unknown_endpoint_default_is_blocked():
    session = NoNetworkSession()
    client = ReadOnlyModemClient(session=session)
    with pytest.raises(UnsafeOperationError):
        client.get("/api/does/not/exist")
    assert session.calls == []


def test_every_gated_entry_classified_and_documented():
    for gated in GATED_GET_ENDPOINTS.values():
        assert gated.classification in {"plausible_read_only", "unknown", "unsafe", "verified_read_only"}
        assert gated.reason.strip()


def test_non_https_base_url_rejected():
    with pytest.raises(ValueError):
        ReadOnlyModemClient("http://192.168.70.1")
    with pytest.raises(ValueError):
        ReadOnlyModemClient("ftp://192.168.70.1")
    with pytest.raises(ValueError):
        ReadOnlyModemClient("https:")


class FakeResponse:
    def __init__(self, status_code=200, text="<response/>"):
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, response=None):
        self.headers = {}
        self.calls = []
        self._response = response or FakeResponse()

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self._response

    def close(self):
        pass


def test_approved_endpoint_calls_get_only_with_redirects_disabled():
    session = FakeSession()
    client = ReadOnlyModemClient(session=session)
    response = client.get("/api/device/basic_information")
    assert response.status_code == 200
    assert len(session.calls) == 1
    assert session.calls[0][1]["allow_redirects"] is False


def test_http_3xx_4xx_5xx_raise_instead_of_silently_passing():
    for status in (301, 302, 307, 400, 401, 403, 500, 503):
        session = FakeSession(FakeResponse(status_code=status))
        client = ReadOnlyModemClient(session=session)
        with pytest.raises(ModemHTTPError):
            client.get("/api/device/basic_information")


def test_no_http_verbs_exposed_for_writes():
    client = ReadOnlyModemClient(session=FakeSession())
    for verb in ("post", "put", "patch", "delete", "head", "options", "request"):
        with pytest.raises(UnsafeOperationError):
            getattr(client, verb)


def test_allowlist_only_contains_verified_entries():
    for endpoint in SAFE_GET_ENDPOINTS.values():
        assert endpoint.verified_read_only is True


def test_socket_blocking_is_enforced_in_the_test_suite():
    # conftest patches socket.socket; this proves the guarantee.
    import socket

    with pytest.raises(RuntimeError):
        socket.socket()

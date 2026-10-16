import pytest
import requests

from huawei_tower.modem.api import ReadOnlyModemClient
from huawei_tower.modem.errors import UnsafeOperationError


class NoNetworkSession:
    def __init__(self):
        self.headers = {}
        self.calls = []

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


def test_write_or_cell_lock_endpoints_are_not_accessible():
    session = NoNetworkSession()
    client = ReadOnlyModemClient(session=session)
    for path in (
        "/api/net/lock-freq",
        "/api/ntwk/celllock",
        "/api/net/reconnect",
        "/api/user/authentication_login",
    ):
        with pytest.raises(UnsafeOperationError):
            client.get(path)
    assert session.calls == []


def test_non_https_base_url_rejected():
    with pytest.raises(ValueError):
        ReadOnlyModemClient("http://192.168.70.1")


def test_approved_endpoint_calls_get_only():
    class FakeResponse:
        status_code = 200
        text = "<response><ProductFamily>LTE</ProductFamily></response>"

    class FakeSession:
        def __init__(self):
            self.headers = {}
            self.calls = []
        def get(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return FakeResponse()
        def close(self):
            pass

    session = FakeSession()
    client = ReadOnlyModemClient(session=session)
    response = client.get("/api/device/basic_information")
    assert response.status_code == 200
    assert len(session.calls) == 1
    assert session.calls[0][1]["allow_redirects"] is False

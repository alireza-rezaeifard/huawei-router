from pathlib import Path
import socket
import sys

import pytest

# Allow running pytest directly from a source checkout without an editable install.
SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "network: test intentionally needs real network access"
    )


@pytest.fixture(autouse=True)
def block_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """Fail-closed offline guarantee: any socket use aborts the test.

    Denies socket construction, outbound/inbound connection attempts, and the
    full DNS/name-resolution family (``getaddrinfo``, ``gethostbyname``,
    ``gethostbyname_ex``, ``gethostbyaddr``, ``getnameinfo``) — resolution is
    real network I/O and the entry point of every HTTP stack. Tests that
    actually need the live network must opt in explicitly via the
    ``network`` marker; none exist at this time. This keeps the whole suite
    offline by construction rather than by convention.

    Known limits (this is a test-level fail-fast tripwire, NOT OS-level
    network isolation): child processes run outside this patch scope (the
    guard is per-test interpreter) and ``socket.socketpair`` (loopback-only)
    is not intercepted. Ordinary tests cannot opt out accidentally.
    """
    if request.node.get_closest_marker("network"):
        yield
        return

    def _deny(*args, **kwargs):
        raise RuntimeError(
            "Network access is disabled in the offline test suite "
            "(no 'network' marker on this test)."
        )

    monkeypatch.setattr(socket, "socket", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)
    monkeypatch.setattr(socket, "gethostbyname", _deny)
    monkeypatch.setattr(socket, "gethostbyname_ex", _deny)
    monkeypatch.setattr(socket, "gethostbyaddr", _deny)
    monkeypatch.setattr(socket, "getnameinfo", _deny)
    yield

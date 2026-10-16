from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from urllib.parse import urljoin, urlparse

import requests

from .errors import ModemHTTPError, UnsafeOperationError
from .tls import resolve_verify_tls

Classification = Literal["verified_read_only", "plausible_read_only", "unsafe", "unknown"]


@dataclass(frozen=True)
class Endpoint:
    path: str
    verified_read_only: bool
    notes: str = ""


@dataclass(frozen=True)
class GatedEndpoint:
    """Endpoint that exists on this firmware but is NOT callable by this client."""

    path: str
    classification: Classification
    reason: str
    evidence: str = ""


# Tier 1 — verified read-only. Each was executed exactly once during the
# read-only discovery session (docs/PHASE1_FINDINGS.md) and returned HTTP 200
# with the documented XML payload. GET behavior is confirmed safe.
SAFE_GET_ENDPOINTS: dict[str, Endpoint] = {
    "/api/device/basic_information": Endpoint(
        "/api/device/basic_information", True, "Basic device metadata; observed HTTP 200."
    ),
    "/api/net/current-plmn": Endpoint(
        "/api/net/current-plmn", True, "Serving PLMN and RAT; observed HTTP 200."
    ),
    "/api/monitoring/traffic-statistics": Endpoint(
        "/api/monitoring/traffic-statistics", True, "Traffic counters; observed HTTP 200."
    ),
    "/api/dialup/connection": Endpoint(
        "/api/dialup/connection", True, "Dial-up configuration read; observed HTTP 200."
    ),
    "/api/dialup/mobile-dataswitch": Endpoint(
        "/api/dialup/mobile-dataswitch", True, "Data switch status read; observed HTTP 200."
    ),
    "/api/pin/status": Endpoint(
        "/api/pin/status", True, "SIM PIN state; observed HTTP 200."
    ),
    "/api/user/state-login": Endpoint(
        "/api/user/state-login", True, "Login capability metadata; observed HTTP 200."
    ),
    "/api/global/module-switch": Endpoint(
        "/api/global/module-switch", True, "Feature switches; observed HTTP 200."
    ),
    "/api/webserver/SesTokInfo": Endpoint(
        "/api/webserver/SesTokInfo", True, "Session bootstrap; response contains secrets -> never logged."
    ),
    "/api/webserver/token": Endpoint(
        "/api/webserver/token", True, "Allocates a CSRF token (server-side state); body never logged."
    ),
    "/api/monitoring/check-notifications": Endpoint(
        "/api/monitoring/check-notifications", True, "Notification counters; observed HTTP 200."
    ),
}


# Tier 2/4 — verified NOT enabled. Classification per docs/PHASE3_JS_ANALYSIS.md.
GATED_GET_ENDPOINTS: dict[str, GatedEndpoint] = {
    # Best Pair scan polling: the firmware main.js maps these names, but the
    # page modules that call them were never retrievable without login, so the
    # exact method/parameters/side effects are UNVERIFIED. A GET on an unknown
    # trigger state is not proven side-effect-free.
    "/api/monitoring/best-position-status": GatedEndpoint(
        "/api/monitoring/best-position-status",
        "plausible_read_only",
        "Name suggests status polling; caller page is in an admin-only chunk, "
        "never traced. Enabled only after firmware control-flow evidence.",
        evidence="main.js webpack chunk map + endpoint map; see PHASE1/3 docs",
    ),
    "/api/monitoring/best-position-result": GatedEndpoint(
        "/api/monitoring/best-position-result",
        "plausible_read_only",
        "Name suggests result read; caller page untraced. No evidence that this "
        "is side-effect free on an unscanned state.",
        evidence="main.js endpoint map ('bestPositionRes')",
    ),
    "/api/device/information": GatedEndpoint(
        "/api/device/information",
        "plausible_read_only",
        "Requires login (observed 100003 pre-login); authenticated GET behavior "
        "not yet exercised.",
        evidence="Phase 1 probes",
    ),
    "/api/monitoring/status": GatedEndpoint(
        "/api/monitoring/status",
        "plausible_read_only",
        "Requires login; also the app adds 'Update-Cookie: UpdateCookie' header "
        "on GET — likely session refresh side effect. Not verified.",
        evidence="main.js GET wrapper: \"/api/monitoring/status\"===s && (u[\"Update-Cookie\"]=\"UpdateCookie\")",
    ),
    "/api/monitoring/converged-status": GatedEndpoint(
        "/api/monitoring/converged-status",
        "plausible_read_only",
        "Requires login (observed 100003 pre-login).",
        evidence="guide.js getCurrentLanguage uses it pre-login",
    ),
    "/api/net/cell-info": GatedEndpoint(
        "/api/net/cell-info",
        "unknown",
        "Cell/neighbor schema unverified; GET side effects unknown.",
        evidence="main.js endpoint map ('cellInfo')",
    ),
    "/api/net/signal": GatedEndpoint(
        "/api/net/signal",
        "unknown",
        "Not in endpoint map; listed as device/signal. Mapped name unknown — treat as unknown.",
        evidence="-",
    ),
    "/api/device/signal": GatedEndpoint(
        "/api/device/signal",
        "plausible_read_only",
        "Known Huawei signal-status endpoint; not yet exercised on this firmware.",
        evidence="main.js 'singal:\"/api/device/signal\"'",
    ),
    "/api/net/network": GatedEndpoint(
        "/api/net/network",
        "unknown",
        "Net select mode read but JS usage untraced; could relate to registration flows.",
        evidence="main.js 'network:\"/api/net/network\"'",
    ),
    "/api/net/net-mode-list": GatedEndpoint(
        "/api/net/net-mode-list",
        "plausible_read_only",
        "Axis list supporting net-mode page; requires login. POST /net-mode is "
        "the write; GET side effects unverified.",
        evidence="observed 100003 (login required), Phase 1",
    ),
}

# Tier 3 — unsafe or unknown-dangerous. The client rejects these before any I/O.
FORBIDDEN_PATHS: set[str] = {
    # Scan initiation (method/side effects unknown; never probe).
    "/api/monitoring/best-signal-position",
    "/api/monitoring/external-best-signal-position",
    "/api/monitoring/onekey_diag",
    # Cell/band/PCI locking and write-path endpoints.
    "/api/net/handle-cell",
    "/api/ntwk/celllock",
    "/api/net/lock-freq",
    "/api/net/net-mode",
    # Registration / connectivity hazards.
    "/api/net/register",
    "/api/net/reconnect",
    "/api/net/plmn-list",  # manual network search; likely triggers re-registration
    "/api/dialup/dial",
    "/api/monitoring/start_date",
    "/api/device/control",
    "/api/device/datalock",
    # Authentication POSTs (never callable as GETs by this client).
    "/api/user/challenge_login",
    "/api/user/authentication_login",
    "/api/user/login",
}

_WRITE_METHODS = ("post", "put", "patch", "delete", "head", "options", "request")


class ReadOnlyModemClient:
    """GET-only modem client with exact-path allowlisting and no generic request API."""

    def __init__(
        self,
        base_url: str = "https://192.168.70.1",
        *,
        verify_tls: bool | str = True,
        timeout: float = 8.0,
        session: requests.Session | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Modem base URL must be an explicit HTTPS URL.")
        self.base_url = base_url.rstrip("/") + "/"
        # Fail closed BEFORE any I/O: verify_tls=False (or any weakening value)
        # is rejected here, never silently forwarded to the session.
        self.verify_tls = resolve_verify_tls(verify_tls)
        self.timeout = timeout
        if session is None:
            # Internally created session only: never inherit environment
            # proxies or .netrc credentials for the fixed modem origin (they
            # could redirect or decorate requests unexpectedly). TLS
            # verification is unaffected — ``verify`` is passed per request.
            self._session = requests.Session()
            self._session.trust_env = False
        else:
            # Caller-injected session is kept exactly as provided — including
            # falsey objects — and its configuration is never modified.
            self._session = session
        self._session.headers.update({"Accept": "*/*", "User-Agent": "H158-381-BestPair/0.3 read-only"})

    def _classify(self, path: str) -> str | None:
        """Return None when ``path`` is approved; otherwise a rejection reason."""
        if path in FORBIDDEN_PATHS:
            return f"Blocked endpoint (unsafe/unknown side effects): {path}"
        endpoint = SAFE_GET_ENDPOINTS.get(path)
        if endpoint is not None and endpoint.verified_read_only:
            return None
        gated = GATED_GET_ENDPOINTS.get(path)
        if gated is not None:
            return f"GET blocked for {path}: {gated.classification} — {gated.reason}"
        return f"GET blocked for {path}: not on the approved allowlist (unknown endpoint)."

    def get(self, path: str) -> requests.Response:
        reason = self._classify(path)
        if reason is not None:
            raise UnsafeOperationError(reason)
        url = urljoin(self.base_url, path.lstrip("/"))
        response = self._session.get(
            url,
            timeout=self.timeout,
            verify=self.verify_tls,
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise ModemHTTPError(f"GET {path} returned HTTP {response.status_code}")
        return response

    def close(self) -> None:
        self._session.close()

    def __getattr__(self, name: str):
        # Fail closed for any accidental exposure of HTTP-verb style methods.
        if name.lower() in _WRITE_METHODS:
            raise UnsafeOperationError(
                f"ReadOnlyModemClient deliberately does not support '{name}'. "
                "All writes require an explicit, separately-approved client."
            )
        raise AttributeError(name)

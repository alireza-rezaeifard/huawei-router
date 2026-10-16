from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests

from .errors import ModemHTTPError, UnsafeOperationError


@dataclass(frozen=True)
class Endpoint:
    path: str
    verified_read_only: bool
    notes: str = ""


# Only endpoints reported as confirmed, unauthenticated GET reads are enabled.
# Authenticated endpoints are deliberately gated until their GET behavior is reviewed.
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
        "/api/webserver/SesTokInfo", True, "Session/token bootstrap metadata; observed HTTP 200."
    ),
    "/api/webserver/token": Endpoint(
        "/api/webserver/token", True, "Token endpoint observed; never log its response."
    ),
    "/api/monitoring/check-notifications": Endpoint(
        "/api/monitoring/check-notifications", True, "Notification counters; observed HTTP 200."
    ),
}

# These endpoints are known to exist but are NOT enabled until their behavior is verified.
GATED_GET_ENDPOINTS: dict[str, str] = {
    "/api/monitoring/best-position-status": "Verify it only polls status and cannot start a scan.",
    "/api/monitoring/best-position-result": "Verify it only reads prior scan results.",
    "/api/device/information": "Requires login; authenticated GET behavior not yet tested.",
    "/api/monitoring/status": "Requires login; authenticated GET behavior not yet tested.",
    "/api/monitoring/converged-status": "Requires login; authenticated GET behavior not yet tested.",
    "/api/net/cell-info": "Cell schema and authenticated GET behavior not yet tested.",
    "/api/net/network": "Inspect firmware JS to ensure GET does not trigger network search.",
    "/api/net/net-mode-list": "Requires login; inspect firmware behavior first.",
}

FORBIDDEN_PATHS = {
    "/api/monitoring/best-signal-position",
    "/api/monitoring/external-best-signal-position",
    "/api/net/handle-cell",
    "/api/ntwk/celllock",
    "/api/net/lock-freq",
    "/api/net/register",
    "/api/net/reconnect",
    "/api/user/challenge_login",
    "/api/user/authentication_login",
    "/api/user/login",
}


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
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._session = session or requests.Session()
        self._session.headers.update({"Accept": "*/*", "User-Agent": "H158-381-BestPair/0.2 read-only"})

    def get(self, path: str) -> requests.Response:
        if path in FORBIDDEN_PATHS:
            raise UnsafeOperationError(f"Blocked endpoint: {path}")
        endpoint = SAFE_GET_ENDPOINTS.get(path)
        if endpoint is None or not endpoint.verified_read_only:
            reason = GATED_GET_ENDPOINTS.get(path, "Endpoint is not on the approved GET allowlist.")
            raise UnsafeOperationError(f"GET blocked for {path}: {reason}")
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

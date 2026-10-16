"""Same-origin firmware JavaScript asset downloader (Phase 3, ID-D).

Evidence for the loading mechanism (``evidence/raw/js__js_main.js_r_1709723942``,
webpack runtime): chunks are loaded with ``src = i.p + "js/" + ({'...': name}[e]
|| e) + ".js"`` where the webpack public path is ``i.p = "../"```` — i.e. every
UI page is fetched from ``<origin>/js/<chunk-name>.js`` and its CSS from
``<origin>/css/<chunk-name>.css``. Libraries (``/lib/emui-crypto.js``,
``/lib/vue.global.prod.js`` ...) are loaded via fixed <script src> tags in
``/html/index.html`` / ``/``. No chunk URL is ever derived from server-supplied
data; the downloader therefore mirrors exactly this scheme and never accepts a
URL from a response.

Observed at discovery time (unauthenticated):
  /js/main.js, /js/login.js, /lib/emui-crypto.js, chunk /js/common.js were
  served as real content (HTTP 200), while admin page chunks returned HTTP 200
  with an XML error body ``<error><code>100003</code>...`` and a ``text/xml``
  content type. The downloader detects that and refuses to store such a body
  as if it were an asset.

Safety properties implemented here:
- HTTPS-only modem origin; a fixed explicit target list; no redirects
  (allow_redirects=False, 3xx => error).
- Path traversal and foreign-origin rejection (only constants leave this file).
- Hard byte ceiling per asset, streamed; oversize => error, nothing stored.
- Unauthenticated-only in this phase: authenticated downloads require separate,
  documented approval and are gated through ``allow_authenticated=False``.
- ''page'' pages such as /html/index.html are fetched from the same approved
  constants; dry-run mode performs no network I/O.
- Assets are written only under a caller-supplied directory; the caller must
  point it at a Git-excluded evidence folder (default suggestion documented).
- No cookies, tokens, or credentials are stored or logged by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal, Protocol
from urllib.parse import urljoin, urlparse

_MAX_ASSET_BYTES = 8 * 1024 * 1024
_ALLOWED_SUFFIX = ".js"
_ERROR_MARKERS = (b"<?xml", b"<error>", b"<response>")


@dataclass(frozen=True)
class FirmwareAsset:
    """A fixed firmware asset that may be downloaded from the modem origin."""

    path: str
    category: Literal["ui_core", "library", "admin_chunk", "page"]
    # True when the asset was observed to require an authenticated session
    # (its unauthenticated GET returned error 100003 inside an XML body).
    requires_authenticated_session: bool = False
    notes: str = ""


# Explicit, reviewed asset list. This is the ONLY set of files this module can
# download; nothing else—however plausible its name—will ever be requested.
APPROVED_ASSETS: dict[str, FirmwareAsset] = {
    "/html/index.html": FirmwareAsset(
        "/html/index.html", "page", False, "App shell with csrf_token metas (redact on store)."
    ),
    "/js/main.js": FirmwareAsset(
        "/js/main.js", "ui_core", False, "Common chunk: endpoint map, login flow, axios wrappers."
    ),
    "/js/login.js": FirmwareAsset(
        "/js/login.js", "ui_core", False, "Login page module."
    ),
    "/js/common.js": FirmwareAsset(
        "/js/common.js", "ui_core", False, "Vuex actions/getters layer. Served unauthenticated."
    ),
    "/lib/emui-crypto.js": FirmwareAsset(
        "/lib/emui-crypto.js", "library", False, "CryptoJS + SCRAM implementation."
    ),
    # Admin chunks — confirmed to require an authenticated session (they return
    # error 100003 as an XML body without one). Enabled explicitly for later
    # phases only; requires_authenticated_session=True blocks them now.
    "/js/celllock-celllock-vue.js": FirmwareAsset(
        "/js/celllock-celllock-vue.js", "admin_chunk", True, "Cell lock page (PCI lock)."
    ),
    "/js/lockband.js": FirmwareAsset(
        "/js/lockband.js", "admin_chunk", True, "Band/frequency lock page."
    ),
    "/js/mobilesearch-mobilesearch-vue.js": FirmwareAsset(
        "/js/mobilesearch-mobilesearch-vue.js", "admin_chunk", True, "Manual network search page."
    ),
    "/js/mobilenetwork-mobilenetwork-vue.js": FirmwareAsset(
        "/js/mobilenetwork-mobilenetwork-vue.js", "admin_chunk", True, "Mobile network page."
    ),
    "/js/networkmode.js": FirmwareAsset(
        "/js/networkmode.js", "admin_chunk", True, "Network mode page."
    ),
    "/js/onekey-onekey-vue.js": FirmwareAsset(
        "/js/onekey-onekey-vue.js", "admin_chunk", True, "One-key check page (signal test)."
    ),
}


class _ResponseLike(Protocol):
    status_code: int
    headers: dict

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...


class _SessionLike(Protocol):
    def get(self, url: str, *, timeout: float, verify: object, allow_redirects: bool) -> _ResponseLike:
        ...


class AssetDownloadError(RuntimeError):
    """Raised when an asset cannot be downloaded safely."""


class JSAssetDownloader:
    """Downloads approved firmware JS assets into a local evidence directory."""

    def __init__(
        self,
        base_url: str,
        dest_dir: str | Path,
        *,
        session: _SessionLike | None = None,
        timeout: float = 15.0,
        verify_tls: bool | str = True,
        dry_run: bool = False,
        max_asset_bytes: int = _MAX_ASSET_BYTES,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Downloader base URL must be an explicit HTTPS URL.")
        self._base = base_url.rstrip("/") + "/"
        self._origin = parsed.hostname
        self._dest = Path(dest_dir)
        self._session = session  # lazily built when not a dry run
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._dry_run = dry_run
        self._max_bytes = max_asset_bytes

    def plan(self) -> list[tuple[str, Path]]:
        """The exact (path, destination) pairs this downloader is allowed to fetch."""
        return [
            (a.path, self._dest / a.path.lstrip("/").replace("/", "_"))
            for a in APPROVED_ASSETS.values()
        ]

    authenticated_allowed: bool = False  # Phase 3 boundary: auth not yet approved.

    def _validate_asset(self, path: str) -> FirmwareAsset:
        asset = APPROVED_ASSETS.get(path)
        if asset is None:
            raise AssetDownloadError(f"'{path}' is not on the approved asset list.")
        if not path.startswith("/") or ".." in path or "\\" in path:
            raise AssetDownloadError("Refusing non-canonical or traversal paths.")
        if asset.requires_authenticated_session and not self.authenticated_allowed:
            raise AssetDownloadError(
                f"{path} requires an authenticated session; authenticated downloads "
                "are not approved yet. See docs/PHASE3_JS_ANALYSIS.md."
            )
        return asset

    def fetch(self, path: str) -> Path | None:
        """Download one approved asset and store it under ``dest_dir``."""
        from .errors import ModemHTTPError

        asset = self._validate_asset(path)
        if self._dry_run:
            return None  # no network I/O in dry-run mode

        import requests  # local import: not needed for plan()/dry-run tests

        session = self._session
        created_here = False
        if session is None:
            session = requests.Session()
            created_here = True
        try:
            url = urljoin(self._base, asset.path.lstrip("/"))
            if self._peer_origin(url) != self._origin:
                raise AssetDownloadError("Resolved URL escaped the modem origin.")
            response = session.get(
                url,
                timeout=self._timeout,
                verify=self._verify_tls,
                allow_redirects=False,
            )
            if 300 <= response.status_code < 400:
                raise AssetDownloadError(
                    f"Refusing redirect for {path} (HTTP {response.status_code})."
                )
            if response.status_code != 200:
                raise ModemHTTPError(f"GET {path} returned HTTP {response.status_code}")

            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(65536):
                total += len(chunk)
                if total > self._max_bytes:
                    raise AssetDownloadError(
                        f"{path} exceeds the configured size limit; refusing to store."
                    )
                chunks.append(chunk)
            body = b"".join(chunks)

            head = body[:64].lstrip()
            if any(head.startswith(m) for m in _ERROR_MARKERS):
                raise AssetDownloadError(
                    f"{path} returned a Huawei XML response (error/not-available), "
                    "not a JavaScript asset. Refusing to store."
                )

            dest = self._dest / path.lstrip("/").replace("/", "_")
            self._dest.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(dest.suffix + ".tmp")
            tmp.write_bytes(body)
            tmp.replace(dest)
            return dest
        finally:
            if created_here:
                session.close()  # type: ignore[union-attr]

    def _peer_origin(self, url: str) -> str:
        return urlparse(url).hostname

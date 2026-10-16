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
- TLS certificate verification can never be disabled (``verify_tls=False``
  and any other weakening value raise ``ValueError`` in the constructor,
  before any I/O; see ``tls.resolve_verify_tls`` — Phase 3.1).
- Path traversal and foreign-origin rejection (only constants leave this file).
- Hard byte ceiling per asset, streamed; oversize => error, nothing stored.
- Unauthenticated-only by default: an asset flagged
  ``requires_authenticated_session`` is refused unless the caller supplies a
  narrowly scoped ``AuthenticatedDownloadAuthorization`` naming that exact
  asset path on THAT ``fetch()`` call. The downloader never constructs an
  authorization itself, never performs a login, and possession of a session
  cookie does not bypass the gate (Phase 3.1 fail-closed redesign).
- HTML pages such as /html/index.html are fetched from the same approved
  constants; dry-run mode performs no network I/O.
- Assets are written only under a caller-supplied directory; the caller must
  point it at a Git-excluded evidence folder (default suggestion documented).
- No cookies, tokens, or credentials are stored or logged by this module.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal, Protocol
from urllib.parse import urljoin, urlparse

from .tls import resolve_verify_tls

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


@dataclass(frozen=True)
class AuthenticatedDownloadAuthorization:
    """Explicit, narrowly scoped consent for ONE authenticated asset download.

    This object must be constructed deliberately by an approving operator
    (outside this module — the downloader never creates one). It is frozen,
    scoped to exactly ONE approved asset path, and requires a non-empty
    operator identity and justification so approvals are auditable.

    A live session cookie, token, or `authenticated_allowed` state never
    substitutes for this object.
    """

    approved_path: str
    operator: str
    reason: str

    def __post_init__(self) -> None:
        asset = APPROVED_ASSETS.get(self.approved_path)
        if asset is None or not asset.requires_authenticated_session:
            raise ValueError(
                "AuthenticatedDownloadAuthorization.approved_path must name an "
                "approved asset that requires an authenticated session; got "
                f"{self.approved_path!r}."
            )
        if not self.operator or not self.operator.strip():
            raise ValueError("AuthenticatedDownloadAuthorization.operator must be non-empty.")
        if not self.reason or not self.reason.strip():
            raise ValueError("AuthenticatedDownloadAuthorization.reason must be non-empty.")


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
        # Fail closed BEFORE any I/O: verify_tls=False (or any weakening value)
        # is rejected here, never silently forwarded to the session.
        self._verify_tls = resolve_verify_tls(verify_tls)
        self._dry_run = dry_run
        self._max_bytes = max_asset_bytes

    def plan(self) -> list[tuple[str, Path]]:
        """The exact (path, destination) pairs this downloader is allowed to fetch."""
        return [
            (a.path, self._dest / a.path.lstrip("/").replace("/", "_"))
            for a in APPROVED_ASSETS.values()
        ]

    def _validate_asset(
        self,
        path: str,
        authorization: AuthenticatedDownloadAuthorization | None,
    ) -> FirmwareAsset:
        asset = APPROVED_ASSETS.get(path)
        if asset is None:
            raise AssetDownloadError(f"'{path}' is not on the approved asset list.")
        if not path.startswith("/") or ".." in path or "\\" in path:
            raise AssetDownloadError("Refusing non-canonical or traversal paths.")
        if asset.requires_authenticated_session:
            if not isinstance(authorization, AuthenticatedDownloadAuthorization):
                raise AssetDownloadError(
                    f"{path} requires an authenticated session; the download is "
                    "refused unless an AuthenticatedDownloadAuthorization naming "
                    "this exact path is supplied to fetch() for this call. "
                    "Session state alone never authorizes a download. "
                    "See docs/PHASE3_JS_ANALYSIS.md."
                )
            if authorization.approved_path != path:
                raise AssetDownloadError(
                    f"Authorization covers '{authorization.approved_path}', "
                    f"not '{path}'; refusing to authorize an unrelated asset."
                )
        return asset

    def fetch(
        self,
        path: str,
        *,
        authorization: AuthenticatedDownloadAuthorization | None = None,
    ) -> Path | None:
        """Download one approved asset and store it under ``dest_dir``.

        ``authorization`` is required only for assets flagged
        ``requires_authenticated_session``; it must name exactly ``path``.
        Validation happens before any network I/O.
        """
        from .errors import ModemHTTPError

        asset = self._validate_asset(path, authorization)
        if self._dry_run:
            return None  # no network I/O in dry-run mode

        import requests  # local import: not needed for plan()/dry-run tests

        session = self._session
        created_here = False
        if session is None:
            session = requests.Session()
            # Caller-injected sessions keep their explicit configuration;
            # internally created sessions must not inherit environment
            # proxies, .netrc credentials, or REQUESTS_CA_BUNDLE (odd
            # redirection risk for a fixed modem origin). TLS verification
            # itself is unaffected — ``verify`` is passed per request.
            session.trust_env = False
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
            self._publish(path, dest, body)
            return dest
        finally:
            if created_here:
                session.close()  # type: ignore[union-attr]

    def _publish(self, path: str, dest: Path, body: bytes) -> None:
        """Atomically publish ``body`` at ``dest`` — never overwriting anything.

        Temporary file: created with :func:`tempfile.mkstemp` in the
        destination's own directory using a UNIQUE random name and exclusive
        creation (``O_CREAT|O_EXCL``), so concurrent runs can never collide
        with, overwrite, or delete each other's temporary files. Only the
        temporary file created by THIS call is ever cleaned up.

        Publication: ``os.link(tmp, dest)`` fails atomically if ``dest``
        exists (on both Windows/NTFS and POSIX), so a destination created
        even nanoseconds earlier — or by a concurrent process — is preserved
        byte-for-byte. There is no rename/replace step and no silent clobber
        on any platform: on filesystems without hard-link support publication
        is REFUSED (fail-closed) instead of falling back to an overwriting
        rename. On success the temp file is unlinked (the hard link keeps
        the published inode alive); on every failure path the temp file is
        unlinked and ``dest`` is never touched.
        """
        if dest.exists():
            raise AssetDownloadError(
                f"Destination for {path} already exists ({dest.name}); the "
                "previous file is preserved and nothing was overwritten."
            )
        fd, tmp_name = tempfile.mkstemp(
            dir=str(dest.parent), prefix=dest.name + ".", suffix=".part"
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
            try:
                os.link(tmp, dest)
            except FileExistsError as exc:
                # Destination appeared concurrently: preserve it byte-for-byte.
                raise AssetDownloadError(
                    f"Destination for {path} appeared during publication; the "
                    "concurrently created file was preserved, nothing overwritten."
                ) from exc
            except OSError as exc:
                # No hard-link support here (e.g. exFAT/network share): fail
                # closed rather than risk a clobbering rename fallback.
                raise AssetDownloadError(
                    f"Filesystem does not support atomic no-clobber publication "
                    f"for {dest.parent}; refusing to store ({exc.errno})."
                ) from exc
        finally:
            tmp.unlink(missing_ok=True)

    def _peer_origin(self, url: str) -> str:
        return urlparse(url).hostname

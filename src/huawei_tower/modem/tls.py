"""Fixed TLS verification policy for every modem connection (Phase 3.1).

Policy: TLS certificate verification is ALWAYS enabled.

- ``True``  -> use the default trust store (requests/urllib3 default).
- ``str``   -> path to an existing CA bundle file; verification stays ON and
  the bundle is additionally trusted.
- ``False`` (or any other value) -> rejected immediately with ``ValueError``,
  before any network I/O is possible.

There is deliberately no supported way to turn verification off. Callers
cannot opt out via booleans, warnings suppression, or environment variables;
this helper is the single validation point used by both the modem API client
and the JS asset downloader.
"""

from __future__ import annotations

from pathlib import Path

VerifyTls = "True (default trust store) or the absolute path of an existing CA bundle"


def resolve_verify_tls(value: bool | str) -> bool | str:
    """Validate the caller's verification preference without ever disabling it.

    Returns ``True`` for the default trust store, or the resolved absolute CA
    bundle path. Never returns ``False``; raises ``ValueError`` for anything
    that would weaken or bypass verification.
    """
    if value is False:
        raise ValueError(
            "TLS certificate verification cannot be disabled for modem "
            "connections. Pass True (default trust store) or the path of a "
            "CA bundle to trust instead."
        )
    if isinstance(value, bool):
        if value is True:
            return True
        raise ValueError("verify_tls: only True is accepted for booleans.")
    if not isinstance(value, str):
        raise ValueError(
            "verify_tls must be True or a non-empty CA bundle file path."
        )
    candidate = value.strip()
    if not candidate:
        raise ValueError(
            "verify_tls must be True or a non-empty CA bundle file path."
        )
    bundle = Path(candidate)
    if not bundle.is_file():
        raise ValueError(
            f"verify_tls CA bundle path does not exist or is not a file: {candidate}"
        )
    return str(bundle.resolve())

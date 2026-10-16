"""Fixed TLS verification policy for every modem connection (Phase 3.1).

Policy: TLS certificate verification is ALWAYS enabled.

- ``True``  -> use the default trust store (requests/urllib3 default).
- ``str``   -> path to an existing CA bundle file; verification stays ON and
  the bundle is additionally trusted. The file must contain well-formed PEM
  certificate blocks (X.509 parsing is validated offline at configuration
  time, so a malformed bundle fails BEFORE any request rather than deep
  inside a TLS handshake). Non-certificate PEM blocks are ignored.
- ``False`` (or any other value) -> rejected immediately with ``ValueError``,
  before any network I/O is possible.

There is deliberately no supported way to turn verification off. Callers
cannot opt out via booleans, warnings suppression, or environment variables;
this helper is the single validation point used by both the modem API client
and the JS asset downloader.
"""

from __future__ import annotations

from pathlib import Path

PEM_CERT_BEGIN = b"-----BEGIN CERTIFICATE-----"
PEM_CERT_END = b"-----END CERTIFICATE-----"


def _validate_ca_bundle(candidate: str) -> str:
    """Reject CA bundles that contain no parseable X.509 PEM certificate.

    This is a configuration-time sanity check, not a full chain-validity
    audit: a syntactically valid but expired/untrusted certificate still
    passes here and fails later *inside TLS* (securely, not weakened).
    """
    raw = Path(candidate).read_bytes()
    blocks: list[bytes] = []
    position = 0
    while True:
        start = raw.find(PEM_CERT_BEGIN, position)
        if start < 0:
            break
        end = raw.find(PEM_CERT_END, start)
        if end < 0:
            raise ValueError(
                f"verify_tls CA bundle contains a truncated PEM certificate "
                f"(no END marker): {candidate}"
            )
        blocks.append(raw[start: end + len(PEM_CERT_END)])
        position = end + len(PEM_CERT_END)
    if not blocks:
        raise ValueError(
            f"verify_tls CA bundle contains no PEM certificate block: {candidate}"
        )
    from cryptography import x509

    for index, block in enumerate(blocks, start=1):
        try:
            x509.load_pem_x509_certificate(block)
        except Exception as exc:
            raise ValueError(
                f"verify_tls CA bundle holds a malformed PEM certificate "
                f"(block #{index}): {candidate}"
            ) from exc
    return str(Path(candidate).resolve())


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
    return _validate_ca_bundle(candidate)

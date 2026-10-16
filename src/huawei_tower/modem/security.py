from __future__ import annotations

import getpass
import re


def prompt_password(username: str = "admin") -> str:
    """Prompt locally without echoing the password; never stores it."""
    return getpass.getpass(f"Password for modem user {username} (input hidden): ")


_VALUE = r"(?:\"[^\"]*\"|'[^']*'|[^,\s;}\"']+)"

_SECRET_PATTERNS = [
    # password-like key/value pairs (JSON quotes around keys tolerated)
    re.compile(r"(?i)(password|passwd|pwd|passphrase|pin)\s*\"?\s*[:=]\s*" + _VALUE),
    # Huawei session / CSRF material
    re.compile(
        r"(?i)(SessionID|SesInfo|TokInfo|__RequestVerificationToken\w*|csrf_token)\s*\"?\s*[:=]\s*"
        + _VALUE
    ),
    # Raw Cookie / Set-Cookie headers (may embed SessionID or auth state)
    re.compile(r"(?i)((?:set-\s*)?cookie)\s*:\s*[^\r\n]+"),
    # Material that authenticates like a password (proof or derived secrets)
    re.compile(
        r"(?i)(clientproof|clientsignature|storedkey|serverkey|hasholdnewpwd|newstoredkey|newserverkey)\s*\"?\s*[:=]\s*"
        + _VALUE
    ),
    # Nonce-bearing SCRAM exchanges should never leak either
    re.compile(
        r"(?i)(firstnonce|servernonce|finalnonce)\s*\"?\s*[:=]\s*" + _VALUE
    ),
]


def redact_secrets(value: str) -> str:
    """Best-effort redaction for logs/evidence; do not use as the only control."""
    result = value
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(r"\1=<redacted>", result)
    return result

from __future__ import annotations

import getpass
import re


def prompt_password(username: str = "admin") -> str:
    """Prompt locally without echoing the password; never stores it."""
    return getpass.getpass(f"Password for modem user {username} (input hidden): ")


_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^,\s;]+"),
    re.compile(r"(?i)(SesInfo|TokInfo|SessionID|__RequestVerificationToken)\s*[:=]\s*[^,\s;]+"),
]


def redact_secrets(value: str) -> str:
    """Best-effort redaction for logs/evidence; do not use as the only security control."""
    result = value
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(r"\1=<redacted>", result)
    return result

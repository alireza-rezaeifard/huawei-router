"""Offline implementation of the H158-381 SCRAM login algorithm.

Evidence source (read-only, no live login performed in this phase):
- ``evidence/raw/lib_emui-crypto.js`` line 7558:
  ``CryptoJS.SCRAM`` = WordArray subclass with ``keySize: 8`` (words, i.e. 32 bytes),
  ``hasher: SHA256``, ``hmac: HmacSHA256``. Note the non-standard argument order of
  ``signature(e, t) -> HmacSHA256(message=e, key=t)`` and of ``clientKey``/
  ``serverKey`` (the string constant is the HMAC *key*, the derived key material is
  the *message*).
- ``evidence/raw/js__js_main.js_r_1709723942`` (minified; symbols anchored):
  challenge flow constructs ``firstnonce`` with
  ``CryptoJS.SCRAM().nonce().toString()`` (32 random bytes, lower-case hex),
  posts ``{username, firstnonce, mode:1}`` to ``/api/user/challenge_login``,
  and on the response builds
  ``authMessage = firstnonce + "," + servernonce + "," + servernonce``
  (the server nonce is concatenated twice), then posts
  ``{clientproof, finalnonce}`` to ``/api/user/authentication_login`` and,
  when the challenge response carries ``newType='1'`` plus ``newSalt``/
  ``newIterations``, appends ``hashOldNewPwd = SHA256(newStoredKey + newServerKey
  + clientproof)``, ``newStoredKey``, ``newServerKey``.

This module performs NO network operations and never stores credentials:
all functions are pure and callers pass values in and out explicitly.
The characteristic constants are defined verbatim from the firmware code.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

AUTH_CHALLENGE_ENDPOINT = "/api/user/challenge_login"
AUTH_FINALIZE_ENDPOINT = "/api/user/authentication_login"

NONCE_BYTES = 32
DERIVED_KEY_BYTES = 32

CLIENT_KEY_LABEL = b"Client Key"
SERVER_KEY_LABEL = b"Server Key"


class ScramDataError(ValueError):
    """Raised for structurally invalid challenge/response data."""


def _as_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def hex_decode(hex_string: str, *, field: str) -> bytes:
    """Convert a firmware hex string to bytes, rejecting malformed input."""
    if not isinstance(hex_string, str) or hex_string == "":
        raise ScramDataError(f"{field}: expected a non-empty hex string")
    try:
        return bytes.fromhex(hex_string)
    except ValueError as exc:
        raise ScramDataError(f"{field}: not valid hex") from exc


def new_nonce_hex() -> str:
    """32 random bytes as lower-case hex, matching ``SCRAM.nonce().toString()``.

    Nonce entropy is provided by Python ``secrets`` (never a fixed value).
    """
    return secrets.token_hex(NONCE_BYTES)


def _normalize_iterations(value: Any) -> int:
    """XML dictionaries deliver digits as strings; accept exact digit strings only."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ScramDataError("iterations: expected an integer")
    if isinstance(value, str):
        if not value.isdigit():
            raise ScramDataError("iterations: expected an integer")
        return int(value)
    return value


def pbkdf2_sha256(password: str | bytes, salt: bytes, iterations: int | str) -> bytes:
    """PBKDF2-HMAC-SHA256, 32-byte output (CryptoJS ``keySize: 8`` words).

    ``salt`` is the raw salt bytes decoded from the challenge ``<salt>`` hex.
    """
    iterations = _normalize_iterations(iterations)
    if iterations <= 0:
        raise ScramDataError("iterations: must be positive")
    if not salt:
        raise ScramDataError("salt: must not be empty")
    if not password:
        raise ScramDataError("password: must not be empty")
    return hashlib.pbkdf2_hmac(
        "sha256", _as_bytes(password), salt, iterations, dklen=DERIVED_KEY_BYTES
    )


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 with explicit (key, message) argument order."""
    return hmac.new(key, message, hashlib.sha256).digest()


def sha256_hex(text: str) -> str:
    """SHA-256 of a UTF-8 string; lower-case hex (main.js built-in SHA256)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def salted_password_hex(password: str | bytes, salt: bytes, iterations: int) -> str:
    return pbkdf2_sha256(password, salt, iterations).hex()


def client_key(salted_password: bytes) -> bytes:
    """Firmware: ``this.cfg.hmac(e, 'Client Key')`` — message keyed by string.

    Reversed relative to standard SCRAM; replicated exactly.
    """
    return hmac_sha256(CLIENT_KEY_LABEL, salted_password)


def server_key(salted_password: bytes) -> bytes:
    return hmac_sha256(SERVER_KEY_LABEL, salted_password)


def stored_key(client_key_bytes: bytes) -> bytes:
    return hashlib.sha256(client_key_bytes).digest()


def firmware_signature(message: bytes, key: bytes) -> bytes:
    """Firmware ``signature(e, t)`` = HMAC-SHA256(message=e, key=t)."""
    return hmac_sha256(key, message)


def auth_message(first_nonce: str, server_nonce: str) -> str:
    """``firstnonce,servernonce,servernonce`` — server nonce appears twice."""
    if not first_nonce or not server_nonce:
        raise ScramDataError("nonces: must be non-empty")
    for name, value in (("first_nonce", first_nonce), ("server_nonce", server_nonce)):
        if not isinstance(value, str) or any(ch in value for ch in ", \r\n"):
            raise ScramDataError(f"{name}: must be a compact nonce string")
    return f"{first_nonce},{server_nonce},{server_nonce}"


def client_proof_hex(
    password: str | bytes,
    salt: bytes,
    iterations: int,
    auth_message_text: str,
) -> str:
    """``clientProof`` = hex(clientKey XOR HMAC(key=authMessage, msg=storedKey)).

    The XOR orientation matches ``s.words[a] ^= c.words[a]`` in the firmware;
    HMAC argument order matches :func:`firmware_signature`.
    """
    sp = pbkdf2_sha256(password, salt, iterations)
    ck = client_key(sp)
    sk = stored_key(ck)
    sig = firmware_signature(sk, _as_bytes(auth_message_text))
    proof = bytes(a ^ b for a, b in zip(ck, sig))
    return proof.hex()


def server_proof_hex(
    password: str | bytes,
    salt: bytes,
    iterations: int,
    auth_message_text: str,
) -> str:
    """``serverProof`` = hex(HMAC(key=authMessage, msg=serverKey))."""
    sp = pbkdf2_sha256(password, salt, iterations)
    sk = server_key(sp)
    return firmware_signature(sk, _as_bytes(auth_message_text)).hex()


def _p_challenge_fields(data: dict[str, Any]) -> tuple[str, int, str]:
    try:
        salt_hex = data["salt"]
        iterations_raw = data["iterations"]
        server_nonce = data["servernonce"]
    except KeyError as exc:
        raise ScramDataError(f"challenge response missing field: {exc}") from exc
    if not isinstance(server_nonce, str):
        raise ScramDataError("servernonce: expected a string")
    return salt_hex, iterations_raw, server_nonce


def challenge_new_type(data: dict[str, Any]) -> bool:
    """True when the firmware password-migration branch must run."""
    return str(data.get("newType", "")) == "1"


def build_challenge_login_payload(username: str, first_nonce: str) -> dict[str, Any]:
    """XML request data posted to ``/api/user/challenge_login`` (mode 1)."""
    if not username:
        raise ScramDataError("username: must be non-empty")
    return {"username": username, "firstnonce": first_nonce, "mode": 1}


def build_authentication_login_payload(
    password: str | bytes,
    first_nonce: str,
    challenge: dict[str, Any],
) -> dict[str, Any]:
    """Full second-step body for ``/api/user/authentication_login``.

    ``challenge`` is the parsed challenge response. Validation is fail-closed:
    any missing/invalid field raises :class:`ScramDataError`.
    """
    salt_hex, iterations_raw, server_nonce = _p_challenge_fields(challenge)
    salt = hex_decode(salt_hex, field="salt")
    hex_decode(server_nonce, field="servernonce")  # validity check; echo verbatim
    am = auth_message(first_nonce, server_nonce)
    payload: dict[str, Any] = {
        "clientproof": client_proof_hex(password, salt, iterations_raw, am),
        "finalnonce": server_nonce,
    }
    if challenge_new_type(challenge):
        try:
            new_salt_hex = challenge["newSalt"]
            new_iterations = challenge["newIterations"]
        except KeyError as exc:
            raise ScramDataError(f"challenge response missing field: {exc}") from exc
        new_salt = hex_decode(new_salt_hex, field="newSalt")
        new_sp_hex = salted_password_hex(password, new_salt, new_iterations)
        new_sp = bytes.fromhex(new_sp_hex)
        new_stored = stored_key(client_key(new_sp)).hex()
        new_server = server_key(new_sp).hex()
        payload["hashOldNewPwd"] = sha256_hex(new_stored + new_server + payload["clientproof"])
        payload["newStoredKey"] = new_stored
        payload["newServerKey"] = new_server
    return payload


def server_key_hex_for_verification(
    password: str | bytes,
    challenge: dict[str, Any],
    first_nonce: str,
) -> str:
    """Hex server key, needed to verify the final response ciphertext-free."""
    salt_hex, iterations_raw, _ = _p_challenge_fields(challenge)
    salt = hex_decode(salt_hex, field="salt")
    return server_key(pbkdf2_sha256(password, salt, iterations_raw)).hex()


def verify_authentication_login_response(
    response_payload: dict[str, Any],
    challenge: dict[str, Any],
    first_nonce: str,
    password: str | bytes,
) -> bool:
    """Validate ``serversignature`` and ``rsapubkeysignature`` per main.js."""
    for field in ("serversignature", "rsapubkeysignature", "rsan"):
        if field not in response_payload:
            raise ScramDataError(f"authentication response missing field: {field}")
    if not isinstance(response_payload["rsan"], str):
        raise ScramDataError("rsan: expected a string")
    if not _looks_hex(response_payload["rsan"]) or response_payload["rsan"] == "":
        # ``rsan`` arrives as a hex string per jsrsasign RSAKey.setPublic.
        raise ScramDataError("rsan: not valid hex")
    salt_hex, iterations_raw, server_nonce = _p_challenge_fields(challenge)
    salt = hex_decode(salt_hex, field="salt")
    am = auth_message(first_nonce, server_nonce)
    expected_server_sig = server_proof_hex(password, salt, iterations_raw, am)
    if response_payload["serversignature"] != expected_server_sig:
        return False
    sp = pbkdf2_sha256(password, salt, iterations_raw)
    server_key_bytes = server_key(sp)
    modulus_bytes = bytes.fromhex(response_payload["rsan"])
    expected_rsa_sig = firmware_signature(modulus_bytes, server_key_bytes).hex()
    return response_payload["rsapubkeysignature"] == expected_rsa_sig


def _looks_hex(value: str) -> bool:
    try:
        bytes.fromhex(value)
        return True
    except (ValueError, TypeError):
        return False

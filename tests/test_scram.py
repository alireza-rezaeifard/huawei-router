"""Offline SCRAM algorithm tests â€” no network, no live credentials involved.

Independent verification strategy:
1. ``cryptography`` (OpenSSL-backed) primitives are used as an INDEPENDENT
   reference for SHA-256, HMAC-SHA256 and PBKDF2-HMAC-SHA256 â€” separate
   implementations from the stdlib ``hashlib``/``hmac`` used inside the module.
2. The firmware-specific construction (HMAC orientation, double server nonce,
   XOR order, migration composition) is re-derived in the tests directly from
   the decompiled JS semantics, so an error in
   ``huawei_tower.modem.scram`` cannot pass by copying.
3. Golden vectors were generated once from the reference construction in this
   file's logic and are asserted bit-for-bit.
"""

from __future__ import annotations

import pytest

from huawei_tower.modem import scram

PASSWORD = "V3ct0rTest#42"
SALT_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
ITERATIONS = 4096
FIRST_NONCE = "a" * 64
SERVER_NONCE = "b" * 64
RSAN_HEX = "ef0123456789" * 12


def _c_sha256_hex(data: bytes) -> str:
    from cryptography.hazmat.primitives import hashes

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def _c_hmac_sha256(key: bytes, message: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.hmac import HMAC

    h = HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


def _c_pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=dklen,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def _reference_components() -> dict[str, str]:
    """Independent re-derivation of the firmware construction from JS semantics.

    literal transcription of the emui-crypto.js SCRAM object:
      - clientKey(km)   = HMAC(key="Client Key", msg=km)
      - serverKey(km)   = HMAC(key="Server Key", msg=km)
      - storedKey(ck)   = SHA256(ck)
      - signature(m, k) = HMAC(key=k, msg=m)      (note: key is SECOND arg)
      - clientProof     = clientKey XOR signature(storedKey_raw, authMessage)
      - serverProof     = signature(serverKey_raw, authMessage)
    where authMessage = firstnonce,servernonce,servernonce.
    """
    salt = bytes.fromhex(SALT_HEX)
    sp = _c_pbkdf2_sha256(PASSWORD.encode(), salt, ITERATIONS, 32)
    ck = _c_hmac_sha256(b"Client Key", sp)
    sk = _c_hmac_sha256(b"Server Key", sp)
    am = f"{FIRST_NONCE},{SERVER_NONCE},{SERVER_NONCE}".encode()
    stored_raw = bytes.fromhex(_c_sha256_hex(ck))           # storedKey is a WordArray (raw bytes)
    client_sig = _c_hmac_sha256(am, stored_raw)             # signature(msg=stored_raw, key=am)
    proof = bytes(a ^ b for a, b in zip(ck, client_sig)).hex()
    server_proof = _c_hmac_sha256(am, sk).hex()             # signature(msg=sk_raw, key=am)
    return {
        "sp": sp.hex(),
        "client_key": ck.hex(),
        "server_key": sk.hex(),
        "stored_key": stored_raw.hex(),
        "client_proof": proof,
        "server_proof": server_proof,
        "am": am.decode(),
    }


REFERENCE = _reference_components()


def test_salted_password_matches_independent_reference():
    assert (
        scram.salted_password_hex(PASSWORD, bytes.fromhex(SALT_HEX), ITERATIONS)
        == REFERENCE["sp"]
    )


def test_client_and_server_keys_match_reference():
    sp = bytes.fromhex(scram.salted_password_hex(PASSWORD, bytes.fromhex(SALT_HEX), ITERATIONS))
    assert scram.client_key(sp).hex() == REFERENCE["client_key"]
    assert scram.server_key(sp).hex() == REFERENCE["server_key"]
    assert scram.stored_key(scram.client_key(sp)).hex() == REFERENCE["stored_key"]


def test_auth_message_duplicates_server_nonce():
    am = scram.auth_message(FIRST_NONCE, SERVER_NONCE)
    assert am == REFERENCE["am"]
    assert am.count(SERVER_NONCE) == 2


def test_client_proof_matches_independent_reference():
    salt = bytes.fromhex(SALT_HEX)
    am = scram.auth_message(FIRST_NONCE, SERVER_NONCE)
    assert scram.client_proof_hex(PASSWORD, salt, ITERATIONS, am) == REFERENCE["client_proof"]


def test_server_proof_matches_independent_reference():
    salt = bytes.fromhex(SALT_HEX)
    am = scram.auth_message(FIRST_NONCE, SERVER_NONCE)
    assert scram.server_proof_hex(PASSWORD, salt, ITERATIONS, am) == REFERENCE["server_proof"]


def test_golden_vector_end_to_end_payload():
    salt = bytes.fromhex(SALT_HEX)
    am = scram.auth_message(FIRST_NONCE, SERVER_NONCE)
    assert scram.client_proof_hex(PASSWORD, salt, ITERATIONS, am) == (
        "897f9713b03ba435bb057b20757f91f0710458be43c2ab8b0c4e90614280b938"
    )
    assert scram.server_proof_hex(PASSWORD, salt, ITERATIONS, am) == (
        "848441a05d030265feb07917726a64215cd85ca4900307278d3cdbde9f0ddb9d"
    )


def test_authentication_payload_builds_and_contains_exact_fields():
    challenge = {"salt": SALT_HEX, "iterations": str(ITERATIONS), "servernonce": SERVER_NONCE}
    payload = scram.build_authentication_login_payload(PASSWORD, FIRST_NONCE, challenge)
    assert set(payload) == {"clientproof", "finalnonce"}
    assert payload["finalnonce"] == SERVER_NONCE
    assert payload["clientproof"] == REFERENCE["client_proof"]


def test_new_type_migration_fields_are_included():
    challenge = {
        "salt": SALT_HEX,
        "iterations": ITERATIONS,
        "servernonce": SERVER_NONCE,
        "newType": "1",
        "newSalt": "deadbeef" * 9,
        "newIterations": "2048",
    }
    payload = scram.build_authentication_login_payload(PASSWORD, FIRST_NONCE, challenge)
    assert payload["newStoredKey"] == (
        "f296f54ea651e4f2471e5ea55afa4f239ff01275346b04642e3fb976985fc0fd"
    )
    assert payload["newServerKey"] == (
        "2d023674d1329ec1419530590b31665fd39839506f2109882b183f66879f1f9b"
    )
    composition = _c_sha256_hex(
        (
            payload["newStoredKey"] + payload["newServerKey"] + REFERENCE["client_proof"]
        ).encode()
    )
    assert payload["hashOldNewPwd"] == composition == (
        "50d115382a3a64b1a6e02c75dffcd9c91f131561998eab5efc61945c52fbdccc"
    )


def test_response_verification_success():
    challenge = {"salt": SALT_HEX, "iterations": ITERATIONS, "servernonce": SERVER_NONCE}
    payload = {
        "rsan": RSAN_HEX,
        "serversignature": REFERENCE["server_proof"],
        "rsapubkeysignature": (
            "1e95c8ceff5a63b8c520b36e3bd29edb832295a4d8bdffb3553ab9a9d1264546"
        ),
    }
    assert scram.verify_authentication_login_response(payload, challenge, FIRST_NONCE, PASSWORD)


def test_response_verification_fails_on_wrong_serversignature():
    challenge = {"salt": SALT_HEX, "iterations": ITERATIONS, "servernonce": SERVER_NONCE}
    payload = {
        "rsan": RSAN_HEX,
        "serversignature": "00" * 32,
        "rsapubkeysignature": "1e95c8ceff5a63b8c520b36e3bd29edb832295a4d8bdffb3553ab9a9d1264546",
    }
    assert not scram.verify_authentication_login_response(payload, challenge, FIRST_NONCE, PASSWORD)


def test_response_verification_fails_on_wrong_rsapubkeysignature():
    challenge = {"salt": SALT_HEX, "iterations": ITERATIONS, "servernonce": SERVER_NONCE}
    payload = {
        "rsan": RSAN_HEX,
        "serversignature": REFERENCE["server_proof"],
        "rsapubkeysignature": "00" * 32,
    }
    assert not scram.verify_authentication_login_response(payload, challenge, FIRST_NONCE, PASSWORD)


def test_missing_challenge_field_raises():
    challenge = {"salt": SALT_HEX, "servernonce": SERVER_NONCE}
    with pytest.raises(scram.ScramDataError):
        scram.build_authentication_login_payload(PASSWORD, FIRST_NONCE, challenge)


def test_bad_hex_salt_raises():
    challenge = {"salt": "zz", "iterations": 10, "servernonce": SERVER_NONCE}
    with pytest.raises(scram.ScramDataError):
        scram.build_authentication_login_payload(PASSWORD, FIRST_NONCE, challenge)


def test_non_positive_iterations_raises():
    with pytest.raises(scram.ScramDataError):
        scram.pbkdf2_sha256(PASSWORD, b"salt", 0)
    with pytest.raises(scram.ScramDataError):
        scram.pbkdf2_sha256(PASSWORD, b"salt", -1)
    with pytest.raises(scram.ScramDataError):
        scram.pbkdf2_sha256(PASSWORD, b"salt", "12x")


def test_empty_salt_and_empty_password_raise():
    with pytest.raises(scram.ScramDataError):
        scram.pbkdf2_sha256(PASSWORD, b"", 10)
    with pytest.raises(scram.ScramDataError):
        scram.pbkdf2_sha256("", b"salt", 10)


def test_missing_response_field_raises():
    challenge = {"salt": SALT_HEX, "iterations": ITERATIONS, "servernonce": SERVER_NONCE}
    with pytest.raises(scram.ScramDataError):
        scram.verify_authentication_login_response({"rsan": "aa"}, challenge, FIRST_NONCE, PASSWORD)


def test_invalid_rsan_raises():
    challenge = {"salt": SALT_HEX, "iterations": ITERATIONS, "servernonce": SERVER_NONCE}
    payload = {"rsan": "not-hex", "serversignature": "00" * 32, "rsapubkeysignature": "00" * 32}
    with pytest.raises(scram.ScramDataError):
        scram.verify_authentication_login_response(payload, challenge, FIRST_NONCE, PASSWORD)


def test_new_type_with_missing_new_salt_raises():
    challenge = {
        "salt": SALT_HEX, "iterations": ITERATIONS, "servernonce": SERVER_NONCE,
        "newType": "1", "newIterations": "2048",
    }
    with pytest.raises(scram.ScramDataError):
        scram.build_authentication_login_payload(PASSWORD, FIRST_NONCE, challenge)


def test_auth_message_rejects_embedded_commas_and_whitespace():
    with pytest.raises(scram.ScramDataError):
        scram.auth_message("a,b", "c")
    with pytest.raises(scram.ScramDataError):
        scram.auth_message("a b", "c")
    with pytest.raises(scram.ScramDataError):
        scram.auth_message("", "c")


def test_nonce_generation_is_valid_hex_of_32_bytes():
    nonce = scram.new_nonce_hex()
    assert len(nonce) == 64
    bytes.fromhex(nonce)
    assert nonce != scram.new_nonce_hex()


def test_challenge_payload_shape():
    payload = scram.build_challenge_login_payload("admin", scram.new_nonce_hex())
    assert payload == {
        "username": "admin",
        "firstnonce": payload["firstnonce"],
        "mode": 1,
    }
    with pytest.raises(scram.ScramDataError):
        scram.build_challenge_login_payload("", "abc")

from huawei_tower.modem.security import redact_secrets


def test_redacts_password_and_session_material():
    text = "password=secret SesInfo:abc123 TokInfo=csrf123"
    cleaned = redact_secrets(text)
    assert "secret" not in cleaned
    assert "abc123" not in cleaned
    assert "csrf123" not in cleaned


def test_redacts_set_cookie_and_bare_sessionid():
    cleaned = redact_secrets("Set-Cookie: SessionID=8aaf18aa..."
                             "\nCookie: SessionID=dead; a=b"
                             "\n{SessionID: 0x123}")
    assert "8aaf18aa" not in cleaned
    assert "dead" not in cleaned or "Cookie=<redacted>" in cleaned
    assert "Set-Cookie" in cleaned


def test_redacts_verification_token_headers():
    cleaned = redact_secrets("__RequestVerificationTokenone: abc __RequestVerificationToken: def")
    assert "abc" not in cleaned
    assert "def" not in cleaned


def test_redacts_scram_derived_material_and_nonces():
    cleaned = redact_secrets("clientproof=abc hashOldNewPwd=def firstnonce=0012 servernonce=ffee")
    for fragment in ("abc", "def", "0012", "ffee"):
        assert fragment not in cleaned


def test_logs_still_parseable_after_redaction():
    cleaned = redact_secrets('{"password": "hunter2", "endpoint": "/api/user/login", "status": 401}')
    assert "hunter2" not in cleaned
    assert "status" in cleaned
    assert "endpoint" in cleaned

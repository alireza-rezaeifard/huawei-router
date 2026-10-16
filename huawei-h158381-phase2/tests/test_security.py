from huawei_tower.modem.security import redact_secrets


def test_redacts_password_and_session_material():
    text = "password=secret SesInfo:abc123 TokInfo=csrf123"
    cleaned = redact_secrets(text)
    assert "secret" not in cleaned
    assert "abc123" not in cleaned
    assert "csrf123" not in cleaned

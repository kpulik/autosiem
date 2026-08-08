from __future__ import annotations

from autosiem.llm import Redactor as LlmRedactor
from autosiem.redaction import Redactor, default_redactor


def test_masks_secrets_and_pii() -> None:
    r = Redactor(mask_pii=True)
    text = 'password="hunter2" token=abc123 email="a.b@example.com" ip=203.0.113.10'
    out = r.redact(text)
    assert "hunter2" not in out
    assert "abc123" not in out
    assert "a.b@example.com" not in out
    assert "203.0.113.10" not in out


def test_without_pii_keeps_ips() -> None:
    r = Redactor(mask_pii=False)
    assert "203.0.113.10" in r.redact("ip=203.0.113.10")
    assert "hunter2" not in r.redact('password="hunter2"')


def test_aws_key_masked() -> None:
    r = Redactor()
    out = r.redact("key=AKIAIOSFODNN7EXAMPLE more")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "<AWS_KEY>" in out


def test_ssh_private_key_block_masked() -> None:
    r = Redactor()
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----"
    out = r.redact(key)
    assert "PRIVATE KEY-----" not in out
    assert "<SSH_KEY>" in out


def test_credit_card_luhn_only() -> None:
    r = Redactor()
    valid = "4532015112830366"  # passes Luhn
    assert valid not in r.redact(f"card {valid}")
    assert "CC_NUMBER" in r.redact(f"card {valid}")
    invalid = "1234567890123456"  # fails Luhn
    assert invalid in r.redact(f"card {invalid}")


def test_default_redactor() -> None:
    r = default_redactor()
    assert r.mask_pii is True
    assert "hunter2" not in r.redact('password="hunter2"')


def test_llm_reexports_redactor() -> None:
    r = LlmRedactor(mask_pii=True)
    out = r.redact('token="sekrit" ip=198.51.100.9')
    assert "sekrit" not in out
    assert "198.51.100.9" not in out
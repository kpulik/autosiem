from __future__ import annotations

import json

import pytest

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

# --- SEC-011: shapes that reached the model unmasked -------------------------
# Every LLM prompt is built with json.dumps, so a JSON key is the common case,
# and it was the one the labelled pattern missed.

_SECRET = "Zx9Qw7Lm2Pk5Rt8Vb3Nc6"
_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS documentation example
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"password": _SECRET}),
        json.dumps({"token": _SECRET}),
        json.dumps({"client_secret": _SECRET}),
        json.dumps({"sessionToken": _SECRET}),
        json.dumps({"SecretAccessKey": _SECRET}),
        json.dumps({"event": json.dumps({"password": _SECRET})}),  # JSON escaped inside a string
        json.dumps({"password": f"pass word {_SECRET}"}),  # a quoted value may contain spaces
        f"client_secret={_SECRET}",
        f"refresh_token={_SECRET}",
        f"aws_secret_access_key = {_SECRET}",
        f"Authorization: SSWS {_SECRET}",
        f"Authorization: Basic {_SECRET}",
    ],
)
def test_labelled_secrets_in_every_shape_are_masked(text: str) -> None:
    assert _SECRET not in Redactor(mask_pii=False).redact(text)


def test_the_label_survives_so_the_reader_knows_a_secret_was_there() -> None:
    out = Redactor(mask_pii=False).redact(json.dumps({"client_secret": _SECRET}))
    assert "client_secret" in out
    assert "<REDACTED>" in out


@pytest.mark.parametrize(
    "text",
    [
        f"aws configure set aws_secret_access_key {_AWS_SECRET}",
        f"creds {_AWS_SECRET} end",
        json.dumps({"SecretAccessKey": _AWS_SECRET}),
    ],
)
def test_bare_aws_secret_access_key_is_masked(text: str) -> None:
    assert _AWS_SECRET not in Redactor(mask_pii=False).redact(text)


@pytest.mark.parametrize("text", [f"session {_JWT} ok", f"id_jwt={_JWT}", json.dumps({"jwt": _JWT})])
def test_jwt_is_masked(text: str) -> None:
    out = Redactor(mask_pii=False).redact(text)
    assert "eyJzdWIi" not in out, out


@pytest.mark.parametrize(
    "token",
    [
        "gho_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
        "ghs_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
        "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
    ],
)
def test_github_token_prefixes_are_masked(token: str) -> None:
    assert token not in Redactor(mask_pii=False).redact(f"leaked {token} here")


@pytest.mark.parametrize(
    "keep",
    [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1, lowercase hex
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",  # Sysmon writes hashes uppercase
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256
        "3f2504e0-4f89-11d3-9a0c-0305e82c3301",  # GUID
        "AUTO-CRED-004",
    ],
)
def test_hashes_and_ids_an_analyst_needs_are_kept(keep: str) -> None:
    assert keep in Redactor(mask_pii=False).redact(f"hashes={keep} rule {keep}")

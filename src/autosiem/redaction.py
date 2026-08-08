"""Per-class secret & PII redaction policies for AutoSIEM.

Redaction is layered and deterministic:

- labelled secrets are always masked (the highest-priority class),
- high-entropy tokens (OpenAI ``sk-``, GitHub ``ghp_``, ``Bearer``, AWS ``AKIA``)
  and SSH private key blocks are always masked,
- credit-card numbers are masked *only* when they pass the Luhn checksum
  (so arbitrary 16-digit numbers are preserved),
- IPs / emails / SSNs / IPv6 addresses are masked only when ``mask_pii`` is set.

The :class:`Redactor` is re-exported from :mod:`autosiem.llm` to keep the
legacy ``autosiem.llm.Redactor`` import path working.
"""

from __future__ import annotations

import re

# --- Labelled secrets ---------------------------------------------------------
# Common labelled credentials: password=x, "token":"y", access_token=z, ...
_LABELLED_SECRET = re.compile(
    r"(\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|access[_-]?token)\b\s*[:=]\s*)"
    r"([\"'][^\"']*[\"']|[^\s,;}\]]+)",
    re.IGNORECASE,
)
# High-entropy / bearer-like fragments (ported from autosiem.llm, keep as-is).
_HIGH_ENTROPY = re.compile(
    r"\b(?:sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{20,}|Bearer\s+[A-Za-z0-9._-]{12,})\b"
)

# AWS access key ID: AKIA followed by exactly 16 base-62 chars.
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# SSH private key block (RSA / OPENSSH / EC / DSA, or bare "PRIVATE KEY" banner).
_SSH_KEY = re.compile(
    r"-----BEGIN (RSA|OPENSSH|EC|DSA)? PRIVATE KEY-----.*?"
    r"-----END (RSA|OPENSSH|EC|DSA)? PRIVATE KEY-----",
    re.DOTALL,
)

# The full secret-pattern list (labelled credentials + high-entropy tokens).
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    _LABELLED_SECRET,
    _HIGH_ENTROPY,
]

# --- PII label patterns: (regex, replacement) --------------------------------
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")

PII_LABEL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_IPV4, "<IP>"),
    (_EMAIL, "<EMAIL>"),
    (_SSN, "<SSN>"),
    (_IPV6, "<IPV6>"),
]

# Credit-card candidate: a run of digits with optional space/dash separators.
_CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,16}\d(?!\d)")


def _valid_credit_card(digits: str) -> bool:
    """Return True if ``digits`` (digits only) satisfies the Luhn checksum."""
    total = 0
    for index, ch in enumerate(reversed(digits)):
        value = int(ch)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_labelled(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("<REDACTED>", text)
    return text


def _mask_high_entropy(text: str) -> str:
    return _AWS_ACCESS_KEY.sub("<AWS_KEY>", text)


def _mask_ssh(text: str) -> str:
    return _SSH_KEY.sub("<SSH_KEY>", text)


def _mask_credit_cards(text: str) -> str:
    def _repl(match: "re.Match[str]") -> str:
        digits = re.sub(r"[^0-9]", "", match.group(0))
        if 13 <= len(digits) <= 16 and _valid_credit_card(digits):
            return "CC_NUMBER"
        return match.group(0)

    return _CREDIT_CARD_RE.sub(_repl, text)


class Redactor:
    """Redacts secrets (always) and optionally PII before sending data to an LLM."""

    def __init__(self, mask_pii: bool = True) -> None:
        self.mask_pii = mask_pii

    def mask_secrets(self, text: str) -> str:
        """Mask secrets only (labelled creds, high-entropy tokens, SSH keys, cards)."""
        text = _mask_labelled(text)
        text = _mask_high_entropy(text)
        text = _mask_ssh(text)
        text = _mask_credit_cards(text)
        return text

    def mask_pii_only(self, text: str) -> str:
        """Apply just the PII label patterns (IP / email / SSN / IPv6)."""
        for pattern, replacement in PII_LABEL_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def redact(self, text: str) -> str:
        text = self.mask_secrets(text)
        if self.mask_pii:
            text = self.mask_pii_only(text)
        return text


def default_redactor() -> Redactor:
    """Return a default :class:`Redactor` with PII masking enabled."""
    return Redactor(mask_pii=True)
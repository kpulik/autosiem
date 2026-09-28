"""Per-class secret & PII redaction policies for AutoSIEM.

Redaction is layered and deterministic:

- labelled secrets are always masked (the highest-priority class), in
  ``key=value``, header and JSON form, keeping the label,
- prefixed tokens (OpenAI ``sk-``, GitHub ``gh*_``/``github_pat_``, ``Bearer``),
  JWTs, AWS access key IDs and secret access keys, and SSH private key blocks
  are always masked,
- credit-card numbers are masked *only* when they pass the Luhn checksum
  (so arbitrary 16-digit numbers are preserved),
- IPs / emails / SSNs / IPv6 addresses are masked only when ``mask_pii`` is set.

The :class:`Redactor` is re-exported from :mod:`autosiem.llm` to keep the
legacy ``autosiem.llm.Redactor`` import path working.
"""

from __future__ import annotations

import re

# --- Labelled secrets ---------------------------------------------------------
# A label is any identifier containing a secret word, so client_secret,
# refresh_token, sessionToken and aws_secret_access_key count, not just the bare
# word (SEC-011). It may be followed by a closing quote, escaped when the JSON is
# itself inside a string, because every LLM prompt is built with json.dumps and
# '"password": "x"' used to slip past a pattern that wanted '=' right after the
# word. Affixes are bounded so a long alphanumeric run cannot backtrack for ever.
_SECRET_WORD = r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)"
_LABELLED_SECRET = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?P<label>[A-Za-z0-9_-]{0,40}" + _SECRET_WORD + r"[A-Za-z0-9_-]{0,40}(?:\\?[\"'])?\s*[:=]\s*)"
    # An "Authorization: <scheme> <token>" value is two words, and matching only
    # the first left the token in place (Bearer before 2026-09-23; Okta's SSWS
    # and Basic until SEC-011 was finished).
    r"(?P<value>(?:(?:Bearer|Basic|SSWS)\s+)?(?:\\?[\"'][^\"'\\]*\\?[\"']|[^\s,;}\]]+))",
    re.IGNORECASE,
)
# High-entropy / bearer-like fragments with a recognisable prefix.
_HIGH_ENTROPY = re.compile(
    # sk- keys carry internal hyphens now (sk-live-..., sk-proj-...), and the
    # original class stopped at the first one, so a live key survived redaction.
    # GitHub issues ghp_/gho_/ghu_/ghs_/ghr_ tokens and github_pat_ fine-grained ones.
    r"\b(?:sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|Bearer\s+[A-Za-z0-9._-]{12,})\b"
)

# A JWT: base64url JSON header and payload (both start "eyJ", i.e. '{"'), then a
# signature that is empty for alg=none.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")

# AWS secret access key: 40 base64 characters with no label of its own, as in
# "aws configure set aws_secret_access_key <key>". Requiring upper, lower and a
# digit or '/'/'+' keeps SHA-1 hashes (single-case hex) out, which an analyst needs.
_AWS_SECRET_KEY = re.compile(
    r"(?<![A-Za-z0-9/+=])"
    r"(?=[A-Za-z0-9/+]{0,39}[A-Z])(?=[A-Za-z0-9/+]{0,39}[a-z])(?=[A-Za-z0-9/+]{0,39}[0-9/+])"
    r"[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
)

# AWS access key ID: AKIA followed by exactly 16 base-62 chars.
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# SSH private key block (RSA / OPENSSH / EC / DSA, or bare "PRIVATE KEY" banner).
_SSH_KEY = re.compile(
    r"-----BEGIN (RSA|OPENSSH|EC|DSA)? PRIVATE KEY-----.*?"
    r"-----END (RSA|OPENSSH|EC|DSA)? PRIVATE KEY-----",
    re.DOTALL,
)

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
    # Keep the label: "client_secret=<REDACTED>" tells the reader a secret was there.
    text = _LABELLED_SECRET.sub(r"\g<label><REDACTED>", text)
    return _HIGH_ENTROPY.sub("<REDACTED>", text)


def _mask_high_entropy(text: str) -> str:
    text = _JWT.sub("<JWT>", text)
    text = _AWS_ACCESS_KEY.sub("<AWS_KEY>", text)
    return _AWS_SECRET_KEY.sub("<AWS_SECRET>", text)


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
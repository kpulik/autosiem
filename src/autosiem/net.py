"""Outbound network policy.

Every remote fetch in AutoSIEM routes through :func:`require_https`, so the rule
is stated once instead of being re-decided at each call site.

Why it matters here specifically: the data AutoSIEM pulls decides what it
detects. A tampered threat-intel bundle yields fabricated findings or silent
false negatives; a tampered ATT&CK index rewrites what every technique means and
therefore every coverage figure. Both are plain match-strings on the wire with
no signature, so transport is the only integrity AutoSIEM has.

Loopback is exempt when a caller opts in: a local model server on
``http://localhost:1234/v1`` never leaves the machine, and it is the documented
default for LM Studio and Ollama.

Recorded as SEC-017 in ``docs/security-review.md``.
"""
from __future__ import annotations

from urllib.parse import urlparse

#: Hosts whose traffic never leaves the machine.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"})


class InsecureURLError(ValueError):
    """A URL was rejected by the transport policy.

    Subclasses ``ValueError`` so existing ``except ValueError`` handlers keep
    working.
    """


def is_loopback(url: str) -> bool:
    """True when ``url`` addresses this machine."""
    host = (urlparse(url).hostname or "").strip().lower()
    if not host:
        return False
    return host in LOOPBACK_HOSTS or host.startswith("127.")


def require_https(url: str, *, allow_loopback: bool = False, what: str = "data") -> str:
    """Return ``url`` if the transport policy allows it, else raise.

    ``allow_loopback`` permits plaintext to this machine only; it never permits
    plaintext to a remote host.
    """
    value = (url or "").strip()
    if value.lower().startswith("https://"):
        return value
    if allow_loopback and is_loopback(value):
        return value
    raise InsecureURLError(
        f"refusing to fetch {what} over a non-HTTPS URL: {url!r}. "
        "A plaintext feed can be tampered with in transit, and AutoSIEM has no "
        "other integrity check on it."
        + ("" if allow_loopback else " Use https://.")
    )

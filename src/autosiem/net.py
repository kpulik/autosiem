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

Redirects get the same rule (:func:`open_url`). ``urllib`` follows them by
default, to plaintext and to other hosts, and it carries every header along, so
an Okta ``SSWS`` token went to whatever host a 302 named. Checking only the first
URL left that open.

Recorded as SEC-017 in ``docs/security-review.md``.
"""
from __future__ import annotations

import urllib.request
from typing import IO, Any
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


#: Headers that carry a credential. They are dropped when a redirect changes
#: origin, the way browsers and ``requests`` do, and ``urllib`` does not.
CREDENTIAL_HEADERS = ("Authorization", "Proxy-authorization", "Cookie")


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


class _RedirectPolicy(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only over HTTPS, and never carry credentials off-origin.

    Plaintext is followed only from loopback to loopback, and only for a caller
    that opted into loopback, so a remote server cannot bounce a request onto
    this machine's plaintext services. Refusing plaintext also rules out the
    cloud metadata endpoint, which speaks HTTP only.
    """

    def __init__(self, allow_loopback: bool) -> None:
        super().__init__()
        self.allow_loopback = allow_loopback

    def redirect_request(
        self, req: urllib.request.Request, fp: IO[bytes], code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        loopback_ok = self.allow_loopback and is_loopback(req.full_url)
        try:
            require_https(newurl, allow_loopback=loopback_ok, what="a redirect")
        except InsecureURLError:
            scheme, host, port = _origin(newurl)
            target = f"{scheme}://{host}" + (f":{port}" if port else "")
            # Name only the origin: a redirect URL can carry a signed query string.
            raise InsecureURLError(
                f"refusing a redirect from {_origin(req.full_url)[1]} to {target}: "
                "redirects must stay on HTTPS"
            ) from None
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin(newurl) != _origin(req.full_url):
            for name in CREDENTIAL_HEADERS:
                new.remove_header(name)
        return new


def open_url(request: urllib.request.Request | str, *, timeout: float, allow_loopback: bool = False) -> Any:
    """``urllib.request.urlopen`` with the redirect policy applied.

    The first URL is the caller's to check with :func:`require_https`; this
    governs every hop after it.
    """
    opener = urllib.request.build_opener(_RedirectPolicy(allow_loopback))
    return opener.open(request, timeout=timeout)

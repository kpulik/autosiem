"""SEC-017: redirects follow the transport rule too.

``urllib`` follows a redirect to plaintext and to any host, and forwards every
header, so before this an Okta ``SSWS`` token reached whatever host a 302 named.
``require_https`` only ever saw the first URL.
"""
from __future__ import annotations

import ast
import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from autosiem.net import InsecureURLError, _RedirectPolicy, open_url

SRC = Path(__file__).resolve().parents[1] / "src" / "autosiem"


def _redirect(original: str, newurl: str, *, allow_loopback: bool = False, method: str = "GET") -> urllib.request.Request | None:
    request = urllib.request.Request(
        original, headers={"Authorization": "SSWS okta-token", "Cookie": "sid=1", "User-Agent": "autosiem"}, method=method
    )
    return _RedirectPolicy(allow_loopback).redirect_request(request, None, 302, "Found", {}, newurl)  # type: ignore[arg-type]


def test_a_same_origin_https_redirect_keeps_the_credential() -> None:
    new = _redirect("https://acme.okta.com/api/v1/logs", "https://acme.okta.com/api/v1/logs?after=2")
    assert new is not None
    assert new.get_header("Authorization") == "SSWS okta-token"


def test_a_cross_origin_redirect_drops_credentials_but_is_followed() -> None:
    """GitHub release downloads redirect to another host; the download must still work."""
    new = _redirect("https://acme.okta.com/api/v1/logs", "https://attacker.example/collect")
    assert new is not None
    assert new.get_header("Authorization") is None
    assert new.get_header("Cookie") is None
    assert new.get_header("User-agent") == "autosiem"


def test_a_different_port_is_a_different_origin() -> None:
    new = _redirect("https://acme.okta.com/x", "https://acme.okta.com:8443/x")
    assert new is not None and new.get_header("Authorization") is None


@pytest.mark.parametrize("newurl", ["http://acme.okta.com/api/v1/logs", "http://169.254.169.254/latest/meta-data/"])
def test_a_redirect_off_https_is_refused(newurl: str) -> None:
    with pytest.raises(InsecureURLError, match="redirects must stay on HTTPS"):
        _redirect("https://acme.okta.com/api/v1/logs", newurl)


def test_a_remote_server_cannot_bounce_a_request_onto_local_plaintext() -> None:
    """Loopback opt-in covers a local model server, not a remote one's redirect."""
    with pytest.raises(InsecureURLError):
        _redirect("https://llm.example/v1/chat", "http://127.0.0.1:1234/v1/chat", allow_loopback=True)


def test_local_to_local_plaintext_is_allowed_when_opted_in() -> None:
    new = _redirect("http://localhost:1234/v1/chat", "http://127.0.0.1:1234/v1/chat/", allow_loopback=True)
    assert new is not None


def test_the_refusal_names_the_origin_not_the_signed_query() -> None:
    with pytest.raises(InsecureURLError) as info:
        _redirect("https://bucket.s3.amazonaws.com/k", "http://evil.example/p?X-Amz-Signature=deadbeef")
    assert "deadbeef" not in str(info.value)
    assert "http://evil.example" in str(info.value)


# --------------------------------------------------------------------------
# end to end over real sockets (loopback, so plaintext is allowed by opt-in)
# --------------------------------------------------------------------------


@pytest.fixture
def two_servers() -> Iterator[tuple[str, dict[str, str | None]]]:
    """Server A redirects to server B (another origin); B records what it received."""
    seen: dict[str, str | None] = {}

    class Target(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen["authorization"] = self.headers.get("Authorization")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"[]")

        def log_message(self, *_args: object) -> None:
            return None

    target = HTTPServer(("127.0.0.1", 0), Target)
    target_url = f"http://localhost:{target.server_address[1]}/stolen"

    class Redirector(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", target_url)
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            return None

    redirector = HTTPServer(("127.0.0.1", 0), Redirector)
    for server in (redirector, target):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{redirector.server_address[1]}/api/v1/logs", seen
    for server in (redirector, target):
        server.shutdown()
        server.server_close()


def test_plain_urllib_leaks_the_token_across_origins(two_servers) -> None:
    """The baseline this module exists for: if this ever stops leaking, the policy can go."""
    url, seen = two_servers
    urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "SSWS okta-token"}), timeout=5).read()
    assert seen["authorization"] == "SSWS okta-token"


def test_open_url_follows_the_redirect_without_the_token(two_servers) -> None:
    url, seen = two_servers
    body = open_url(urllib.request.Request(url, headers={"Authorization": "SSWS okta-token"}), timeout=5, allow_loopback=True).read()
    assert body == b"[]"
    assert seen["authorization"] is None


# --------------------------------------------------------------------------
# every outbound call site goes through the policy
# --------------------------------------------------------------------------

#: net.py builds the governed opener. projections.py builds one that refuses every
#: redirect, which is stricter (tests/test_projections.py proves it with a real 302).
_OPENER_OWNERS = {"net.py", "projections.py"}
_OPENER_NAMES = {"urlopen", "build_opener"}


def _opener_references(source: str) -> list[int]:
    """Line numbers that name urlopen/build_opener in any form: a call, an
    attribute (``request.urlopen``) or ``from urllib.request import urlopen``."""
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and node.attr in _OPENER_NAMES:
            lines.append(node.lineno)
        elif isinstance(node, ast.Name) and node.id in _OPENER_NAMES:
            lines.append(node.lineno)
        elif isinstance(node, ast.ImportFrom) and any(alias.name in _OPENER_NAMES for alias in node.names):
            lines.append(node.lineno)
    return lines


@pytest.mark.parametrize(
    "snippet",
    [
        "import urllib.request\nurllib.request.urlopen(u)",
        "from urllib import request\nrequest.urlopen(u)",
        "from urllib.request import urlopen\nurlopen(u)",
        "import urllib.request\nurllib.request.build_opener().open(u)",
    ],
)
def test_the_guard_sees_every_way_to_reach_urlopen(snippet: str) -> None:
    assert _opener_references(snippet)


def test_the_guard_ignores_unrelated_code() -> None:
    assert not _opener_references("import urllib.request\nreq = urllib.request.Request(u)\nopen_url(req)")


def test_no_module_reaches_urlopen_outside_the_policy() -> None:
    offenders = {
        str(path.relative_to(SRC)): _opener_references(path.read_text(encoding="utf-8"))
        for path in SRC.rglob("*.py")
        if path.name not in _OPENER_OWNERS
    }
    offenders = {name: lines for name, lines in offenders.items() if lines}
    assert offenders == {}, f"route these through net.open_url: {offenders}"

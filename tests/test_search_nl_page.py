"""The /search page over the existing /api/search-nl endpoint.

The page's job is not to run a search - `/events` already does that. It is to
show what the natural-language query BECAME: which terms were recognised as
structured filters, what was left as free text, and the equivalent CLI command.
`translate_query` is a keyword translator, so a page that hid its output would
make a crude parser look like comprehension.
"""

from __future__ import annotations

import html
import re

import pytest
from fastapi.testclient import TestClient

from autosiem.querygen import translate_query, to_cli_flags
from autosiem.web.api import SEARCH_EXAMPLES, UI_PAGES, app


@pytest.fixture
def client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "search.db"))
    monkeypatch.setenv("AUTOSIEM_AUTH_INSECURE", "1")
    return TestClient(app)


def _chips(body: str) -> dict[str, str]:
    return dict(re.findall(r"<span><strong>(.*?)</strong> (.*?)</span>", body))


def _cli_line(body: str) -> str:
    match = re.search(r'data-copy="([^"]+)"', body)
    return match.group(1) if match else ""


# -- registration and auth -------------------------------------------------

def test_the_page_is_registered_so_the_auth_middleware_covers_it():
    """A page missing from UI_PAGES is served to unauthenticated callers (SEC-005)."""
    assert "/search" in UI_PAGES


def test_the_page_requires_auth_when_rbac_is_configured(monkeypatch, tmp_path):
    users = tmp_path / "users.json"
    users.write_text('{"users": []}')
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "s.db"))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", str(users))
    monkeypatch.delenv("AUTOSIEM_AUTH_INSECURE", raising=False)
    assert TestClient(app).get("/search").status_code == 401


# -- the empty state -------------------------------------------------------

def test_an_empty_search_offers_examples_rather_than_a_blank_page(client):
    body = client.get("/search").text
    assert client.get("/search").status_code == 200
    for example in SEARCH_EXAMPLES:
        assert example in body
    assert "matched" not in body        # no result count before a search


def test_the_incident_queue_links_to_the_page(client):
    """A page nothing links to is not shipped; it is just reachable by URL."""
    assert 'href="/search"' in client.get("/").text


def test_the_examples_are_links_that_run_themselves(client):
    body = client.get("/search").text
    assert "/search?q=failed%20logins%20by%20user%20alice%20last%2024h" in body


# -- the translation panel -------------------------------------------------

def test_the_page_shows_which_terms_became_filters(client):
    body = client.get("/search?q=open critical incidents").text
    assert _chips(body) == {"query": "critical", "status": "open"}


def test_leftover_free_text_is_shown_not_hidden(client):
    """The parser leaves junk words in `query`; the page must not pretend otherwise."""
    body = client.get("/search?q=events from ip 198.51.100.25").text
    chips = _chips(body)
    assert chips["entity"] == "ip:198.51.100.25"
    assert chips["query"] == "from"      # the leftover, displayed honestly


def test_the_cli_line_is_the_same_search_as_a_command(client):
    query = "open critical incidents"
    body = client.get(f"/search?q={query}").text
    expected = "autosiem search-nl " + " ".join(to_cli_flags(translate_query(query)))
    assert _cli_line(body) == expected


def test_a_query_that_parses_to_nothing_says_so(client):
    body = client.get("/search?q=%20").text
    assert "nothing recognised" in body or "matched" in body


# -- targets ---------------------------------------------------------------

def test_the_target_defaults_to_incidents_and_accepts_events(client):
    assert "Searching <strong>incidents</strong>" in client.get("/search?q=alice").text
    assert "Searching <strong>events</strong>" in client.get("/search?q=alice&target=events").text


def test_an_unknown_target_falls_back_to_incidents(client):
    """Never pass an unvalidated target through to the store."""
    body = client.get("/search?q=alice&target=../../etc/passwd").text
    assert "Searching <strong>incidents</strong>" in body


def test_the_active_target_is_marked_in_the_toggle(client):
    body = client.get("/search?q=alice&target=events").text
    assert "chipbtn active' href='/search?q=alice&target=events'" in body


# -- results ---------------------------------------------------------------

def test_results_are_counted_with_the_right_plural(client):
    """The demo events all chain to user:alice, producing exactly one incident."""
    assert client.post("/api/ingest/demo").status_code == 200
    assert len(client.get("/api/incidents").json()) == 1

    one = client.get("/search?q=open incidents").text
    assert re.search(r"<strong>1</strong>\s*incident matched", one), "expected the singular"
    none = client.get("/search?q=zzzz-no-such-thing").text
    assert re.search(r"<strong>0</strong>\s*incidents matched", none), "expected the plural"


# -- escaping --------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "</textarea><svg onload=alert(1)>",
])
def test_the_query_is_escaped_everywhere_it_is_reflected(client, payload):
    """`q` is echoed into the input value, the chips and the CLI line.

    The property is that the payload never appears VERBATIM: with <, >, " and '
    escaped it cannot close the attribute or open a tag, even though harmless
    fragments like `onerror=alert(1)` survive inside the escaped text.
    """
    body = client.get("/search", params={"q": payload}).text
    assert payload not in body
    assert html.escape(payload, quote=True) in body

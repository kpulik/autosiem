"""The rendered pages: what the redesign promises an analyst, checked in the HTML.

The palette and typography have their own files (`test_ui_palette.py`,
`test_ui_auth.py`). These cover the page structure the redesign introduced and
one real bug it fixed: the queue's "Load demo telemetry" button posted to
`/ui/ingest/demo`, a route that never existed, so the main call to action on the
first page an evaluator sees returned 404.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from autosiem.web.api import _sev, _table, _timeline_rows, _ts, app


@pytest.fixture
def client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "ui.db"))
    monkeypatch.setenv("AUTOSIEM_AUTH_INSECURE", "1")
    return TestClient(app)


def _demo_form(page: str) -> tuple[str, str]:
    match = re.search(
        r'<form method="post" action="([^"]+)"><input type="hidden" name="csrf_token" value="([^"]+)"><button>Load demo telemetry</button>',
        page,
    )
    assert match, "the queue has no demo button"
    return match.group(1), match.group(2)


# -- the bug ------------------------------------------------------------------

def test_the_demo_button_posts_to_a_route_that_exists(client):
    action, token = _demo_form(client.get("/").text)
    response = client.post(action, data={"csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303, f"{action} answered {response.status_code}"
    assert len(client.get("/api/incidents").json()) == 1


def test_after_the_demo_the_queue_lists_the_incident_with_its_severity(client):
    action, token = _demo_form(client.get("/").text)
    client.post(action, data={"csrf_token": token})
    page = client.get("/").text
    incident = client.get("/api/incidents").json()[0]
    assert f'href="/incidents/{incident["incident_id"]}"' in page
    assert f'class="sev sev-{incident["severity"]}"' in page
    assert "<strong>1</strong> incident" in page


# -- shell --------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/search", "/events", "/findings", "/rules", "/sources", "/suppressions", "/audit"])
def test_every_page_has_the_nav_and_marks_itself_current(client, path):
    page = client.get(path).text
    nav = re.search(r'<nav aria-label="Sections">(.*?)</nav>', page, re.S)
    assert nav, "the page has no section nav"
    assert f'<a href="{path}" aria-current="page">' in nav.group(1)
    assert nav.group(1).count('aria-current="page"') == 1


def test_the_incident_page_shows_the_timeline_and_collapses_the_raw_bundle(client):
    client.post("/api/ingest/demo")
    incident = client.get("/api/incidents").json()[0]
    page = client.get(f"/incidents/{incident['incident_id']}").text
    timeline = client.get(f"/api/incidents/{incident['incident_id']}/timeline").json()
    assert page.count('<li class="tl-item') == len(timeline)
    assert '<details class="raw">' in page and "Raw incident bundle" in page
    assert 'aria-pressed="true"' in page        # the current status is marked


# -- helpers ------------------------------------------------------------------

def test_timestamps_label_utc_keep_other_offsets_and_never_guess_a_zone():
    assert ">2026-08-04 10:00:00 UTC<" in _ts("2026-08-04T10:00:00+00:00")
    assert ">2026-08-04 10:00:00 UTC<" in _ts("2026-08-04T10:00:00.123Z")
    assert ">2026-08-04 10:00:00 +02:00<" in _ts("2026-08-04T10:00:00+02:00")
    assert _ts("2026-08-04T10:00:00").endswith(">2026-08-04 10:00:00</time>")   # naive: no label
    assert _ts("not a time") == "not a time"


def test_the_timeline_prints_each_date_once_and_every_time():
    steps = [{"timestamp": f"2026-08-04T10:0{i}:00+00:00", "title": "t"} for i in range(3)]
    steps.append({"timestamp": "2026-08-05T00:01:00+00:00", "title": "t"})
    out = _timeline_rows(steps)
    assert out.count('<span class="tl-date">') == 2
    assert out.count(">2026-08-04<") == 1 and out.count(">2026-08-05<") == 1
    assert out.count(" UTC</time>") == 4


def test_an_unknown_severity_never_reaches_a_class_name():
    """Severity comes from stored data; it must not be interpolated into markup."""
    rendered = _sev('"><script>x</script>')
    assert 'class="sev sev-none"' in rendered
    assert "<script>" not in rendered


def test_the_table_shows_known_columns_and_keeps_every_field_in_raw():
    rows = [{"timestamp": "2026-08-04T10:00:00+00:00", "severity": "high", "action": "login_failure",
             "user": "alice", "data": {"secret_looking": "x<y"}}]
    out = _table(rows)
    for label in ("Time", "Severity", "Action", "User"):
        assert f"<th scope='col'>{label}</th>" in out
    assert "secret_looking" in out and "x&lt;y" in out       # folded, escaped, not dropped
    assert "<th scope='col'>Data</th>" not in out


def test_an_incident_row_in_a_table_links_to_its_page():
    out = _table([{"incident_id": "abc", "title": "Brute force", "severity": "critical"}])
    assert "href='/incidents/abc'" in out

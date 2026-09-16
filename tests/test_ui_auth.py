"""Tests for UI page authentication (SEC-005) and CSRF enforcement.

The rendered UI pages used to bypass auth entirely, which served /audit and
every incident detail page to any unauthenticated caller. They are guarded now,
and cookie auth plus mandatory CSRF make the browser UI usable without
reopening the hole.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from autosiem.web.api import UI_PAGES, _csrf_token, _is_readonly_ui_get, app  # noqa: E402

TOGGLE_PATH = "/ui/rules/AUTO-AUTH-001/toggle"


def _users_file(tmp_path, role: str = "admin", token: str = "tok") -> str:
    path = tmp_path / "users.json"
    path.write_text(json.dumps({"users": [{"name": "u", "role": role, "tenant": "acme", "token": token}]}))
    return str(path)


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "ui.db"))
    return tmp_path


# --- path classification ---------------------------------------------------


def test_ui_pages_are_matched_exactly_not_by_loose_prefix() -> None:
    assert _is_readonly_ui_get("/events", "GET") is True
    assert _is_readonly_ui_get("/incidents/abc-123", "GET") is True
    # A loose startswith("/events") would have matched these.
    assert _is_readonly_ui_get("/eventsomething", "GET") is False
    assert _is_readonly_ui_get("/auditlog", "GET") is False
    # Only GET renders a page.
    assert _is_readonly_ui_get("/events", "POST") is False


def test_every_known_ui_page_is_classified() -> None:
    assert "/audit" in UI_PAGES
    assert all(_is_readonly_ui_get(page, "GET") for page in UI_PAGES)


# --- UI pages are guarded --------------------------------------------------


@pytest.mark.parametrize("page", sorted(UI_PAGES))
def test_ui_pages_require_auth_in_rbac_mode(page, monkeypatch, db) -> None:
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)
    assert client.get(page).status_code == 401
    assert client.get(page, headers={"Authorization": "Bearer tok"}).status_code == 200


def test_audit_page_is_not_readable_unauthenticated(monkeypatch, db) -> None:
    """The tamper-evident log must not be world-readable."""
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)
    response = client.get("/audit")
    assert response.status_code == 401
    assert "Unauthorized" in response.text


def test_incident_detail_requires_auth(monkeypatch, db) -> None:
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    assert TestClient(app).get("/incidents/anything").status_code == 401


def test_ui_pages_require_auth_in_legacy_token_mode(monkeypatch, db) -> None:
    monkeypatch.delenv("AUTOSIEM_RBAC_FILE", raising=False)
    monkeypatch.setenv("AUTOSIEM_API_TOKEN", "shared")
    client = TestClient(app)
    assert client.get("/events").status_code == 401
    assert client.get("/events", headers={"Authorization": "Bearer shared"}).status_code == 200


def test_ui_pages_fail_closed_with_no_auth_configured(monkeypatch, db) -> None:
    monkeypatch.delenv("AUTOSIEM_RBAC_FILE", raising=False)
    monkeypatch.delenv("AUTOSIEM_API_TOKEN", raising=False)
    monkeypatch.delenv("AUTOSIEM_AUTH_INSECURE", raising=False)
    assert TestClient(app).get("/events").status_code == 401


def test_insecure_mode_reopens_the_ui_for_local_use(monkeypatch, db) -> None:
    monkeypatch.delenv("AUTOSIEM_RBAC_FILE", raising=False)
    monkeypatch.delenv("AUTOSIEM_API_TOKEN", raising=False)
    monkeypatch.setenv("AUTOSIEM_AUTH_INSECURE", "1")
    assert TestClient(app).get("/events").status_code == 200


def test_health_and_metrics_stay_open(monkeypatch, db) -> None:
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/metrics").status_code == 200


# --- cookie auth -----------------------------------------------------------


def test_token_cookie_authenticates_a_browser(monkeypatch, db) -> None:
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)
    client.cookies.set("autosiem_token", "tok")
    assert client.get("/events").status_code == 200


def test_a_wrong_token_cookie_is_rejected(monkeypatch, db) -> None:
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)
    client.cookies.set("autosiem_token", "nope")
    assert client.get("/events").status_code == 401


def test_header_wins_over_cookie(monkeypatch, db) -> None:
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)
    client.cookies.set("autosiem_token", "nope")
    assert client.get("/events", headers={"Authorization": "Bearer tok"}).status_code == 200


# --- CSRF ------------------------------------------------------------------


def test_csrf_is_enforced_by_default(monkeypatch, db) -> None:
    """Previously a no-op unless AUTOSIEM_CSRF_SECRET happened to be set."""
    monkeypatch.delenv("AUTOSIEM_CSRF_SECRET", raising=False)
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)

    response = client.post(
        TOGGLE_PATH, data={"enabled": "0"}, headers={"Authorization": "Bearer tok"}
    )
    assert response.status_code == 403
    assert "csrf" in response.json()["detail"]


def test_a_valid_csrf_token_is_accepted(monkeypatch, db) -> None:
    monkeypatch.delenv("AUTOSIEM_CSRF_SECRET", raising=False)
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)

    response = client.post(
        TOGGLE_PATH,
        data={"enabled": "0", "csrf_token": _csrf_token(TOGGLE_PATH)},
        headers={"Authorization": "Bearer tok"},
        follow_redirects=False,
    )
    assert response.status_code in (200, 303)


def test_csrf_tokens_are_bound_to_their_path(monkeypatch, db) -> None:
    """A token minted for one action must not work against another."""
    monkeypatch.delenv("AUTOSIEM_CSRF_SECRET", raising=False)
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", _users_file(db))
    client = TestClient(app)

    borrowed = _csrf_token("/ui/suppressions/add")
    response = client.post(
        TOGGLE_PATH,
        data={"enabled": "0", "csrf_token": borrowed},
        headers={"Authorization": "Bearer tok"},
    )
    assert response.status_code == 403


def test_configured_csrf_secret_is_read_at_call_time(monkeypatch) -> None:
    """Reading the env at import time meant setting it later had no effect."""
    monkeypatch.setenv("AUTOSIEM_CSRF_SECRET", "secret-one")
    first = _csrf_token(TOGGLE_PATH)
    monkeypatch.setenv("AUTOSIEM_CSRF_SECRET", "secret-two")
    assert _csrf_token(TOGGLE_PATH) != first


def test_csrf_token_is_not_empty_without_configuration(monkeypatch) -> None:
    monkeypatch.delenv("AUTOSIEM_CSRF_SECRET", raising=False)
    assert len(_csrf_token(TOGGLE_PATH)) == 32


def _seed_incident_with_source(tmp_path, source: str):
    """Persist a demo incident whose decision has the given confidence_source."""
    import json as _json
    from pathlib import Path as _Path

    from autosiem.llm import LLMBackend, LLMConfig, LLMService
    from autosiem.pipeline import AutoSIEMPipeline
    from autosiem.rules import load_rules
    from autosiem.storage import AutoSIEMStorage

    root = _Path(__file__).resolve().parents[1]
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()

    llm = None
    if source == "model":
        class _Stub(LLMBackend):
            def chat(self, system: str, user: str) -> str:
                return _json.dumps(
                    {
                        "decision_type": "containment_proposed",
                        "confidence": 0.91,
                        "rationale": "stub",
                        "recommended_owner": "tier-2-incident-responder",
                        "summary": "stub report",
                    }
                )

        llm = LLMService(config=LLMConfig())
        llm.backend = _Stub(llm.config)

    db = tmp_path / f"{source}.db"
    result = AutoSIEMPipeline(load_rules(root / "rules"), llm=llm).process_lines(lines)
    store = AutoSIEMStorage(db)
    store.save_pipeline_result(result)
    return db, result.incidents[0].incident_id


def test_incident_page_labels_a_deterministic_decision(tmp_path, monkeypatch):
    db, incident_id = _seed_incident_with_source(tmp_path, "deterministic")
    monkeypatch.setenv("AUTOSIEM_DB", str(db))
    monkeypatch.setenv("AUTOSIEM_AUTH_INSECURE", "1")
    page = TestClient(app).get(f"/incidents/{incident_id}").text
    assert "Deterministic" in page
    assert "No language model was involved" in page
    assert "LLM-assisted" not in page


def test_incident_page_labels_a_model_sourced_decision(tmp_path, monkeypatch):
    """The case that matters: a reviewer must be able to see a model decided."""
    db, incident_id = _seed_incident_with_source(tmp_path, "model")
    monkeypatch.setenv("AUTOSIEM_DB", str(db))
    monkeypatch.setenv("AUTOSIEM_AUTH_INSECURE", "1")
    page = TestClient(app).get(f"/incidents/{incident_id}").text
    assert "LLM-assisted" in page
    assert "reported by a language model" in page
    assert "cannot authorize autonomous response" in page


# -- typography -------------------------------------------------------------

def test_the_ui_never_ships_a_banned_display_font() -> None:
    """Inter, Roboto and Arial are barred as display faces by house style."""
    from autosiem.web.api import _page

    css = _page("t", "<p>body</p>")
    for banned in ("Inter", "Roboto", "Arial"):
        assert banned not in css, f"{banned} is back in the page shell"


def test_the_ui_requests_no_external_font() -> None:
    """A SOC console must render in an air-gapped network.

    A webfont link would also tell the font host every time an analyst opens
    the dashboard, which is a disclosure a security tool should not make.
    """
    from autosiem.web.api import _page

    css = _page("t", "<p>body</p>")
    for remote in ("fonts.googleapis.com", "fonts.gstatic.com", "@import", "@font-face"):
        assert remote not in css, f"the shell fetches {remote}"


def test_the_type_system_is_driven_by_custom_properties() -> None:
    from autosiem.web.api import _page

    css = _page("t", "<p>body</p>")
    assert "--font-display:" in css and "--font-body:" in css
    assert "font-family: var(--font-body)" in css

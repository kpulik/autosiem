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

"""SEC-007 and SEC-009: who can ingest, and who the audit log says acted.

The shared conftest turns on AUTOSIEM_AUTH_INSECURE for convenience, so every
test here removes it first: these are the real, fail-closed modes.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from autosiem.rbac import hash_token
from autosiem.web.api import app

EVENT = json.dumps({
    "timestamp": "2026-09-17T10:00:00Z", "category": "authentication", "action": "login_failed",
    "user": "alice", "src_ip": "198.51.100.25", "host": "vpn-1", "outcome": "failure",
})


@pytest.fixture
def secure(monkeypatch, tmp_path):
    monkeypatch.delenv("AUTOSIEM_AUTH_INSECURE", raising=False)
    for name in ("AUTOSIEM_API_TOKEN", "AUTOSIEM_INGEST_TOKEN", "AUTOSIEM_RBAC_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "auth.db"))
    return monkeypatch


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- SEC-007: the ingest token is a write-only credential -------------------

def test_a_collector_can_ingest_with_only_the_ingest_token(secure) -> None:
    # Before this, a collector had to hold the admin-equivalent API token as
    # well, which invited operators to reuse one value for both.
    secure.setenv("AUTOSIEM_API_TOKEN", "admin-tok")
    secure.setenv("AUTOSIEM_INGEST_TOKEN", "ingest-tok")
    client = TestClient(app)
    assert client.post("/api/ingest", content=EVENT, headers=_bearer("ingest-tok")).status_code == 200
    assert client.post("/api/ingest", content=EVENT, headers={"x-api-key": "ingest-tok"}).status_code == 200


def test_the_ingest_token_opens_nothing_but_ingest(secure) -> None:
    secure.setenv("AUTOSIEM_API_TOKEN", "admin-tok")
    secure.setenv("AUTOSIEM_INGEST_TOKEN", "ingest-tok")
    client = TestClient(app)
    collector = _bearer("ingest-tok")
    assert client.get("/api/incidents", headers=collector).status_code == 401
    assert client.get("/api/audit", headers=collector).status_code == 401
    assert client.post("/api/rules/AUTO-AUTH-001", json={"enabled": False}, headers=collector).status_code == 401
    # Only POST: the same path under another method is not the ingest surface.
    assert client.get("/api/ingest", headers=collector).status_code == 401


def test_an_ingest_only_deployment_accepts_ingest_and_nothing_else(secure) -> None:
    # No API token and no RBAC: previously every request, ingest included,
    # was refused, so the ingest token could never be used on its own.
    secure.setenv("AUTOSIEM_INGEST_TOKEN", "ingest-tok")
    client = TestClient(app)
    assert client.post("/api/ingest", content=EVENT, headers=_bearer("ingest-tok")).status_code == 200
    assert client.post("/api/ingest", content=EVENT).status_code == 401
    assert client.get("/api/incidents", headers=_bearer("ingest-tok")).status_code == 401


def test_when_an_ingest_token_is_set_the_api_token_alone_cannot_ingest(secure) -> None:
    secure.setenv("AUTOSIEM_API_TOKEN", "admin-tok")
    secure.setenv("AUTOSIEM_INGEST_TOKEN", "ingest-tok")
    client = TestClient(app)
    assert client.post("/api/ingest", content=EVENT, headers=_bearer("admin-tok")).status_code == 401
    # Both, in separate headers, still works for callers that send both.
    both = {"Authorization": "Bearer admin-tok", "x-api-key": "ingest-tok"}
    assert client.post("/api/ingest", content=EVENT, headers=both).status_code == 200


def test_a_wrong_ingest_token_is_refused(secure) -> None:
    secure.setenv("AUTOSIEM_INGEST_TOKEN", "ingest-tok")
    client = TestClient(app)
    assert client.post("/api/ingest", content=EVENT, headers=_bearer("ingest-to")).status_code == 401
    assert client.post("/api/ingest", content=EVENT, headers={"x-api-key": "INGEST-TOK"}).status_code == 401


def test_the_ingest_token_does_not_bypass_rbac(secure, tmp_path) -> None:
    # In RBAC mode ingest still needs a user holding ingest:events; the ingest
    # token is an additional check there, never a way around the user store.
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "collector", "role": "ingest", "token_hash": hash_token("collector-tok")},
    ]}))
    secure.setenv("AUTOSIEM_RBAC_FILE", str(users))
    secure.setenv("AUTOSIEM_INGEST_TOKEN", "ingest-tok")
    client = TestClient(app)
    assert client.post("/api/ingest", content=EVENT, headers=_bearer("ingest-tok")).status_code == 401
    both = {"Authorization": "Bearer collector-tok", "x-api-key": "ingest-tok"}
    assert client.post("/api/ingest", content=EVENT, headers=both).status_code == 200


def test_ingest_token_comparison_is_constant_time(secure) -> None:
    # The old check used ``==``; the SEC-006 sweep had missed it.
    import autosiem.web.api as api

    secure.setenv("AUTOSIEM_INGEST_TOKEN", "ingest-tok")
    calls: list[tuple[bytes, bytes]] = []
    real = api.secrets.compare_digest

    def spy(a, b):  # type: ignore[no-untyped-def]
        calls.append((a, b))
        return real(a, b)

    secure.setattr(api.secrets, "compare_digest", spy)
    TestClient(app).post("/api/ingest", content=EVENT, headers=_bearer("ingest-tok"))
    assert calls, "the ingest token must be compared with secrets.compare_digest"


@pytest.mark.parametrize("header", ["Authorization", "x-api-key"])
def test_a_non_ascii_token_is_a_401_not_a_500(secure, header) -> None:
    # Starlette decodes headers as latin-1, so one high byte arrives as a
    # non-ASCII str, and compare_digest raises TypeError on those. The
    # shared-token check therefore answered 500 instead of 401.
    secure.setenv("AUTOSIEM_API_TOKEN", "admin-tok")
    secure.setenv("AUTOSIEM_INGEST_TOKEN", "ingest-tok")
    client = TestClient(app, raise_server_exceptions=False)
    value = b"Bearer tok\xe9" if header == "Authorization" else b"tok\xe9"
    raw: dict[bytes, bytes] = {header.encode("ascii"): value}
    assert client.get("/api/incidents", headers=raw).status_code == 401
    assert client.post("/api/ingest", content=EVENT, headers=raw).status_code == 401


# --- SEC-009: the audit actor comes only from authentication ----------------

def _last_rule_actor(client: TestClient, headers: dict[str, str]) -> str:
    rows = client.get("/api/audit", headers=headers).json()
    return [row for row in rows if row["action"] == "rule_state_changed"][0]["actor"]


def test_shared_token_mode_ignores_a_caller_supplied_actor(secure) -> None:
    # The forgery: ``?actor=admin`` used to be written to the audit log as-is.
    secure.setenv("AUTOSIEM_API_TOKEN", "admin-tok")
    client = TestClient(app)
    admin = _bearer("admin-tok")
    client.post("/api/rules/AUTO-AUTH-001?actor=someone-else", json={"enabled": False}, headers=admin)
    assert _last_rule_actor(client, admin) == "api-token"


def test_rbac_mode_records_the_user_whatever_the_query_says(secure, tmp_path) -> None:
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "dana", "role": "analyst", "token_hash": hash_token("dana-tok")},
    ]}))
    secure.setenv("AUTOSIEM_RBAC_FILE", str(users))
    client = TestClient(app)
    dana = _bearer("dana-tok")
    client.post("/api/rules/AUTO-AUTH-001?actor=root", json={"enabled": False}, headers=dana)
    assert _last_rule_actor(client, dana) == "dana"


def test_insecure_mode_records_unauthenticated(secure) -> None:
    # The open local mode knows nothing about the caller, so it says so rather
    # than inventing "analyst".
    secure.setenv("AUTOSIEM_AUTH_INSECURE", "1")
    client = TestClient(app)
    client.post("/api/rules/AUTO-AUTH-001?actor=root", json={"enabled": False})
    assert _last_rule_actor(client, {}) == "unauthenticated"

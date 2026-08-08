from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from autosiem.web.api import app


@pytest.fixture
def client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "api.db"))
    return TestClient(app)


def _credential_dump_event() -> dict:
    return {
        "timestamp": "2026-08-04T10:07:00Z",
        "category": "process",
        "action": "process_start",
        "user": "alice",
        "host": "workstation-7",
        "process_name": "mimikatz.exe",
        "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        "outcome": "success",
    }


def test_api_rules_lists_all_rules(client: TestClient) -> None:
    response = client.get("/api/rules")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["rules"]) == 16
    rule_ids = {rule["rule_id"] for rule in payload["rules"]}
    assert {"AUTO-AUTH-001", "AUTO-CRED-002", "AUTO-IMPACT-001"} <= rule_ids
    assert all(rule["enabled"] for rule in payload["rules"])
    assert isinstance(payload["overrides"], list)


def test_api_rules_toggle_persists(client: TestClient) -> None:
    response = client.post("/api/rules/AUTO-AUTH-001", json={"enabled": False})
    assert response.status_code == 200
    assert response.json() == {"rule_id": "AUTO-AUTH-001", "enabled": False, "tenant_id": "default"}

    single = client.get("/api/rules", params={"rule_id": "AUTO-AUTH-001"})
    assert single.status_code == 200
    payload = single.json()
    assert len(payload["rules"]) == 1
    assert payload["rules"][0]["enabled"] is False
    assert payload["overrides"][0]["rule_id"] == "AUTO-AUTH-001"


def test_api_rules_unknown_id_returns_404(client: TestClient) -> None:
    response = client.get("/api/rules", params={"rule_id": "AUTO-NOPE-000"})
    assert response.status_code == 404


def test_api_rules_test_fires_rule(client: TestClient) -> None:
    response = client.post("/api/rules/test", json={"event": _credential_dump_event()})
    assert response.status_code == 200
    payload = response.json()
    rule_ids = {finding["rule_id"] for finding in payload["findings"]}
    assert "AUTO-CRED-002" in rule_ids
    assert payload["events"] == 1


def test_api_rules_test_requires_event(client: TestClient) -> None:
    response = client.post("/api/rules/test", json={})
    assert response.status_code == 400


def test_api_metrics_exports_prometheus_text(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "autosiem_events" in response.text
    assert "autosiem_incidents" in response.text


def test_api_search_nl(client: TestClient) -> None:
    response = client.get("/api/search-nl", params={"q": "failed logins by user alice last 24h"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["translation"]["entity"] == "user:alice"
    assert payload["target"] == "incidents"


def test_rules_page_renders(client: TestClient) -> None:
    response = client.get("/rules")
    assert response.status_code == 200
    assert "Detection Rules" in response.text
    assert "AUTO-AUTH-001" in response.text


def test_api_auth_guard_blocks_when_token_configured(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "api-auth.db"))
    monkeypatch.setenv("AUTOSIEM_API_TOKEN", "sekret")
    client = TestClient(app)

    assert client.get("/api/rules").status_code == 401
    assert client.get("/api/rules", headers={"Authorization": "Bearer sekret"}).status_code == 200
    assert client.get("/api/rules", headers={"X-API-Key": "sekret"}).status_code == 200
    # Read-only UI and health stay open even when the token is configured.
    assert client.get("/health").status_code == 200


def _write_users_file(tmp_path, users: list[dict]) -> str:
    path = tmp_path / "users.json"
    path.write_text(json.dumps({"users": users}))
    return str(path)


def test_rbac_mode_requires_valid_user(monkeypatch, tmp_path) -> None:
    users = _write_users_file(
        tmp_path,
        [{"name": "soc", "role": "analyst", "tenant": "acme", "token": "analyst-tok"}],
    )
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "rbac.db"))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", users)
    client = TestClient(app)

    assert client.get("/api/rules").status_code == 401
    assert client.get("/api/rules", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = client.get("/api/rules", headers={"Authorization": "Bearer analyst-tok"})
    assert ok.status_code == 200
    assert len(ok.json()["rules"]) == 16
    # X-API-Key is honored too.
    assert client.get("/api/rules", headers={"X-API-Key": "analyst-tok"}).status_code == 200
    # Health stays open; the rendered UI pages do NOT (SEC-005).
    assert client.get("/health").status_code == 200
    assert client.get("/rules").status_code == 401
    assert client.get("/rules", headers={"Authorization": "Bearer analyst-tok"}).status_code == 200
    # A browser can authenticate with the token cookie instead of a header.
    client.cookies.set("autosiem_token", "analyst-tok")
    assert client.get("/rules").status_code == 200
    client.cookies.clear()


def test_rbac_mode_enforces_role_permissions(monkeypatch, tmp_path) -> None:
    users = _write_users_file(
        tmp_path,
        [
            {"name": "viewer", "role": "viewer", "tenant": "acme", "token": "viewer-tok"},
            {"name": "analyst", "role": "analyst", "tenant": "acme", "token": "analyst-tok"},
            {"name": "collector", "role": "ingest", "tenant": "acme", "token": "ingest-tok"},
            {"name": "root", "role": "admin", "tenant": "acme", "token": "admin-tok"},
        ],
    )
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "rbac.db"))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", users)
    client = TestClient(app)
    viewer = {"Authorization": "Bearer viewer-tok"}
    analyst = {"Authorization": "Bearer analyst-tok"}
    ingest = {"Authorization": "Bearer ingest-tok"}
    admin = {"Authorization": "Bearer admin-tok"}

    # All authenticated users may read rules; the ingest machine account may not.
    assert client.get("/api/rules", headers=viewer).status_code == 200
    assert client.get("/api/rules", headers=analyst).status_code == 200
    assert client.get("/api/rules", headers=ingest).status_code == 403
    assert client.get("/api/rules", headers=admin).status_code == 200

    # Toggling a rule needs rules:manage (analyst/admin yes, viewer no).
    assert client.post("/api/rules/AUTO-AUTH-001", json={"enabled": False}, headers=viewer).status_code == 403
    assert client.post("/api/rules/AUTO-AUTH-001", json={"enabled": False}, headers=analyst).status_code == 200
    assert client.post("/api/rules/AUTO-AUTH-001", json={"enabled": True}, headers=admin).status_code == 200

    # Approvals need approve:proposals; rejections are the same permission.
    assert client.post("/api/proposals/nope/approve", headers=viewer).status_code == 403
    assert client.post("/api/proposals/nope/reject", headers=ingest).status_code == 403

    # Ingest is ingest-only: only the machine account may ingest demo data.
    assert client.post("/api/ingest/demo", headers=viewer).status_code == 403
    assert client.post("/api/ingest/demo", headers=analyst).status_code == 403
    assert client.post("/api/ingest/demo", headers=ingest).status_code == 200
    assert client.post("/api/ingest/demo", headers=admin).status_code == 200

    # Rule testing needs rules:test (analyst yes, viewer no).
    assert client.post("/api/rules/test", json={"event": _credential_dump_event()}, headers=viewer).status_code == 403
    assert client.post("/api/rules/test", json={"event": _credential_dump_event()}, headers=analyst).status_code == 200

    # Audit is read-only (viewer may read it).
    assert client.get("/api/audit", headers=viewer).status_code == 200


def test_rbac_tenant_scoping_isolates_data(monkeypatch, tmp_path) -> None:
    """Each tenant's ingest is invisible to the other tenant's analysts."""
    users = _write_users_file(
        tmp_path,
        [
            {"name": "acme-bot", "role": "ingest", "tenant": "acme", "token": "acme-ingest"},
            {"name": "acme-soc", "role": "analyst", "tenant": "acme", "token": "acme-soc"},
            {"name": "globex-soc", "role": "analyst", "tenant": "globex", "token": "globex-soc"},
        ],
    )
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "tenants.db"))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", users)
    client = TestClient(app)
    acme_bot = {"Authorization": "Bearer acme-ingest"}
    acme = {"Authorization": "Bearer acme-soc"}
    globex = {"Authorization": "Bearer globex-soc"}

    ingested = client.post("/api/ingest/demo", headers=acme_bot)
    assert ingested.status_code == 200
    assert ingested.json()["incidents"] >= 1

    # The acme analyst sees the acme data...
    acme_incidents = client.get("/api/incidents", headers=acme).json()
    assert acme_incidents
    assert all(row["tenant_id"] == "acme" for row in acme_incidents)
    assert client.get("/api/events", headers=acme).json()

    # ...and the globex analyst sees none of it.
    assert client.get("/api/incidents", headers=globex).json() == []
    assert client.get("/api/events", headers=globex).json() == []
    assert client.get("/api/findings", headers=globex).json() == []
    assert client.get("/api/sources", headers=globex).json() == []

    # Cross-tenant incident fetch is a 404, not a 403 (no existence probing).
    incident_id = acme_incidents[0]["incident_id"]
    assert client.get(f"/api/incidents/{incident_id}", headers=acme).status_code == 200
    assert client.get(f"/api/incidents/{incident_id}", headers=globex).status_code == 404
    assert client.get(f"/api/incidents/{incident_id}/timeline", headers=globex).status_code == 404
    assert client.post(
        f"/api/incidents/{incident_id}/update", json={"status": "closed"}, headers=globex
    ).status_code == 404
    assert client.post(
        f"/api/incidents/{incident_id}/comments", json={"body": "probe"}, headers=globex
    ).status_code == 404

    # /metrics is exempt from auth (Prometheus), so no tenant filter.
    # The data-scoped /api/* endpoints above already prove isolation.


def test_rbac_user_management_endpoints(monkeypatch, tmp_path) -> None:
    users = _write_users_file(
        tmp_path,
        [
            {"name": "root", "role": "admin", "tenant": "acme", "token": "admin-tok"},
            {"name": "analyst", "role": "analyst", "tenant": "acme", "token": "analyst-tok"},
        ],
    )
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "users.db"))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", users)
    client = TestClient(app)
    admin = {"Authorization": "Bearer admin-tok"}
    analyst = {"Authorization": "Bearer analyst-tok"}

    # users:manage is admin-only.
    assert client.get("/api/users", headers=analyst).status_code == 403
    listed = client.get("/api/users", headers=admin)
    assert listed.status_code == 200
    assert {u["name"] for u in listed.json()["users"]} == {"root", "analyst"}

    # Add a user, then authenticate as them.
    created = client.post(
        "/api/users",
        json={"name": "newbie", "role": "viewer", "tenant": "globex", "token": "newbie-tok"},
        headers=admin,
    )
    assert created.status_code == 200
    assert created.json()["tenant"] == "globex"
    assert client.get("/api/rules", headers={"Authorization": "Bearer newbie-tok"}).status_code == 200

    # Duplicates are rejected.
    assert client.post("/api/users", json={"name": "newbie"}, headers=admin).status_code == 400

    # Rotate: the old token dies, the returned one works.
    rotated = client.post("/api/users/newbie/rotate-token", headers=admin)
    assert rotated.status_code == 200
    new_token = rotated.json()["token"]
    assert client.get("/api/rules", headers={"Authorization": "Bearer newbie-tok"}).status_code == 401
    assert client.get("/api/rules", headers={"Authorization": f"Bearer {new_token}"}).status_code == 200

    # Revoke: the account stays but can no longer authenticate.
    assert client.post("/api/users/newbie/revoke-token", headers=admin).status_code == 200
    assert client.get("/api/rules", headers={"Authorization": f"Bearer {new_token}"}).status_code == 401
    assert "newbie" in {u["name"] for u in client.get("/api/users", headers=admin).json()["users"]}

    # Remove: gone for good.
    assert client.delete("/api/users/newbie", headers=admin).status_code == 200
    assert "newbie" not in {u["name"] for u in client.get("/api/users", headers=admin).json()["users"]}
    assert client.delete("/api/users/newbie", headers=admin).status_code == 404
    assert client.post("/api/users/ghost/rotate-token", headers=admin).status_code == 404
    assert client.post("/api/users/ghost/revoke-token", headers=admin).status_code == 404


def test_rbac_user_changes_are_audited(monkeypatch, tmp_path) -> None:
    users = _write_users_file(
        tmp_path, [{"name": "root", "role": "admin", "tenant": "acme", "token": "admin-tok"}]
    )
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "users-audit.db"))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", users)
    client = TestClient(app)
    admin = {"Authorization": "Bearer admin-tok"}

    client.post("/api/users", json={"name": "temp", "role": "viewer", "token": "t"}, headers=admin)
    client.post("/api/users/temp/rotate-token", headers=admin)
    client.post("/api/users/temp/revoke-token", headers=admin)
    client.delete("/api/users/temp", headers=admin)

    audit = client.get("/api/audit", headers=admin).json()
    actions = [row["action"] for row in audit]
    for expected in ("rbac_user_added", "rbac_token_rotated", "rbac_token_revoked", "rbac_user_removed"):
        assert expected in actions
    user_rows = [row for row in audit if row["action"].startswith("rbac_")]
    assert all(row["actor"] == "root" for row in user_rows)
    assert all(row["target"] == "temp" for row in user_rows)


def test_user_management_requires_rbac_file(monkeypatch, tmp_path) -> None:
    """Without a users file there is nowhere to persist, so the surface 503s."""
    monkeypatch.delenv("AUTOSIEM_RBAC_FILE", raising=False)
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "nofile.db"))
    monkeypatch.setenv("AUTOSIEM_API_TOKEN", "sekret")
    client = TestClient(app)
    assert client.get("/api/users", headers={"Authorization": "Bearer sekret"}).status_code == 503


def test_legacy_mode_is_not_tenant_scoped(monkeypatch, tmp_path) -> None:
    """Single-token mode keeps its original behaviour: it sees every row."""
    monkeypatch.delenv("AUTOSIEM_RBAC_FILE", raising=False)
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "legacy.db"))
    monkeypatch.setenv("AUTOSIEM_API_TOKEN", "sekret")
    client = TestClient(app)
    auth = {"Authorization": "Bearer sekret"}

    assert client.post("/api/ingest/demo", headers=auth).status_code == 200
    incidents = client.get("/api/incidents", headers=auth).json()
    assert incidents
    # Rows land in the default tenant and stay readable without any scoping.
    assert all(row["tenant_id"] == "default" for row in incidents)


def test_rbac_mode_actor_threads_into_audit(monkeypatch, tmp_path) -> None:
    users = _write_users_file(
        tmp_path,
        [
            {"name": "root", "role": "admin", "tenant": "acme", "token": "admin-tok"},
            {"name": "analyst", "role": "analyst", "tenant": "acme", "token": "analyst-tok"},
        ],
    )
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "rbac.db"))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", users)
    client = TestClient(app)
    analyst = {"Authorization": "Bearer analyst-tok"}

    client.post("/api/rules/AUTO-AUTH-001", json={"enabled": False}, headers=analyst)
    audit = client.get("/api/audit", headers=analyst).json()
    rule_events = [row for row in audit if row.get("action") == "rule_state_changed"]
    assert rule_events and rule_events[-1]["actor"] == "analyst"


def test_rbac_control_plane_tenant_isolation(monkeypatch, tmp_path) -> None:
    """A rule toggle in one tenant does not affect another tenant."""
    users = _write_users_file(
        tmp_path,
        [
            {"name": "acme-analyst", "role": "analyst", "tenant": "acme", "token": "acme-tok"},
            {"name": "globex-analyst", "role": "analyst", "tenant": "globex", "token": "globex-tok"},
            {"name": "acme-ingest", "role": "ingest", "tenant": "acme", "token": "acme-ingest-tok"},
        ],
    )
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "control.db"))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", users)
    client = TestClient(app)
    acme = {"Authorization": "Bearer acme-tok"}
    globex = {"Authorization": "Bearer globex-tok"}
    acme_bot = {"Authorization": "Bearer acme-ingest-tok"}

    # Ingest demo data under acme so suppressions have something to work with.
    assert client.post("/api/ingest/demo", headers=acme_bot).status_code == 200

    # --- Rule toggle isolation ---
    # Acme disables AUTO-AUTH-001.
    resp = client.post("/api/rules/AUTO-AUTH-001", json={"enabled": False}, headers=acme)
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == "acme"

    # Globex still sees it enabled.
    globex_rules = client.get("/api/rules", headers=globex).json()
    auth_rule = [r for r in globex_rules["rules"] if r["rule_id"] == "AUTO-AUTH-001"][0]
    assert auth_rule["enabled"] is True

    # Acme sees it disabled.
    acme_rules = client.get("/api/rules", headers=acme).json()
    auth_rule_acme = [r for r in acme_rules["rules"] if r["rule_id"] == "AUTO-AUTH-001"][0]
    assert auth_rule_acme["enabled"] is False

    # Overrides list is per-tenant.
    globex_overrides = client.get("/api/rules", headers=globex).json()["overrides"]
    acme_overrides = client.get("/api/rules", headers=acme).json()["overrides"]
    acme_tenant_overrides = [o for o in acme_overrides if o["tenant_id"] == "acme"]
    globex_tenant_overrides = [o for o in globex_overrides if o["tenant_id"] == "globex"]
    assert len(acme_tenant_overrides) == 1
    assert len(globex_tenant_overrides) == 0  # globex never toggled

    # --- Suppression isolation ---
    resp = client.post(
        "/api/suppressions",
        json={"rule_id": "*", "name": "acme-noise", "action": "suppress", "reason": "test", "created_by": "analyst"},
        headers=acme,
    )
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == "acme"

    # Acme sees the suppression.
    acme_sups = client.get("/api/suppressions", headers=acme).json()
    assert len(acme_sups) == 1

    # Globex sees nothing.
    globex_sups = client.get("/api/suppressions", headers=globex).json()
    assert globex_sups == []

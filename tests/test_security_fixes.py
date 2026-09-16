import json
from starlette.testclient import TestClient
from autosiem.rbac import hash_token
from autosiem.web.api import app
from autosiem.listeners import SyslogServer

def test_sec_001_fail_closed_without_insecure_flag(monkeypatch):
    """SEC-001: Without token, RBAC, or AUTOSIEM_AUTH_INSECURE=1, API requests fail 401."""
    monkeypatch.delenv("AUTOSIEM_API_TOKEN", raising=False)
    monkeypatch.delenv("AUTOSIEM_RBAC_FILE", raising=False)
    monkeypatch.delenv("AUTOSIEM_AUTH_INSECURE", raising=False)
    client = TestClient(app)

    res = client.get("/api/incidents")
    assert res.status_code == 401
    assert "unauthorized" in res.json()["detail"]


def test_sec_002_ui_post_routes_require_permission_in_rbac_mode(monkeypatch, tmp_path):
    """SEC-002: UI POST mutating routes enforce RBAC permissions when RBAC enabled."""
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps({
        "users": [{"name": "viewer_user", "role": "viewer", "token_hash": hash_token("viewer-tok")}]
    }))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", str(users_file))
    client = TestClient(app)

    # Unauthenticated UI POST fails 401
    res = client.post("/ui/rules/AUTO-AUTH-001/toggle", data={"enabled": "0"})
    assert res.status_code == 401

    # Viewer (lacks PERM_RULES_MANAGE) gets 403 Forbidden
    res = client.post(
        "/ui/rules/AUTO-AUTH-001/toggle",
        data={"enabled": "0"},
        headers={"Authorization": "Bearer viewer-tok"}
    )
    assert res.status_code == 403


def test_sec_003_ingest_payload_size_limit(monkeypatch):
    """SEC-003: Payload exceeding MAX_INGEST_BYTES returns 413 Payload Too Large."""
    monkeypatch.setenv("AUTOSIEM_AUTH_INSECURE", "1")
    monkeypatch.setenv("AUTOSIEM_MAX_INGEST_BYTES", "100")
    client = TestClient(app)

    huge_payload = json.dumps([{"event": "x" * 200}])
    res = client.post("/api/ingest", content=huge_payload)
    assert res.status_code == 413
    assert "payload too large" in res.json()["detail"]


def test_sec_004_syslog_listener_ip_allowlist():
    """SEC-004: SyslogServer drops events from IPs not in allowed_hosts."""
    received = []
    listener = SyslogServer(
        handler=lambda raw: received.append(raw),
        host="127.0.0.1",
        allowed_hosts=["10.0.0.1"]  # 127.0.0.1 is not 10.0.0.1
    )
    listener.start()
    try:
        # Simulate sending datagram
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"<13>1 2026-08-06T00:00:00Z myhost test - - - hello", ("127.0.0.1", listener.port))
        import time
        time.sleep(0.1)
        # 127.0.0.1 is not 10.0.0.1, so event should be dropped
        assert len(received) == 0
    finally:
        listener.stop()

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from autosiem.web.api import app

AUTHORS: dict[str, object] = {}


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "api.db"))
    # Ensure a clean module-level DB path per test run.
    return TestClient(app)


def _event(line: int) -> dict[str, object]:
    return {
        "timestamp": f"2026-08-05T10:0{line}:00Z",
        "category": "authentication",
        "action": "login_failed",
        "user": "alice",
        "src_ip": "198.51.100.25",
        "host": "vpn-1",
        "outcome": "failure",
    }


def test_ingest_jsonl(client: TestClient) -> None:
    lines = "\n".join(json.dumps(_event(i)) for i in range(3))
    response = client.post("/api/ingest", content=lines, headers={"Content-Type": "application/x-ndjson"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] == 3
    assert payload["events"] == 3
    assert payload["findings"] >= 0
    assert payload["incidents"] >= 0


def test_ingest_json_array(client: TestClient) -> None:
    events = [_event(1), _event(2)]
    response = client.post("/api/ingest", json=events)
    assert response.status_code == 200
    assert response.json()["accepted"] == 2


def test_ingest_single_event(client: TestClient) -> None:
    response = client.post("/api/ingest", json=_event(1))
    assert response.status_code == 200
    assert response.json()["accepted"] == 1


def test_ingest_invalid_payload_returns_400(client: TestClient) -> None:
    response = client.post("/api/ingest", content="not json at all", headers={"Content-Type": "text/plain"})
    assert response.status_code == 400
    assert "invalid event payload" in response.json()["detail"]


def test_ingest_requires_token_when_configured(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AUTOSIEM_INGEST_TOKEN", "s3cret")
    no_auth = client.post("/api/ingest", content=json.dumps(_event(1)))
    assert no_auth.status_code == 401

    with_auth = client.post(
        "/api/ingest", content=json.dumps(_event(1)), headers={"Authorization": "Bearer s3cret"}
    )
    assert with_auth.status_code == 200

    xkey = client.post("/api/ingest", content=json.dumps(_event(1)), headers={"X-API-Key": "s3cret"})
    assert xkey.status_code == 200


def test_ingest_persists_events(client: TestClient) -> None:
    client.post("/api/ingest", json=[_event(1), _event(2)])
    events = client.get("/api/events").json()
    assert len(events) >= 2
    assert any(event["data"]["action"] == "login_failed" for event in events)


def test_api_sources_reports_per_source_health(client: TestClient) -> None:
    client.post("/api/ingest", json=[_event(1), _event(2)])
    response = client.get("/api/sources")
    assert response.status_code == 200
    rows = response.json()
    assert rows
    assert all(row["events"] >= 1 and row["source"] for row in rows)


def test_sources_page_renders(client: TestClient) -> None:
    client.post("/api/ingest", json=[_event(1)])
    response = client.get("/sources")
    assert response.status_code == 200
    assert "Sources" in response.text
    assert "events" in response.text

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, cast

import pytest

from autosiem.backends import (
    BackendError,
    ClickHouseBackend,
    EventBackend,
    OpenSearchBackend,
    SqliteBackend,
    make_backend,
)
from autosiem.normalization import normalize, parse_raw_line
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = REPO_ROOT / "rules"
EVENTS_FILE = REPO_ROOT / "examples" / "events.jsonl"

SAMPLE_EVENT = normalize(parse_raw_line('{"timestamp":"2026-08-04T10:00:00Z","category":"authentication","action":"login_success","user":"alice","src_ip":"203.0.113.10","host":"vpn-1","outcome":"success"}'))


class FakeResponse:
    def __init__(self, payload: bytes = b"") -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


def _capturing_urlopen(captured: list[urllib.request.Request], payload: bytes = b"") -> Any:
    def fake_urlopen(request: urllib.request.Request, *args: Any, **kwargs: Any) -> FakeResponse:
        captured.append(request)
        return FakeResponse(payload)

    return fake_urlopen


def test_clickhouse_store_events_sends_json_each_row(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr("urllib.request.urlopen", _capturing_urlopen(captured))

    ClickHouseBackend().store_events([SAMPLE_EVENT])

    request = captured[0]
    assert request.get_method() == "POST"
    assert request.data is not None
    assert json.loads(cast(bytes, request.data).decode("utf-8")) == SAMPLE_EVENT.to_dict()
    query = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["query"][0]
    assert query == "INSERT INTO events FORMAT JSONEachRow"


def test_clickhouse_list_events_parses_ndjson(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []
    payload = (json.dumps(SAMPLE_EVENT.to_dict()) + "\n").encode("utf-8")
    monkeypatch.setattr("urllib.request.urlopen", _capturing_urlopen(captured, payload))

    events = ClickHouseBackend().list_events(limit=5)

    assert events == [SAMPLE_EVENT.to_dict()]
    query = urllib.parse.parse_qs(urllib.parse.urlparse(captured[0].full_url).query)["query"][0]
    assert query == "SELECT * FROM events LIMIT 5 FORMAT JSONEachRow"


def test_opensearch_store_events_hits_bulk(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr("urllib.request.urlopen", _capturing_urlopen(captured))

    OpenSearchBackend().store_events([SAMPLE_EVENT])

    request = captured[0]
    assert request.get_method() == "POST"
    assert request.full_url.endswith("/events/_bulk")
    assert request.data is not None
    action_line, doc_line = cast(bytes, request.data).decode("utf-8").splitlines()
    assert json.loads(action_line) == {"index": {"_index": "events"}}
    assert json.loads(doc_line) == SAMPLE_EVENT.to_dict()


def test_opensearch_list_events_maps_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []
    search_hits = {"hits": {"hits": [{"_source": SAMPLE_EVENT.to_dict()}]}}
    payload = json.dumps(search_hits).encode("utf-8")
    monkeypatch.setattr("urllib.request.urlopen", _capturing_urlopen(captured, payload))

    events = OpenSearchBackend().list_events(limit=10)

    assert events == [SAMPLE_EVENT.to_dict()]
    assert "size=10" in captured[0].full_url


def test_http_backend_raises_backend_error_on_urlopen_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_urlopen(request: urllib.request.Request, *args: Any, **kwargs: Any) -> FakeResponse:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", failing_urlopen)

    with pytest.raises(BackendError):
        ClickHouseBackend().store_events([SAMPLE_EVENT])
    with pytest.raises(BackendError):
        OpenSearchBackend().store_events([SAMPLE_EVENT])


def test_sqlite_backend_end_to_end(tmp_path: Path) -> None:
    rules = load_rules(RULES_PATH)
    lines = EVENTS_FILE.read_text(encoding="utf-8").splitlines()[:2]
    result = AutoSIEMPipeline(rules).process_lines(lines)

    backend = SqliteBackend(db_path=tmp_path / "test.db", rules=rules)
    backend.store_events(result.events)
    listed = backend.list_events()

    assert len(listed) == len(result.events)
    assert {row["event_id"] for row in listed} == {event.event_id for event in result.events}


def test_make_backend_factory() -> None:
    assert isinstance(make_backend("sqlite"), SqliteBackend)
    assert isinstance(make_backend("ClickHouse"), ClickHouseBackend)
    assert isinstance(make_backend("opensearch", index="logs"), OpenSearchBackend)
    assert isinstance(make_backend(), EventBackend)
    with pytest.raises(ValueError):
        make_backend("nope")
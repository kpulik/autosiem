from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
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

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def _capturing_urlopen(captured: list[urllib.request.Request], payload: bytes = b"") -> Any:
    def fake_urlopen(request: urllib.request.Request, *args: Any, **kwargs: Any) -> FakeResponse:
        captured.append(request)
        return FakeResponse(payload)

    return fake_urlopen


def test_clickhouse_store_events_sends_json_each_row(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr("autosiem.backends.open_url", _capturing_urlopen(captured))

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
    monkeypatch.setattr("autosiem.backends.open_url", _capturing_urlopen(captured, payload))

    events = ClickHouseBackend().list_events(limit=5)

    assert events == [SAMPLE_EVENT.to_dict()]
    query = urllib.parse.parse_qs(urllib.parse.urlparse(captured[0].full_url).query)["query"][0]
    assert query == "SELECT * FROM events LIMIT 5 FORMAT JSONEachRow"


def test_opensearch_store_events_hits_bulk(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr("autosiem.backends.open_url", _capturing_urlopen(captured))

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
    monkeypatch.setattr("autosiem.backends.open_url", _capturing_urlopen(captured, payload))

    events = OpenSearchBackend().list_events(limit=10)

    assert events == [SAMPLE_EVENT.to_dict()]
    assert "size=10" in captured[0].full_url


def test_http_backend_raises_backend_error_on_urlopen_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_urlopen(request: urllib.request.Request, *args: Any, **kwargs: Any) -> FakeResponse:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("autosiem.backends.open_url", failing_urlopen)

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


_BACKENDS = [ClickHouseBackend, OpenSearchBackend]


@pytest.mark.parametrize("backend_cls", _BACKENDS)
def test_every_backend_call_carries_a_finite_timeout(monkeypatch, backend_cls) -> None:
    """urlopen has no timeout by default. Assert the value as data, the way
    test_connectors does, so a regression is a red test and not a stuck CI job."""
    import autosiem.backends as backends

    seen: list[object] = []

    def fake_open_url(request: urllib.request.Request, timeout: object = None, **_kw: Any) -> FakeResponse:
        seen.append(timeout)
        return FakeResponse(b"{}")

    monkeypatch.setattr(backends, "open_url", fake_open_url)
    backend = backend_cls()
    backend.store_events([SAMPLE_EVENT])  # POST
    backend.list_events(limit=1)  # GET
    assert seen and all(isinstance(t, float) and 0 < t < float("inf") for t in seen)
    assert set(seen) == {backends.HTTP_TIMEOUT_SECONDS}


@pytest.mark.parametrize("backend_cls", _BACKENDS)
def test_a_silent_cluster_raises_backend_error_instead_of_hanging(monkeypatch, silent_server, backend_cls) -> None:
    """A read timeout is a TimeoutError, not a URLError, and used to escape BackendError.

    Run in a thread with a hard deadline so a missing timeout fails this test
    rather than hanging the run.
    """
    import autosiem.backends as backends

    monkeypatch.setattr(backends, "HTTP_TIMEOUT_SECONDS", 0.5)
    outcome: list[BaseException | None] = []

    def call() -> None:
        try:
            backend_cls(url=silent_server).store_events([SAMPLE_EVENT])
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - the test inspects it
            outcome.append(exc)

    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "the call did not time out"
    assert isinstance(outcome[0], BackendError) and "timed out" in str(outcome[0])


def _canned_server(reply: bytes) -> Iterator[str]:
    """One-shot HTTP-ish server that writes ``reply`` verbatim and closes."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def serve() -> None:
        listener.settimeout(5)
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        conn.settimeout(2)
        try:
            conn.recv(65536)
            conn.sendall(reply)
        except OSError:
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    thread.join(6)
    listener.close()


_BAD_REPLIES = {
    "truncated body": b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc",
    "not http": b"\x00\x01\x02garbage",
    "body is not utf-8": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\xff\xfe",
    "server error": b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
}


@pytest.mark.parametrize("backend_cls", _BACKENDS)
@pytest.mark.parametrize("name", sorted(_BAD_REPLIES))
def test_a_garbled_reply_is_a_backend_error_not_a_traceback(backend_cls, name: str) -> None:
    """HTTPException (truncated or non-HTTP replies) and UnicodeDecodeError are not OSErrors."""
    for url in _canned_server(_BAD_REPLIES[name]):
        with pytest.raises(BackendError, match="request failed"):
            backend_cls(url=url).store_events([SAMPLE_EVENT])


@pytest.mark.parametrize("backend_cls", _BACKENDS)
@pytest.mark.parametrize("url", ["myhost", "http://[::1", "http://localhost:abc"])
def test_a_malformed_backend_url_is_a_backend_error(backend_cls, url: str) -> None:
    with pytest.raises(BackendError, match="request failed"):
        backend_cls(url=url).store_events([SAMPLE_EVENT])

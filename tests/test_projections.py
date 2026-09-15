import json
from unittest.mock import MagicMock

import pytest

from autosiem.projections import EventProjection, event_key


@pytest.mark.parametrize("url", ["http://example.org", "https://user:secret@example.org", "file:///tmp/a", "https://example.org?q=x"])
def test_projection_rejects_unsafe_configuration(url):
    with pytest.raises(ValueError):
        EventProjection("opensearch", url, "events")


def test_projection_uses_stable_tenant_identity_and_checks_ack():
    sink = EventProjection("opensearch", "https://example.org", "events")
    response = MagicMock()
    response.status = 201
    response.read.return_value = json.dumps({"_id": event_key("a", "id"), "result": "created"}).encode()
    sink._opener = MagicMock()
    sink._opener.open.return_value.__enter__.return_value = response
    sink.deliver("a", "id", {"event_id": "id"})
    sink.deliver("a", "id", {"event_id": "id"})
    calls = sink._opener.open.call_args_list
    assert calls[0].args[0].full_url == calls[1].args[0].full_url
    assert calls[0].args[0].method == "PUT"
    assert calls[0].kwargs["timeout"] == 10
    assert event_key("a", "id") != event_key("b", "id")
    response.read.return_value = b'{"result":"created"}'
    with pytest.raises(RuntimeError, match="acknowledgement"):
        sink.deliver("a", "id", {})


def test_destination_changes_when_cluster_or_index_changes():
    a = EventProjection("opensearch", "https://a.example", "events")
    b = EventProjection("opensearch", "https://b.example", "events")
    c = EventProjection("opensearch", "https://a.example", "rebuild")
    assert len({a.destination, b.destination, c.destination}) == 3


def test_clickhouse_uses_tenant_event_columns_and_validated_table():
    with pytest.raises(ValueError):
        EventProjection("clickhouse", "https://example.org", "events;drop")
    sink = EventProjection("clickhouse", "https://example.org", "events")
    sink._opener = MagicMock()
    response = sink._opener.open.return_value.__enter__.return_value
    response.status, response.read.return_value = 200, b""
    sink.deliver("a", "id", {"action": "login"})
    request = sink._opener.open.call_args.args[0]
    assert json.loads(request.data) == {"tenant_id": "a", "event_id": "id", "data": '{"action": "login"}'}
    response.read.return_value = b"Code: 241. DB::Exception: memory limit exceeded"
    with pytest.raises(RuntimeError, match="acknowledge"):
        sink.deliver("a", "id", {})


def test_transport_failures_become_the_error_type_the_cli_catches() -> None:
    """HTTPError/URLError are neither ValueError nor RuntimeError, so they
    escaped `outbox --deliver` and printed a traceback."""
    import urllib.error
    from email.message import Message
    import pytest
    from autosiem.projections import EventProjection

    for failure in (
        urllib.error.HTTPError("https://sink.test", 503, "busy", Message(), None),
        urllib.error.URLError("connection refused"),
    ):
        projection = EventProjection("opensearch", "https://sink.test", "events")

        def _raise(*_args: object, **_kwargs: object) -> None:
            raise failure

        projection._opener.open = _raise  # type: ignore[method-assign]
        with pytest.raises(RuntimeError) as caught:
            projection.deliver("tenant", "event-1", {"a": 1})
        assert isinstance(caught.value, (ValueError, RuntimeError))
        # The backend body can echo the document back; only the status escapes.
        assert "a" not in str(caught.value).replace("failed", "")

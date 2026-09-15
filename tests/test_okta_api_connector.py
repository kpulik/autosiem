"""Tests for the API-native Okta System Log connector.

The HTTP transport is injected, so these exercise pagination, cursor
persistence, rate-limit backoff and auth failures without a network call.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from autosiem.connectors import (
    OKTA_MAX_BACKOFF_SECONDS,
    OKTA_MAX_RETRIES,
    ConnectorAuthError,
    OktaApiConnector,
    _okta_backoff_seconds,
    _parse_next_link,
    registry,
)

ORG = "https://dev-123456.okta.com"


def _entry(uuid: str, result: str = "SUCCESS", event_type: str = "user.session.start") -> dict[str, Any]:
    return {
        "uuid": uuid,
        "published": "2026-08-04T10:00:00.000Z",
        "eventType": event_type,
        "outcome": {"result": result},
        "actor": [{"alternateId": "alice@example.com", "displayName": "Alice"}],
        "client": {"ipAddress": "198.51.100.25"},
    }


class FakeTransport:
    """Serves canned (status, headers, body) responses and records requests."""

    def __init__(self, responses: list[tuple[int, dict[str, str], Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
        self.calls.append((url, headers))
        status, response_headers, body = self.responses.pop(0)
        if not isinstance(body, str):
            body = json.dumps(body)
        return status, response_headers, body


def _connector(transport: Any, **config: Any) -> OktaApiConnector:
    sleeps: list[float] = []
    connector = OktaApiConnector(
        {
            "url": ORG,
            "token": "test-token",
            "transport": transport,
            "sleep": sleeps.append,
            **config,
        }
    )
    connector.recorded_sleeps = sleeps  # type: ignore[attr-defined]
    return connector


# --- Link header parsing ---------------------------------------------------


def test_next_link_is_selected_by_rel_not_position() -> None:
    """Okta sends a self link first; taking the first URL would loop forever."""
    header = f'<{ORG}/api/v1/logs?after=self>; rel="self", <{ORG}/api/v1/logs?after=abc>; rel="next"'
    assert _parse_next_link(header) == f"{ORG}/api/v1/logs?after=abc"


def test_missing_next_link_is_none() -> None:
    assert _parse_next_link(f'<{ORG}/api/v1/logs>; rel="self"') is None
    assert _parse_next_link("") is None
    assert _parse_next_link("garbage") is None


# --- registry --------------------------------------------------------------


def test_connector_is_registered() -> None:
    assert "okta-api" in registry.names()
    assert isinstance(registry.create("okta-api", {"url": ORG, "token": "t"}), OktaApiConnector)


# --- happy path ------------------------------------------------------------


def test_a_single_page_is_mapped_through_okta_to_raw() -> None:
    transport = FakeTransport([(200, {}, [_entry("a"), _entry("b", result="FAILURE")])])
    events = _connector(transport).poll()

    assert len(events) == 2
    assert events[0]["source"] == "okta"
    assert events[0]["user"] == "alice@example.com"
    assert events[0]["src_ip"] == "198.51.100.25"
    assert events[1]["action"] == "login_failed"


def test_the_first_poll_uses_a_lookback_window() -> None:
    transport = FakeTransport([(200, {}, [])])
    _connector(transport).poll()
    url = transport.calls[0][0]
    assert url.startswith(f"{ORG}/api/v1/logs?")
    assert "since=" in url and "limit=" in url


def test_an_explicit_since_is_honored() -> None:
    transport = FakeTransport([(200, {}, [])])
    _connector(transport, since="2026-01-01T00:00:00Z").poll()
    assert "since=2026-01-01T00%3A00%3A00Z" in transport.calls[0][0]


def test_the_token_is_sent_as_an_ssws_header() -> None:
    transport = FakeTransport([(200, {}, [])])
    _connector(transport).poll()
    assert transport.calls[0][1]["Authorization"] == "SSWS test-token"


def test_the_token_is_read_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("AUTOSIEM_OKTA_TOKEN", "env-token")
    transport = FakeTransport([(200, {}, [])])
    connector = OktaApiConnector({"url": ORG, "transport": transport})
    connector.poll()
    assert transport.calls[0][1]["Authorization"] == "SSWS env-token"


# --- pagination ------------------------------------------------------------


def test_pages_are_followed_until_one_comes_back_empty() -> None:
    page2 = f'<{ORG}/api/v1/logs?after=2>; rel="next"'
    page3 = f'<{ORG}/api/v1/logs?after=3>; rel="next"'
    transport = FakeTransport(
        [
            (200, {"Link": page2}, [_entry("a")]),
            (200, {"Link": page3}, [_entry("b")]),
            (200, {"Link": page3}, []),
        ]
    )
    events = _connector(transport).poll()
    assert len(events) == 2
    assert len(transport.calls) == 3


def test_max_pages_bounds_a_single_poll() -> None:
    link = f'<{ORG}/api/v1/logs?after=x>; rel="next"'
    transport = FakeTransport([(200, {"Link": link}, [_entry(str(i))]) for i in range(10)])
    events = _connector(transport, max_pages=3).poll()
    assert len(events) == 3
    assert len(transport.calls) == 3


# --- cursor persistence ----------------------------------------------------


def test_the_cursor_is_persisted_and_resumed(tmp_path) -> None:
    """A restart must resume exactly, not replay the window or skip it."""
    state = tmp_path / "cursor.json"
    next_link = f'<{ORG}/api/v1/logs?after=cursor1>; rel="next"'

    first = FakeTransport([(200, {"Link": next_link}, [_entry("a")]), (200, {"Link": next_link}, [])])
    _connector(first, state_path=str(state)).poll()
    assert json.loads(state.read_text())["next"] == f"{ORG}/api/v1/logs?after=cursor1"

    second = FakeTransport([(200, {}, [])])
    _connector(second, state_path=str(state)).poll()
    assert second.calls[0][0] == f"{ORG}/api/v1/logs?after=cursor1"


def test_the_cursor_advances_even_on_an_empty_page(tmp_path) -> None:
    """An empty page still moves the window forward; that is Okta's design."""
    state = tmp_path / "cursor.json"
    link = f'<{ORG}/api/v1/logs?after=moved>; rel="next"'
    _connector(FakeTransport([(200, {"Link": link}, [])]), state_path=str(state)).poll()
    assert json.loads(state.read_text())["next"] == f"{ORG}/api/v1/logs?after=moved"


def test_a_corrupt_cursor_file_falls_back_to_the_time_window(tmp_path) -> None:
    state = tmp_path / "cursor.json"
    state.write_text("{not json")
    transport = FakeTransport([(200, {}, [])])
    _connector(transport, state_path=str(state)).poll()
    assert "since=" in transport.calls[0][0]


def test_no_state_path_still_polls(tmp_path) -> None:
    transport = FakeTransport([(200, {}, [_entry("a")])])
    assert len(_connector(transport).poll()) == 1


# --- rate limiting and errors ----------------------------------------------


def test_a_429_is_retried_after_backing_off() -> None:
    transport = FakeTransport([(429, {"X-Rate-Limit-Reset": "0"}, ""), (200, {}, [_entry("a")])])
    connector = _connector(transport)
    events = connector.poll()
    assert len(events) == 1
    assert len(connector.recorded_sleeps) == 1  # type: ignore[attr-defined]


def test_a_server_error_is_retried() -> None:
    transport = FakeTransport([(503, {}, ""), (200, {}, [_entry("a")])])
    assert len(_connector(transport).poll()) == 1


def test_retries_are_bounded_and_reported_in_health() -> None:
    transport = FakeTransport([(429, {}, "") for _ in range(OKTA_MAX_RETRIES)])
    connector = _connector(transport)
    assert connector.poll() == []
    assert connector.health().ok is False
    assert "429" in connector.health().detail


def test_an_invalid_token_is_surfaced_not_retried() -> None:
    transport = FakeTransport([(401, {}, "")])
    connector = _connector(transport)
    assert connector.poll() == []
    assert connector.health().ok is False
    assert "rejected the token" in connector.health().detail
    assert len(transport.calls) == 1


def test_a_missing_token_is_a_clear_error(monkeypatch) -> None:
    monkeypatch.delenv("AUTOSIEM_OKTA_TOKEN", raising=False)
    connector = OktaApiConnector({"url": ORG, "transport": FakeTransport([(200, {}, [])])})
    assert connector.poll() == []
    assert "no Okta API token" in (connector.health().detail or "")


def test_a_missing_url_does_not_call_out() -> None:
    transport = FakeTransport([])
    connector = OktaApiConnector({"token": "t", "transport": transport})
    assert connector.poll() == []
    assert transport.calls == []
    assert connector.health().ok is False


def test_invalid_json_is_reported_not_raised() -> None:
    connector = _connector(FakeTransport([(200, {}, "not json")]))
    assert connector.poll() == []
    assert "invalid JSON" in (connector.health().detail or "")


def test_non_dict_records_are_skipped() -> None:
    transport = FakeTransport([(200, {}, [_entry("a"), "junk", 42])])
    assert len(_connector(transport).poll()) == 1


# --- backoff maths ---------------------------------------------------------


def test_backoff_uses_the_reset_header_when_it_is_in_the_future() -> None:
    import time as _time

    wait = _okta_backoff_seconds({"x-rate-limit-reset": str(_time.time() + 5)}, attempt=1)
    assert 0 < wait <= 6


def test_backoff_is_capped() -> None:
    import time as _time

    wait = _okta_backoff_seconds({"x-rate-limit-reset": str(_time.time() + 9999)}, attempt=1)
    assert wait == OKTA_MAX_BACKOFF_SECONDS


def test_backoff_falls_back_to_exponential() -> None:
    assert _okta_backoff_seconds({}, attempt=1) == 1.0
    assert _okta_backoff_seconds({}, attempt=3) == 4.0
    assert _okta_backoff_seconds({"x-rate-limit-reset": "garbage"}, attempt=2) == 2.0


# --- health ----------------------------------------------------------------


def test_health_is_ok_after_a_successful_poll() -> None:
    connector = _connector(FakeTransport([(200, {}, [_entry("a")])]))
    connector.poll()
    health = connector.health()
    assert health.ok is True
    assert health.events_received == 1
    assert health.last_poll is not None


def test_health_recovers_after_a_failure_then_success() -> None:
    connector = _connector(FakeTransport([(401, {}, "")]))
    connector.poll()
    assert connector.health().ok is False
    connector._transport = FakeTransport([(200, {}, [_entry("a")])])
    connector.poll()
    assert connector.health().ok is True


# --- parse -----------------------------------------------------------------


def test_parse_maps_one_raw_record() -> None:
    connector = _connector(FakeTransport([]))
    parsed = connector.parse(json.dumps(_entry("a")))
    assert parsed["source"] == "okta"
    assert parsed["user"] == "alice@example.com"


def test_parse_rejects_a_non_object() -> None:
    connector = _connector(FakeTransport([]))
    with pytest.raises(ValueError):
        connector.parse("[1, 2]")


# --- auth error type -------------------------------------------------------


def test_connector_auth_error_is_a_runtime_error() -> None:
    assert issubclass(ConnectorAuthError, RuntimeError)


# --- transport policy (SEC-017) -------------------------------------------


def test_plaintext_org_url_is_refused_before_any_request() -> None:
    """This connector predated net.require_https and bypassed it."""
    transport = FakeTransport([(200, {}, [])])
    connector = _connector(transport, url="http://dev-123456.okta.com")
    assert connector.poll() == []
    assert "InsecureURLError" in connector.health().detail
    assert transport.calls == []


def test_loopback_is_not_exempt_for_a_remote_log_source() -> None:
    """llm.py opts loopback into plaintext; an org's audit log never does."""
    transport = FakeTransport([(200, {}, [])])
    connector = _connector(transport, url="http://localhost:8080")
    assert connector.poll() == []
    assert "InsecureURLError" in connector.health().detail
    assert transport.calls == []

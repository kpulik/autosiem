"""Tests for the API-native Microsoft Entra ID sign-in connector.

Both transports are injected, so these exercise the OAuth client-credentials
exchange, token caching and refresh, `@odata.nextLink` pagination, replay
suppression and throttling without a network call.

The token lifecycle is what is new here. Okta and GitHub carry a long-lived
token from the environment; Entra has to obtain one, cache it against a clock,
and renew it mid-run, so most of these cases are about that.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from autosiem.connectors import (
    ENTRA_MAX_BACKOFF_SECONDS,
    ENTRA_MAX_RETRIES,
    ENTRA_SEEN_IDS,
    ENTRA_TOKEN_SKEW_SECONDS,
    EntraApiConnector,
    _entra_backoff_seconds,
    registry,
)

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-000000000000"
GRAPH = "https://graph.microsoft.com/v1.0"
SIGNINS = f"{GRAPH}/auditLogs/signIns"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"


def _signin(identifier: str, upn: str = "alice@acme.com", result: int = 0) -> dict[str, Any]:
    return {
        "id": identifier,
        "createdDateTime": "2026-09-14T10:00:00Z",
        "userPrincipalName": upn,
        "resultType": result,
        "ipAddress": "198.51.100.25",
        "appDisplayName": "Azure Portal",
        "deviceDetail": {"displayName": "laptop-7"},
        "tenantId": TENANT,
    }


def _page(records: list[dict[str, Any]], next_link: str | None = None) -> str:
    body: dict[str, Any] = {"value": records}
    if next_link:
        body["@odata.nextLink"] = next_link
    return json.dumps(body)


class FakeTokenTransport:
    """Serves canned token responses and records every exchange."""

    def __init__(self, responses: list[tuple[int, dict[str, str], Any]] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[tuple[str, dict[str, str], dict[str, str]]] = []

    def __call__(self, url: str, headers: dict[str, str],
                 form: dict[str, str]) -> tuple[int, dict[str, str], str]:
        self.calls.append((url, headers, form))
        if self.responses:
            status, response_headers, body = self.responses.pop(0)
        else:
            status, response_headers, body = 200, {}, {"access_token": "tok", "expires_in": 3600}
        if not isinstance(body, str):
            body = json.dumps(body)
        return status, response_headers, body


class FakeTransport:
    def __init__(self, responses: list[tuple[int, dict[str, str], Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
        self.calls.append((url, headers))
        status, response_headers, body = self.responses.pop(0)
        if not isinstance(body, str):
            body = json.dumps(body)
        return status, response_headers, body


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _connector(transport: Any, tokens: Any = None, clock: Any = None,
               **config: Any) -> EntraApiConnector:
    settings: dict[str, Any] = {
        "tenant_id": TENANT,
        "client_id": CLIENT,
        "client_secret": "s3cret",
        "transport": transport,
        "token_transport": tokens or FakeTokenTransport(),
        "sleep": lambda _seconds: None,
    }
    if clock is not None:
        settings["clock"] = clock
    settings.update(config)
    return EntraApiConnector(settings)


# -- registration and configuration ---------------------------------------

def test_connector_is_registered_alongside_the_file_based_one():
    assert "entra-api" in registry.names()
    assert "entra" in registry.names()
    assert isinstance(registry.create("entra-api", {"tenant_id": TENANT}), EntraApiConnector)


def test_missing_tenant_or_client_is_reported_without_a_request():
    transport = FakeTransport([])
    tokens = FakeTokenTransport()
    connector = _connector(transport, tokens, tenant_id="")
    assert connector.poll() == []
    assert "tenant_id" in connector.health().detail
    assert transport.calls == [] and tokens.calls == []


def test_missing_secret_is_an_auth_error_naming_the_env_var(monkeypatch):
    monkeypatch.delenv("AUTOSIEM_ENTRA_CLIENT_SECRET", raising=False)
    connector = EntraApiConnector({
        "tenant_id": TENANT, "client_id": CLIENT,
        "transport": FakeTransport([]), "token_transport": FakeTokenTransport(),
    })
    assert connector.poll() == []
    assert "AUTOSIEM_ENTRA_CLIENT_SECRET" in connector.health().detail


def test_secret_is_read_from_the_environment_not_argv(monkeypatch):
    monkeypatch.setenv("AUTOSIEM_ENTRA_CLIENT_SECRET", "env-secret")
    tokens = FakeTokenTransport()
    connector = EntraApiConnector({
        "tenant_id": TENANT, "client_id": CLIENT,
        "transport": FakeTransport([(200, {}, _page([]))]), "token_transport": tokens,
    })
    connector.poll()
    assert tokens.calls[0][2]["client_secret"] == "env-secret"


def test_custom_secret_env_var_is_honoured(monkeypatch):
    monkeypatch.setenv("TENANT_APP_SECRET", "other-secret")
    tokens = FakeTokenTransport()
    EntraApiConnector({
        "tenant_id": TENANT, "client_id": CLIENT, "client_secret_env": "TENANT_APP_SECRET",
        "transport": FakeTransport([(200, {}, _page([]))]), "token_transport": tokens,
    }).poll()
    assert tokens.calls[0][2]["client_secret"] == "other-secret"


# -- token exchange --------------------------------------------------------

def test_token_exchange_posts_the_client_credentials_grant():
    tokens = FakeTokenTransport()
    _connector(FakeTransport([(200, {}, _page([]))]), tokens).poll()
    url, headers, form = tokens.calls[0]
    assert url == TOKEN_URL
    assert form["grant_type"] == "client_credentials"
    assert form["scope"] == "https://graph.microsoft.com/.default"
    assert form["client_id"] == CLIENT
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_access_token_is_sent_as_a_bearer_header():
    tokens = FakeTokenTransport([(200, {}, {"access_token": "abc123", "expires_in": 3600})])
    transport = FakeTransport([(200, {}, _page([]))])
    _connector(transport, tokens).poll()
    assert transport.calls[0][1]["Authorization"] == "Bearer abc123"


def test_token_is_cached_across_pages_and_polls():
    clock = FakeClock()
    tokens = FakeTokenTransport()
    transport = FakeTransport([
        (200, {}, _page([_signin("a")], f"{SIGNINS}?$skiptoken=x")),
        (200, {}, _page([_signin("b")])),
        (200, {}, _page([])),
    ])
    connector = _connector(transport, tokens, clock)
    connector.poll()
    connector.poll()
    assert len(transport.calls) == 3
    assert len(tokens.calls) == 1  # one exchange served every request


def test_token_is_refreshed_once_it_expires():
    clock = FakeClock()
    tokens = FakeTokenTransport([
        (200, {}, {"access_token": "first", "expires_in": 3600}),
        (200, {}, {"access_token": "second", "expires_in": 3600}),
    ])
    transport = FakeTransport([(200, {}, _page([])), (200, {}, _page([]))])
    connector = _connector(transport, tokens, clock)
    connector.poll()
    clock.now += 3600  # past expiry
    connector.poll()
    assert len(tokens.calls) == 2
    assert transport.calls[1][1]["Authorization"] == "Bearer second"


def test_token_is_renewed_early_by_the_skew_window():
    """A token valid at the start of a request must not expire mid-flight."""
    clock = FakeClock()
    tokens = FakeTokenTransport([
        (200, {}, {"access_token": "first", "expires_in": 3600}),
        (200, {}, {"access_token": "second", "expires_in": 3600}),
    ])
    transport = FakeTransport([(200, {}, _page([])), (200, {}, _page([]))])
    connector = _connector(transport, tokens, clock)
    connector.poll()
    # Inside the real lifetime, but inside the skew window.
    clock.now += 3600 - ENTRA_TOKEN_SKEW_SECONDS + 1
    connector.poll()
    assert len(tokens.calls) == 2


def test_a_401_refreshes_the_token_once_and_retries():
    """A token can be revoked before it expires, so the clock is not enough."""
    clock = FakeClock()
    tokens = FakeTokenTransport([
        (200, {}, {"access_token": "stale", "expires_in": 3600}),
        (200, {}, {"access_token": "fresh", "expires_in": 3600}),
    ])
    transport = FakeTransport([(401, {}, ""), (200, {}, _page([_signin("a")]))])
    connector = _connector(transport, tokens, clock)
    assert len(connector.poll()) == 1
    assert connector.last_error is None
    assert len(tokens.calls) == 2
    assert transport.calls[1][1]["Authorization"] == "Bearer fresh"


def test_a_second_401_is_an_auth_failure_not_an_infinite_refresh_loop():
    tokens = FakeTokenTransport()
    transport = FakeTransport([(401, {}, ""), (401, {}, "")])
    connector = _connector(transport, tokens)
    assert connector.poll() == []
    assert "rejected the request" in connector.health().detail
    assert len(transport.calls) == 2


def test_rejected_credentials_do_not_leak_the_error_body():
    body = {"error": "invalid_client", "error_description": f"AADSTS7000215 for {CLIENT} secret ...xyz"}
    tokens = FakeTokenTransport([(401, {}, body)])
    connector = _connector(FakeTransport([]), tokens)
    assert connector.poll() == []
    detail = connector.health().detail
    assert "rejected the client credentials" in detail
    assert "AADSTS7000215" not in detail and "xyz" not in detail


def test_a_token_response_without_an_access_token_is_an_auth_error():
    tokens = FakeTokenTransport([(200, {}, {"token_type": "Bearer"})])
    connector = _connector(FakeTransport([]), tokens)
    assert connector.poll() == []
    assert "no access_token" in connector.health().detail


def test_a_missing_expires_in_forces_a_refresh_every_request():
    clock = FakeClock()
    tokens = FakeTokenTransport([
        (200, {}, {"access_token": "a"}),
        (200, {}, {"access_token": "b"}),
    ])
    transport = FakeTransport([(200, {}, _page([])), (200, {}, _page([]))])
    connector = _connector(transport, tokens, clock)
    connector.poll()
    connector.poll()
    assert len(tokens.calls) == 2  # never trusted, so never cached


def test_token_endpoint_server_error_is_reported_not_raised():
    tokens = FakeTokenTransport([(503, {}, "")])
    connector = _connector(FakeTransport([]), tokens)
    assert connector.poll() == []
    assert "token endpoint returned 503" in connector.health().detail


def test_plaintext_login_host_is_refused():
    connector = _connector(FakeTransport([]), FakeTokenTransport(), login_url="http://login.internal")
    assert connector.poll() == []
    assert "InsecureURLError" in connector.health().detail


# -- request shape and pagination -----------------------------------------

def test_first_poll_filters_from_the_lookback_window():
    transport = FakeTransport([(200, {}, _page([]))])
    _connector(transport, lookback_hours=6).poll()
    url = transport.calls[0][0]
    assert url.startswith(f"{SIGNINS}?")
    assert "%24top=100" in url
    assert "createdDateTime+ge" in url
    assert "%24orderby=createdDateTime" in url


def test_pagination_follows_odata_next_link_from_the_body():
    """Graph paginates in the payload, not an RFC 5988 Link header."""
    transport = FakeTransport([
        (200, {}, _page([_signin("a"), _signin("b")], f"{SIGNINS}?$skiptoken=p2")),
        (200, {}, _page([_signin("c")], f"{SIGNINS}?$skiptoken=p3")),
        (200, {}, _page([])),
    ])
    events = _connector(transport).poll()
    assert [event["entra_event"]["id"] for event in events] == ["a", "b", "c"]
    assert transport.calls[1][0] == f"{SIGNINS}?$skiptoken=p2"
    assert all(event["format"] == "entra_signin" for event in events)
    assert all(event["category"] == "authentication" for event in events)


def test_a_link_header_is_ignored_because_graph_does_not_use_one():
    header = {"Link": f'<{SIGNINS}?wrong=1>; rel="next"'}
    transport = FakeTransport([(200, header, _page([_signin("a")]))])
    assert len(_connector(transport).poll()) == 1
    assert len(transport.calls) == 1


def test_max_pages_bounds_a_single_poll():
    transport = FakeTransport([
        (200, {}, _page([_signin(f"e{i}")], f"{SIGNINS}?$skiptoken=p{i}")) for i in range(10)
    ])
    assert len(_connector(transport, max_pages=3).poll()) == 3
    assert len(transport.calls) == 3


def test_failed_and_successful_signins_map_to_different_actions():
    transport = FakeTransport([(200, {}, _page([_signin("a", result=0), _signin("b", result=50126)]))])
    events = _connector(transport).poll()
    assert events[0]["action"] == "login"
    assert events[1]["action"] == "login_failed"


def test_non_object_payload_is_rejected():
    connector = _connector(FakeTransport([(200, {}, "[]")]))
    assert connector.poll() == []
    assert "non-object payload" in connector.health().detail


def test_missing_value_array_yields_no_events():
    connector = _connector(FakeTransport([(200, {}, json.dumps({"@odata.context": "x"}))]))
    assert connector.poll() == []
    assert connector.last_error is None


# -- cursor and replay suppression ----------------------------------------

def test_cursor_is_persisted_and_resumed_across_restarts(tmp_path):
    state = tmp_path / "entra.json"
    first = FakeTransport([
        (200, {}, _page([_signin("a")], f"{SIGNINS}?$skiptoken=p2")),
        (200, {}, _page([])),
    ])
    _connector(first, state_path=str(state)).poll()
    assert json.loads(state.read_text())["next"] == f"{SIGNINS}?$skiptoken=p2"

    second = FakeTransport([(200, {}, _page([]))])
    _connector(second, state_path=str(state)).poll()
    assert second.calls[0][0] == f"{SIGNINS}?$skiptoken=p2"


def test_the_final_page_is_not_redelivered_on_the_next_poll(tmp_path):
    state = tmp_path / "entra.json"
    first = FakeTransport([
        (200, {}, _page([_signin("a")], f"{SIGNINS}?$skiptoken=p2")),
        (200, {}, _page([_signin("b")])),
    ])
    assert len(_connector(first, state_path=str(state)).poll()) == 2

    second = FakeTransport([(200, {}, _page([_signin("b"), _signin("c")]))])
    events = _connector(second, state_path=str(state)).poll()
    assert [event["entra_event"]["id"] for event in events] == ["c"]


def test_same_timestamp_signins_are_kept_because_the_filter_uses_ge(tmp_path):
    """`gt` would skip a second sign-in sharing the boundary timestamp."""
    transport = FakeTransport([(200, {}, _page([_signin("a"), _signin("b"), _signin("c")]))])
    events = _connector(transport).poll()
    assert [event["entra_event"]["id"] for event in events] == ["a", "b", "c"]


def test_seen_ids_are_persisted_and_bounded(tmp_path):
    state = tmp_path / "entra.json"
    entries = [_signin(f"e{i}") for i in range(ENTRA_SEEN_IDS + 25)]
    _connector(FakeTransport([(200, {}, _page(entries))]), state_path=str(state)).poll()
    seen = json.loads(state.read_text())["seen"]
    assert len(seen) == ENTRA_SEEN_IDS
    assert seen[-1] == f"e{ENTRA_SEEN_IDS + 24}"


def test_unreadable_state_file_falls_back_to_a_fresh_window(tmp_path):
    state = tmp_path / "entra.json"
    state.write_text("{ not json")
    transport = FakeTransport([(200, {}, _page([]))])
    connector = _connector(transport, state_path=str(state))
    assert connector.poll() == []
    assert connector.last_error is None
    assert transport.calls[0][0].startswith(f"{SIGNINS}?")


# -- throttling and errors -------------------------------------------------

def test_429_is_retried_using_retry_after():
    transport = FakeTransport([(429, {"Retry-After": "2"}, ""), (200, {}, _page([_signin("a")]))])
    connector = _connector(transport)
    assert len(connector.poll()) == 1
    assert connector.last_error is None


def test_429_gives_up_after_the_retry_budget():
    transport = FakeTransport([(429, {}, "") for _ in range(ENTRA_MAX_RETRIES)])
    connector = _connector(transport)
    assert connector.poll() == []
    assert f"after {ENTRA_MAX_RETRIES} attempts" in connector.health().detail


def test_server_errors_are_retried():
    transport = FakeTransport([(503, {}, ""), (200, {}, _page([_signin("a")]))])
    assert len(_connector(transport).poll()) == 1


def test_403_explains_the_licence_and_permission_requirement():
    connector = _connector(FakeTransport([(403, {}, "")]))
    assert connector.poll() == []
    detail = connector.health().detail
    assert "AuditLog.Read.All" in detail and "P1/P2" in detail


def test_invalid_json_is_reported_not_raised():
    connector = _connector(FakeTransport([(200, {}, "{oops")]))
    assert connector.poll() == []
    assert "invalid JSON" in connector.health().detail


def test_plaintext_graph_url_is_refused():
    transport = FakeTransport([(200, {}, _page([]))])
    connector = _connector(transport, url="http://graph.internal/v1.0")
    assert connector.poll() == []
    assert "InsecureURLError" in connector.health().detail
    assert transport.calls == []


# -- backoff arithmetic ----------------------------------------------------

def test_retry_after_is_read_as_a_delta_in_seconds():
    assert _entra_backoff_seconds({"retry-after": "7"}, 1) == 7.0


def test_backoff_is_capped_and_falls_back_to_exponential():
    assert _entra_backoff_seconds({"retry-after": "99999"}, 1) == ENTRA_MAX_BACKOFF_SECONDS
    assert _entra_backoff_seconds({}, 1) == 1.0
    assert _entra_backoff_seconds({}, 3) == 4.0
    assert _entra_backoff_seconds({"retry-after": "soon"}, 2) == 2.0


# -- parse -----------------------------------------------------------------

def test_parse_maps_one_record():
    event = _connector(FakeTransport([])).parse(json.dumps(_signin("a")))
    assert event["user"] == "alice@acme.com"
    assert event["source"] == "microsoft.entra"
    assert event["host"] == "laptop-7"


def test_parse_rejects_a_non_object():
    with pytest.raises(ValueError, match="JSON object"):
        _connector(FakeTransport([])).parse("[1, 2]")

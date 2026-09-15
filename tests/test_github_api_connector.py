"""Tests for the API-native GitHub organization audit-log connector.

The HTTP transport is injected, so these exercise pagination, cursor and
seen-id persistence, rate-limit backoff and auth failures without a network
call. The cases that differ from Okta are the interesting ones: GitHub drops
the Link header when you catch up, and answers throttling with 403 as well as
429.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from autosiem.connectors import (
    GITHUB_ID_FIELD,
    GITHUB_MAX_BACKOFF_SECONDS,
    GITHUB_MAX_RETRIES,
    GITHUB_SEEN_IDS,
    GitHubApiConnector,
    _github_backoff_seconds,
    _github_rate_limited,
    registry,
)

ORG = "acme-corp"
API = "https://api.github.com"
AUDIT = f"{API}/orgs/{ORG}/audit-log"


def _entry(document_id: str, action: str = "repo.create", actor: str = "alice") -> dict[str, Any]:
    return {
        GITHUB_ID_FIELD: document_id,
        "@timestamp": 1786000000000,
        "action": action,
        "actor": actor,
        "ip": "198.51.100.25",
        "org": ORG,
        "repo": f"{ORG}/service",
    }


def _next(cursor: str) -> dict[str, str]:
    return {"Link": f'<{AUDIT}?after={cursor}>; rel="next", <{AUDIT}>; rel="first"'}


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


def _connector(transport: Any, **config: Any) -> GitHubApiConnector:
    settings: dict[str, Any] = {
        "org": ORG,
        "token": "test-token",
        "transport": transport,
        "sleep": lambda _seconds: None,
    }
    settings.update(config)
    return GitHubApiConnector(settings)


# -- registration and configuration ---------------------------------------

def test_connector_is_registered_under_its_own_name():
    assert "github-api" in registry.names()
    assert isinstance(registry.create("github-api", {"org": ORG}), GitHubApiConnector)
    # The file-based connector keeps its name; this is an addition, not a swap.
    assert "github" in registry.names()


def test_missing_org_is_reported_without_a_request():
    transport = FakeTransport([])
    connector = _connector(transport, org="")
    assert connector.poll() == []
    assert connector.health().ok is False
    assert "org" in connector.health().detail
    assert transport.calls == []


def test_missing_token_is_an_auth_error_naming_the_env_var(monkeypatch):
    monkeypatch.delenv("AUTOSIEM_GITHUB_TOKEN", raising=False)
    connector = GitHubApiConnector({"org": ORG, "transport": FakeTransport([])})
    assert connector.poll() == []
    assert "AUTOSIEM_GITHUB_TOKEN" in connector.health().detail


def test_token_is_read_from_the_environment_not_argv(monkeypatch):
    monkeypatch.setenv("AUTOSIEM_GITHUB_TOKEN", "env-token")
    transport = FakeTransport([(200, {}, [])])
    connector = GitHubApiConnector({"org": ORG, "transport": transport})
    connector.poll()
    assert transport.calls[0][1]["Authorization"] == "Bearer env-token"


def test_custom_token_env_var_is_honoured(monkeypatch):
    monkeypatch.setenv("GH_AUDIT_TOKEN", "other-token")
    transport = FakeTransport([(200, {}, [])])
    GitHubApiConnector({"org": ORG, "token_env": "GH_AUDIT_TOKEN", "transport": transport}).poll()
    assert transport.calls[0][1]["Authorization"] == "Bearer other-token"


# -- request shape ---------------------------------------------------------

def test_first_poll_requests_an_ascending_window_with_api_version_headers():
    transport = FakeTransport([(200, {}, [])])
    _connector(transport, lookback_hours=6).poll()
    url, headers = transport.calls[0]
    assert url.startswith(f"{AUDIT}?")
    assert "order=asc" in url
    assert "include=all" in url
    assert "per_page=100" in url
    assert "created%3A%3E%3D" in url  # phrase=created:>=<since>
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_per_page_is_capped_at_the_documented_maximum():
    transport = FakeTransport([(200, {}, [])])
    _connector(transport, per_page=5000).poll()
    assert "per_page=100" in transport.calls[0][0]


def test_org_is_url_quoted():
    transport = FakeTransport([(200, {}, [])])
    _connector(transport, org="weird/org").poll()
    assert "/orgs/weird%2Forg/audit-log" in transport.calls[0][0]


def test_enterprise_server_base_url_is_used_verbatim():
    transport = FakeTransport([(200, {}, [])])
    _connector(transport, url="https://ghes.example.com/api/v3/").poll()
    assert transport.calls[0][0].startswith("https://ghes.example.com/api/v3/orgs/")


def test_plaintext_base_url_is_refused_by_transport_policy():
    transport = FakeTransport([(200, {}, [])])
    connector = _connector(transport, url="http://ghes.internal/api/v3")
    assert connector.poll() == []
    assert "InsecureURLError" in connector.health().detail
    assert transport.calls == []


def test_loopback_is_not_exempt_for_an_audit_feed():
    """llm.py opts loopback into plaintext; a remote audit log never does."""
    transport = FakeTransport([(200, {}, [])])
    connector = _connector(transport, url="http://localhost:8080")
    assert connector.poll() == []
    assert "InsecureURLError" in connector.health().detail
    assert transport.calls == []


# -- pagination ------------------------------------------------------------

def test_pagination_follows_rel_next_and_maps_every_record():
    transport = FakeTransport([
        (200, _next("c1"), [_entry("a"), _entry("b")]),
        (200, _next("c2"), [_entry("c")]),
        (200, {}, []),
    ])
    events = _connector(transport).poll()
    assert [event["github_event"][GITHUB_ID_FIELD] for event in events] == ["a", "b", "c"]
    assert all(event["format"] == "github_audit" for event in events)
    assert all(event["category"] == "cloud" for event in events)
    assert events[0]["user"] == "alice"
    assert events[0]["src_ip"] == "198.51.100.25"
    assert len(transport.calls) == 3


def test_max_pages_bounds_a_single_poll():
    transport = FakeTransport([(200, _next(f"c{i}"), [_entry(f"e{i}")]) for i in range(10)])
    events = _connector(transport, max_pages=3).poll()
    assert len(events) == 3
    assert len(transport.calls) == 3


def test_a_page_without_a_next_link_ends_the_poll():
    transport = FakeTransport([(200, {}, [_entry("only")])])
    events = _connector(transport).poll()
    assert len(events) == 1
    assert len(transport.calls) == 1


def test_non_object_payload_is_ignored_rather_than_crashing():
    transport = FakeTransport([(200, {}, ["not-an-object", _entry("a")])])
    events = _connector(transport).poll()
    assert [event["github_event"][GITHUB_ID_FIELD] for event in events] == ["a"]


# -- cursor and replay suppression ----------------------------------------

def test_cursor_is_persisted_and_resumed_across_restarts(tmp_path):
    state = tmp_path / "github.json"
    first = FakeTransport([(200, _next("c1"), [_entry("a")]), (200, {}, [])])
    _connector(first, state_path=str(state)).poll()
    assert json.loads(state.read_text())["next"] == f"{AUDIT}?after=c1"

    second = FakeTransport([(200, {}, [])])
    _connector(second, state_path=str(state)).poll()
    # Resumes from the stored cursor rather than re-deriving a lookback window.
    assert second.calls[0][0] == f"{AUDIT}?after=c1"


def test_the_final_page_is_not_redelivered_on_the_next_poll(tmp_path):
    """GitHub drops the Link header when caught up, so the cursor overlaps."""
    state = tmp_path / "github.json"
    first = FakeTransport([(200, _next("c1"), [_entry("a")]), (200, {}, [_entry("b")])])
    events = _connector(first, state_path=str(state)).poll()
    assert [event["github_event"][GITHUB_ID_FIELD] for event in events] == ["a", "b"]

    # The stored cursor points before "b", so GitHub serves it again.
    second = FakeTransport([(200, {}, [_entry("b"), _entry("c")])])
    events = _connector(second, state_path=str(state)).poll()
    assert [event["github_event"][GITHUB_ID_FIELD] for event in events] == ["c"]


def test_seen_ids_are_persisted_and_bounded(tmp_path):
    state = tmp_path / "github.json"
    entries = [_entry(f"e{i}") for i in range(GITHUB_SEEN_IDS + 50)]
    transport = FakeTransport([(200, {}, entries)])
    _connector(transport, state_path=str(state)).poll()
    seen = json.loads(state.read_text())["seen"]
    assert len(seen) == GITHUB_SEEN_IDS
    assert seen[-1] == f"e{GITHUB_SEEN_IDS + 49}"


def test_records_without_a_document_id_are_never_dropped():
    entry = _entry("x")
    del entry[GITHUB_ID_FIELD]
    transport = FakeTransport([(200, {}, [entry, dict(entry)])])
    assert len(_connector(transport).poll()) == 2


def test_unreadable_state_file_falls_back_to_a_fresh_window(tmp_path):
    state = tmp_path / "github.json"
    state.write_text("{ not json")
    transport = FakeTransport([(200, {}, [])])
    connector = _connector(transport, state_path=str(state))
    assert connector.poll() == []
    assert connector.last_error is None
    assert transport.calls[0][0].startswith(f"{AUDIT}?")


def test_a_poll_with_no_state_path_still_succeeds():
    transport = FakeTransport([(200, {}, [_entry("a")])])
    connector = _connector(transport)
    assert len(connector.poll()) == 1
    assert connector.last_error is None


# -- rate limiting and errors ---------------------------------------------

def test_403_with_exhausted_rate_limit_is_retried_not_treated_as_auth_failure():
    transport = FakeTransport([
        (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1"}, ""),
        (200, {}, [_entry("a")]),
    ])
    connector = _connector(transport)
    assert len(connector.poll()) == 1
    assert connector.last_error is None
    assert len(transport.calls) == 2


def test_403_without_rate_limit_headers_is_an_auth_failure():
    transport = FakeTransport([(403, {}, "")])
    connector = _connector(transport)
    assert connector.poll() == []
    assert "rejected the token" in connector.health().detail
    assert len(transport.calls) == 1


def test_401_is_an_auth_failure():
    connector = _connector(FakeTransport([(401, {}, "")]))
    assert connector.poll() == []
    assert "rejected the token" in connector.health().detail


def test_429_is_retried_then_gives_up_after_the_retry_budget():
    transport = FakeTransport([(429, {}, "") for _ in range(GITHUB_MAX_RETRIES)])
    connector = _connector(transport)
    assert connector.poll() == []
    assert f"after {GITHUB_MAX_RETRIES} attempts" in connector.health().detail
    assert len(transport.calls) == GITHUB_MAX_RETRIES


def test_server_errors_are_retried():
    transport = FakeTransport([(503, {}, ""), (200, {}, [_entry("a")])])
    connector = _connector(transport)
    assert len(connector.poll()) == 1
    assert len(transport.calls) == 2


def test_404_explains_the_enterprise_cloud_requirement():
    connector = _connector(FakeTransport([(404, {}, "")]))
    assert connector.poll() == []
    assert "read:audit_log" in connector.health().detail


def test_invalid_json_is_reported_not_raised():
    connector = _connector(FakeTransport([(200, {}, "{oops")]))
    assert connector.poll() == []
    assert "invalid JSON" in connector.health().detail


def test_a_recovered_poll_clears_the_previous_error():
    connector = _connector(FakeTransport([(500, {}, ""), (200, {}, [_entry("a")])]))
    connector.last_error = "stale"
    connector.poll()
    assert connector.last_error is None
    assert connector.health().ok is True


# -- backoff arithmetic ----------------------------------------------------

def test_retry_after_is_read_as_a_delta_in_seconds():
    assert _github_backoff_seconds({"retry-after": "12"}, 1) == 12.0


def test_rate_limit_reset_is_read_as_an_epoch_timestamp():
    wait = _github_backoff_seconds({"x-ratelimit-reset": str(int(time.time()) + 30)}, 1)
    assert 25 <= wait <= 31


def test_retry_after_wins_over_the_reset_header():
    headers = {"retry-after": "3", "x-ratelimit-reset": str(int(time.time()) + 600)}
    assert _github_backoff_seconds(headers, 1) == 3.0


def test_backoff_is_capped():
    far_future = {"x-ratelimit-reset": str(int(time.time()) + 100_000)}
    assert _github_backoff_seconds(far_future, 1) == GITHUB_MAX_BACKOFF_SECONDS
    assert _github_backoff_seconds({"retry-after": "100000"}, 1) == GITHUB_MAX_BACKOFF_SECONDS


def test_backoff_falls_back_to_exponential_without_headers():
    assert _github_backoff_seconds({}, 1) == 1.0
    assert _github_backoff_seconds({}, 3) == 4.0


def test_unparseable_headers_fall_back_instead_of_raising():
    assert _github_backoff_seconds({"retry-after": "soon"}, 1) == 1.0
    assert _github_backoff_seconds({"x-ratelimit-reset": "never"}, 2) == 2.0


def test_rate_limit_detection_reads_both_signals():
    assert _github_rate_limited({"retry-after": "5"}) is True
    assert _github_rate_limited({"x-ratelimit-remaining": "0"}) is True
    assert _github_rate_limited({"x-ratelimit-remaining": "4999"}) is False
    assert _github_rate_limited({}) is False


# -- parse -----------------------------------------------------------------

def test_parse_maps_one_record():
    event = _connector(FakeTransport([])).parse(json.dumps(_entry("a", action="repo.destroy")))
    assert event["action"] == "repo.destroy"
    assert event["source"] == "github"
    assert event["resource"] == f"{ORG}/service"


def test_parse_rejects_a_non_object():
    with pytest.raises(ValueError, match="JSON object"):
        _connector(FakeTransport([])).parse("[1, 2]")

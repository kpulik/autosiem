"""Tests for the API-native CloudTrail connector (S3-backed).

The transport is injected, so these exercise ListObjectsV2 pagination, gzip
decode, key-based resume and replay suppression without a network call. The
signature itself is covered by `test_sigv4.py` against AWS's own reference
implementation; here we only check that the connector signs at all and sends
exactly the headers it signed.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from typing import Any

import pytest

from autosiem.connectors import (
    CLOUDTRAIL_MAX_RETRIES,
    CLOUDTRAIL_SEEN_KEYS,
    CloudTrailApiConnector,
    _parse_list_objects,
    registry,
)

BUCKET = "cloudtrail-logs"
PREFIX = "AWSLogs/123456789012/CloudTrail/"
WHEN = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)


def _record(event_name: str = "AssumeRole", user: str = "alice") -> dict[str, Any]:
    return {
        "eventTime": "2026-09-15T10:00:00Z",
        "eventID": f"{event_name}-{user}",
        "eventName": event_name,
        "eventSource": "sts.amazonaws.com",
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {"userName": user, "accountId": "123456789012",
                         "arn": f"arn:aws:iam::123456789012:user/{user}"},
        "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/AdminRole"},
        "awsRegion": "us-east-1",
    }


def _gz(records: list[dict[str, Any]]) -> bytes:
    return gzip.compress(json.dumps({"Records": records}).encode("utf-8"))


def _listing(keys: list[str], next_token: str = "") -> bytes:
    entries = "".join(f"<Contents><Key>{key}</Key></Contents>" for key in keys)
    truncated = "true" if next_token else "false"
    token = f"<NextContinuationToken>{next_token}</NextContinuationToken>" if next_token else ""
    return (f'<?xml version="1.0"?><ListBucketResult><IsTruncated>{truncated}</IsTruncated>'
            f"{entries}{token}</ListBucketResult>").encode("utf-8")


class FakeS3:
    """Serves listings by query and objects by key; records every signed request."""

    def __init__(self, listings: list[bytes], objects: dict[str, bytes],
                 status: int = 200, fail_first: int = 0) -> None:
        self.listings = list(listings)
        self.objects = dict(objects)
        self.status = status
        self.fail_first = fail_first
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        self.calls.append((url, headers))
        if self.fail_first > 0:
            self.fail_first -= 1
            return 503, {}, b""
        if self.status != 200:
            return self.status, {}, b""
        path = url.split(".amazonaws.com", 1)[1]
        if path.startswith("/?") or path == "/":
            return 200, {}, (self.listings.pop(0) if self.listings else _listing([]))
        return 200, {}, self.objects.get(path.lstrip("/"), b"")


def _connector(transport: Any, **config: Any) -> CloudTrailApiConnector:
    settings: dict[str, Any] = {
        "bucket": BUCKET, "prefix": PREFIX, "region": "us-east-1",
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "transport": transport, "sleep": lambda _s: None, "clock": lambda: WHEN,
    }
    settings.update(config)
    return CloudTrailApiConnector(settings)


# -- registration and configuration ---------------------------------------

def test_connector_is_registered_beside_the_file_based_one():
    assert "cloudtrail-api" in registry.names()
    assert "cloudtrail" in registry.names()
    assert isinstance(registry.create("cloudtrail-api", {"bucket": BUCKET}), CloudTrailApiConnector)


def test_missing_bucket_is_reported_without_a_request():
    transport = FakeS3([], {})
    connector = _connector(transport, bucket="")
    assert connector.poll() == []
    assert "bucket" in connector.health().detail
    assert transport.calls == []


def test_missing_credentials_name_the_standard_env_vars(monkeypatch):
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    connector = CloudTrailApiConnector({"bucket": BUCKET, "transport": FakeS3([], {})})
    assert connector.poll() == []
    detail = connector.health().detail
    assert "AWS_ACCESS_KEY_ID" in detail and "AWS_SECRET_ACCESS_KEY" in detail


def test_credentials_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAENV")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-from-env")
    transport = FakeS3([_listing([])], {})
    CloudTrailApiConnector({"bucket": BUCKET, "transport": transport,
                            "clock": lambda: WHEN}).poll()
    assert "Credential=AKIAENV/" in transport.calls[0][1]["Authorization"]


# -- signing -------------------------------------------------------------

def test_every_request_is_signed_and_sends_exactly_what_it_signed():
    transport = FakeS3([_listing([])], {})
    _connector(transport).poll()
    _url, headers = transport.calls[0]
    authorization = headers["Authorization"]
    assert authorization.startswith("AWS4-HMAC-SHA256 Credential=")
    signed = authorization.split("SignedHeaders=")[1].split(",")[0]
    for name in signed.split(";"):
        assert name in headers, f"{name} is in SignedHeaders but was not sent"
    assert "x-amz-content-sha256" in headers and "x-amz-date" in headers


def test_a_session_token_reaches_the_request(monkeypatch):
    transport = FakeS3([_listing([])], {})
    _connector(transport, session_token="STS-TOKEN").poll()
    headers = transport.calls[0][1]
    assert headers["x-amz-security-token"] == "STS-TOKEN"
    assert "x-amz-security-token" in headers["Authorization"]


def test_a_plaintext_endpoint_is_impossible_by_construction():
    """The host is derived, so there is no config that yields http://."""
    connector = _connector(FakeS3([_listing([])], {}), region="eu-west-1")
    assert connector.host == f"{BUCKET}.s3.eu-west-1.amazonaws.com"
    connector.poll()
    assert connector.health().ok


# -- listing and reading --------------------------------------------------

def test_objects_are_listed_then_downloaded_and_mapped():
    key = f"{PREFIX}us-east-1/2026/09/15/a_20260915T1200Z.json.gz"
    transport = FakeS3([_listing([key])], {key: _gz([_record(), _record("ConsoleLogin", "bob")])})
    events = _connector(transport).poll()
    assert [event["action"] for event in events] == ["AssumeRole", "ConsoleLogin"]
    assert all(event["format"] == "cloudtrail" for event in events)
    assert all(event["category"] == "cloud" for event in events)
    assert events[0]["user"] == "alice"
    assert events[0]["src_ip"] == "203.0.113.10"
    assert events[0]["resource"] == "AdminRole"


def test_the_listing_request_carries_prefix_and_list_type():
    transport = FakeS3([_listing([])], {})
    _connector(transport).poll()
    url = transport.calls[0][0]
    assert "list-type=2" in url
    assert "prefix=AWSLogs" in url


def test_pagination_follows_the_continuation_token():
    keys = [f"{PREFIX}{i}.json.gz" for i in range(4)]
    transport = FakeS3(
        [_listing(keys[:2], next_token="TOKEN-2"), _listing(keys[2:])],
        {key: _gz([_record(user=f"u{i}")]) for i, key in enumerate(keys)},
    )
    events = _connector(transport).poll()
    assert len(events) == 4
    assert any("continuation-token=TOKEN-2" in url for url, _ in transport.calls)


def test_a_non_truncated_listing_ignores_a_stray_token():
    """IsTruncated false means stop, whatever token the body carries."""
    keys, token = _parse_list_objects(
        '<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a.json.gz</Key></Contents>'
        "<NextContinuationToken>ignored</NextContinuationToken></ListBucketResult>")
    assert keys == ["a.json.gz"] and token == ""


def test_xml_escaped_keys_are_unescaped():
    keys, _ = _parse_list_objects(
        "<ListBucketResult><IsTruncated>false</IsTruncated>"
        "<Contents><Key>AWSLogs/a&amp;b/c.json.gz</Key></Contents></ListBucketResult>")
    assert keys == ["AWSLogs/a&b/c.json.gz"]


def test_non_cloudtrail_objects_are_ignored():
    transport = FakeS3([_listing([f"{PREFIX}CloudTrail-Digest/x.json", f"{PREFIX}real.json.gz"])],
                       {f"{PREFIX}real.json.gz": _gz([_record()])})
    assert len(_connector(transport).poll()) == 1


def test_max_objects_bounds_one_poll():
    keys = [f"{PREFIX}{i:03d}.json.gz" for i in range(20)]
    transport = FakeS3([_listing(keys)], {key: _gz([_record()]) for key in keys})
    assert len(_connector(transport, max_objects=3).poll()) == 3


# -- resume and replay suppression ----------------------------------------

def test_the_last_key_is_persisted_and_resumes_with_start_after(tmp_path):
    state = tmp_path / "ct.json"
    key = f"{PREFIX}2026/09/15/a.json.gz"
    first = FakeS3([_listing([key])], {key: _gz([_record()])})
    _connector(first, state_path=str(state)).poll()
    assert json.loads(state.read_text())["last_key"] == key

    second = FakeS3([_listing([])], {})
    _connector(second, state_path=str(state)).poll()
    assert "start-after=" in second.calls[0][0]


def test_an_object_already_read_is_not_replayed(tmp_path):
    state = tmp_path / "ct.json"
    key = f"{PREFIX}a.json.gz"
    payload = {key: _gz([_record()])}
    assert len(_connector(FakeS3([_listing([key])], payload), state_path=str(state)).poll()) == 1
    # S3 lists it again (start-after is exclusive, but a re-list can overlap).
    assert _connector(FakeS3([_listing([key])], payload), state_path=str(state)).poll() == []


def test_the_seen_key_window_is_bounded(tmp_path):
    state = tmp_path / "ct.json"
    keys = [f"{PREFIX}{i:05d}.json.gz" for i in range(CLOUDTRAIL_SEEN_KEYS + 30)]
    transport = FakeS3([_listing(keys)], {key: _gz([]) for key in keys})
    _connector(transport, state_path=str(state), max_objects=len(keys)).poll()
    assert len(json.loads(state.read_text())["seen"]) == CLOUDTRAIL_SEEN_KEYS


def test_a_failed_object_does_not_advance_the_cursor(tmp_path):
    """A mid-poll failure must re-read the object, not skip past it."""
    state = tmp_path / "ct.json"
    good, bad = f"{PREFIX}a.json.gz", f"{PREFIX}b.json.gz"
    transport = FakeS3([_listing([good, bad])], {good: _gz([_record()]), bad: b"not-gzip"})
    connector = _connector(transport, state_path=str(state))
    assert len(connector.poll()) == 1
    assert connector.health().ok is False
    assert json.loads(state.read_text())["last_key"] == good


def test_unreadable_state_falls_back_to_a_full_listing(tmp_path):
    state = tmp_path / "ct.json"
    state.write_text("{ not json")
    transport = FakeS3([_listing([])], {})
    connector = _connector(transport, state_path=str(state))
    assert connector.poll() == []
    assert connector.last_error is None
    assert "start-after" not in transport.calls[0][0]


# -- errors ---------------------------------------------------------------

def test_403_explains_what_to_check():
    connector = _connector(FakeS3([], {}, status=403))
    assert connector.poll() == []
    detail = connector.health().detail
    assert "s3:ListBucket" in detail and "region" in detail


def test_404_points_at_the_bucket_or_region():
    connector = _connector(FakeS3([], {}, status=404))
    assert connector.poll() == []
    assert "wrong bucket or region" in connector.health().detail


def test_throttling_is_retried_then_gives_up():
    connector = _connector(FakeS3([_listing([])], {}, fail_first=CLOUDTRAIL_MAX_RETRIES))
    assert connector.poll() == []
    assert f"after {CLOUDTRAIL_MAX_RETRIES} attempts" in connector.health().detail


def test_a_transient_503_is_retried_and_succeeds():
    key = f"{PREFIX}a.json.gz"
    transport = FakeS3([_listing([key])], {key: _gz([_record()])}, fail_first=1)
    connector = _connector(transport)
    assert len(connector.poll()) == 1
    assert connector.last_error is None


def test_corrupt_gzip_is_reported_not_raised():
    key = f"{PREFIX}a.json.gz"
    connector = _connector(FakeS3([_listing([key])], {key: b"not-gzip-at-all"}))
    assert connector.poll() == []
    assert "not valid gzip" in connector.health().detail


def test_valid_gzip_holding_invalid_json_is_reported():
    key = f"{PREFIX}a.json.gz"
    connector = _connector(FakeS3([_listing([key])], {key: gzip.compress(b"{oops")}))
    assert connector.poll() == []
    assert "not valid JSON" in connector.health().detail


def test_an_object_without_a_records_array_yields_nothing():
    key = f"{PREFIX}a.json.gz"
    transport = FakeS3([_listing([key])], {key: gzip.compress(b'{"Records": null}')})
    connector = _connector(transport)
    assert connector.poll() == []
    assert connector.last_error is None


# -- parse -----------------------------------------------------------------

def test_parse_accepts_a_records_envelope_and_a_bare_record():
    connector = _connector(FakeS3([], {}))
    assert connector.parse(json.dumps({"Records": [_record()]}))["action"] == "AssumeRole"
    assert connector.parse(json.dumps(_record("ConsoleLogin")))["action"] == "ConsoleLogin"


def test_parse_rejects_an_empty_envelope_and_a_non_object():
    connector = _connector(FakeS3([], {}))
    with pytest.raises(ValueError, match="no records"):
        connector.parse(json.dumps({"Records": []}))
    with pytest.raises(ValueError, match="JSON object"):
        connector.parse("[1, 2]")

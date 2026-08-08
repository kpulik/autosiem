"""Connector SDK: parser + poller + health per source.

A connector is the smallest unit of "get data into AutoSIEM": it knows how to
parse one vendor's raw records and how to poll for new ones. This module ships
the interface, a registry, and a reference implementation
(``FilePollerConnector``) that tails JSONL files — write a ``BaseConnector``
subclass to add a vendor (CloudTrail, Okta, ...); register it and the CLI/API
can drive it. Zero runtime dependencies.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


@dataclass(slots=True)
class ConnectorHealth:
    ok: bool
    detail: str
    events_received: int = 0
    last_poll: str | None = None


class BaseConnector(ABC):
    """A data source: parse its raw records and poll for new events."""

    name = "base"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = dict(config or {})
        self.events_received = 0
        self.last_poll: str | None = None
        self.last_error: str | None = None

    @abstractmethod
    def parse(self, raw: str) -> dict[str, Any]:
        """Turn one raw record into an event dict the normalizer understands."""

    @abstractmethod
    def poll(self) -> list[dict[str, Any]]:
        """Return any new events since the last poll (empty list = nothing new)."""

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            ok=self.last_error is None,
            detail=self.last_error or "ok",
            events_received=self.events_received,
            last_poll=self.last_poll,
        )

    def _record(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.events_received += len(events)
        self.last_poll = datetime.now(timezone.utc).isoformat()
        return events


class FilePollerConnector(BaseConnector):
    """Tail JSONL files: one JSON object per line, one event per line.

    Config: ``path`` — a ``.jsonl`` file or a directory of ``.jsonl`` files.
    Handles append and log rotation (truncate) by tracking byte offsets.
    """

    name = "file"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        raw_path = self.config.get("path")
        self.path: Path = Path(raw_path) if raw_path else Path.cwd()
        self._offsets: dict[Path, int] = {}

    def parse(self, raw: str) -> dict[str, Any]:
        line = raw.strip()
        if not line:
            raise ValueError("empty connector record")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("connector record must be a JSON object")
        return value

    def poll(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if self.path.is_file():
            files = [self.path]
        elif self.path.is_dir():
            files = sorted(self.path.glob("*.jsonl"))
        else:
            files = []
            self.last_error = f"path not found: {self.path}"
        for path in files:
            offset = self._offsets.get(path, 0)
            try:
                size = path.stat().st_size
                if size < offset:
                    offset = 0  # file was rotated/truncated
                with path.open("r", encoding="utf-8") as handle:
                    handle.seek(offset)
                    for line in handle:
                        try:
                            events.append(self.parse(line))
                        except (ValueError, json.JSONDecodeError):
                            continue  # partial trailing line: re-read after it completes
                    self._offsets[path] = handle.tell()
            except OSError as exc:
                self.last_error = f"{path}: {exc}"
        return self._record(events)

    def health(self) -> ConnectorHealth:
        if self.path.is_file() or self.path.is_dir():
            return super().health()
        return ConnectorHealth(
            ok=False,
            detail=f"path not found: {self.path}",
            events_received=self.events_received,
            last_poll=self.last_poll,
        )


def cloudtrail_record_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """Map one AWS CloudTrail record to the normalized raw-event shape.

    The normalizer then infers ``category=cloud`` (from ``aws.cloudtrail`` /
    ``AssumeRole``), so IAM and role-assumption records feed the existing
    cloud rules (AUTO-CLOUD-001, ...) with no extra configuration. Keeps the
    original record under ``cloudtrail_event`` so downstream tools can re-parse.
    """
    identity = record.get("userIdentity") or {}
    arn = str(identity.get("arn") or "")
    user = identity.get("userName") or (arn.rsplit("/", 1)[-1] if "/" in arn else None) or None
    request = record.get("requestParameters") or {}
    resource: Any = None
    role_arn = request.get("roleArn")
    if role_arn:
        resource = str(role_arn).rsplit("/", 1)[-1]
    elif request.get("roleName"):
        resource = request.get("roleName")
    return {
        "format": "cloudtrail",
        "category": "cloud",  # explicit: CloudTrail records are always cloud events
        "source": "aws.cloudtrail",
        "event_source": record.get("eventSource"),
        "event_type": record.get("eventType"),
        "timestamp": record.get("eventTime"),
        "event_id": record.get("eventID") or record.get("requestID"),
        "action": record.get("eventName"),
        "user": user,
        "src_ip": record.get("sourceIPAddress"),
        "cloud_account": identity.get("accountId") or record.get("recipientAccountId"),
        "aws_region": record.get("awsRegion"),
        "resource": resource,
        "outcome": "failure" if record.get("errorCode") else "success",
        "cloudtrail_event": record,
    }


class CloudTrailConnector(BaseConnector):
    """AWS CloudTrail connector: poll CloudTrail JSON and normalize records.

    Config: ``path`` — a file or a directory of CloudTrail exports. A file may
    be an S3-style export (``{"Records": [...]}`` with many events) or JSONL
    with one event object per line; both are expanded into one event per
    record. Zero runtime dependencies: the operator syncs CloudTrail JSON into
    the path (e.g. ``aws s3 sync s3://bucket/AWSLogs/... dir`` or a cron
    export), and ``poll`` tails new records with byte-offset tracking.
    """

    name = "cloudtrail"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        raw_path = self.config.get("path")
        self.path: Path = Path(raw_path) if raw_path else Path.cwd()
        self._offsets: dict[Path, int] = {}

    def parse(self, raw: str) -> dict[str, Any]:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("cloudtrail record must be a JSON object")
        records = value.get("Records")
        if isinstance(records, list):
            if not records:
                raise ValueError("cloudtrail export has no records")
            return cloudtrail_record_to_raw(records[0])
        return cloudtrail_record_to_raw(value)

    def poll(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if self.path.is_file():
            files = [self.path]
        elif self.path.is_dir():
            files = sorted(self.path.glob("*.json")) + sorted(self.path.glob("*.jsonl"))
        else:
            files = []
            self.last_error = f"path not found: {self.path}"
        for path in files:
            offset = self._offsets.get(path, 0)
            try:
                size = path.stat().st_size
                if size < offset:
                    offset = 0  # file was rotated/truncated
                with path.open("r", encoding="utf-8") as handle:
                    handle.seek(offset)
                    data = handle.read()
                    self._offsets[path] = handle.tell()
                events.extend(self._expand_documents(data))
            except OSError as exc:
                self.last_error = f"{path}: {exc}"
        return self._record(events)

    def _expand_documents(self, data: str) -> list[dict[str, Any]]:
        """Expand S3-export and/or JSONL payloads into normalized event dicts."""
        events: list[dict[str, Any]] = []
        if not data.strip():
            return events
        try:
            doc = json.loads(data)
            events.extend(self._expand(doc))
            return events
        except json.JSONDecodeError:
            pass
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.extend(self._expand(json.loads(line)))
            except (ValueError, json.JSONDecodeError):
                continue  # partial trailing line: re-read after it completes
        return events

    def _expand(self, doc: Any) -> list[dict[str, Any]]:
        if not isinstance(doc, dict):
            return []
        records = doc.get("Records")
        if isinstance(records, list):
            return [cloudtrail_record_to_raw(record) for record in records]
        return [cloudtrail_record_to_raw(doc)]

    def health(self) -> ConnectorHealth:
        if self.path.is_file() or self.path.is_dir():
            return super().health()
        return ConnectorHealth(
            ok=False,
            detail=f"path not found: {self.path}",
            events_received=self.events_received,
            last_poll=self.last_poll,
        )


def _first_okta(records: Any, *keys: str) -> Any:
    """Return the first non-empty value across the first element of a list."""
    if not isinstance(records, list) or not records:
        return None
    item = records[0]
    if isinstance(item, dict):
        for key in keys:
            value = item.get(key)
            if value not in (None, ""):
                return value
    return None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1] or path


def okta_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """Map an Okta system-log entry to the normalized raw-event shape.

    ``published``→timestamp, ``actor[0].alternateId``→user,
    ``outcome.result``→outcome (FAILURE→failure), ``client.ipAddress``→src_ip,
    ``target[0].id/alternateId``→resource. ``eventType`` drives the action so a
    successful session/auth event fires AUTO-CRED-001 and a failed one fires
    AUTO-AUTH-001.
    """
    outcome = record.get("outcome") or {}
    result = str(outcome.get("result") or "unknown").lower()
    event_type = str(record.get("eventType") or "")
    category = (
        "authentication"
        if any(k in event_type.lower() for k in ("session", "authentication", "authn", "mfa", "sso", "password"))
        else None
    )
    outcome_name = result if "fail" in result or "denied" in result or "error" in result else "success"
    if outcome_name != "success":
        action = "login_failed"
    elif "success" in result or "succeed" in result:
        action = "login" if any(k in event_type.lower() for k in ("session", "authentication")) else event_type or "okta_event"
    else:
        action = event_type or "okta_event"
    mapped = {
        "format": "okta_system_log",
        "source": "okta",
        "timestamp": record.get("published") or record.get("ts") or record.get("dateTime"),
        "event_id": record.get("uuid"),
        "action": action,
        "user": _first_okta(record.get("actor"), "alternateId", "displayName", "login"),
        "src_ip": (record.get("client") or {}).get("ipAddress"),
        "resource": _first_okta(record.get("target"), "alternateId", "displayName", "id"),
        "outcome": outcome_name,
        "okta_event": record,
    }
    if category:
        mapped["category"] = category
    return mapped


def github_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """Map a GitHub audit-log entry to the normalized raw-event shape.

    ``@timestamp``→timestamp, ``actor``→user, ``ip``→src_ip,
    ``organization``→cloud_account, ``repo``→resource, ``action``→action.
    Category is always ``cloud`` so audit entries feed cloud entity risk.
    """
    ts = record.get("@timestamp") or record.get("timestamp")
    if isinstance(ts, (int, float)) and ts > 1e12:
        ts = ts / 1000.0  # GitHub audit @timestamp is epoch milliseconds
    return {
        "format": "github_audit",
        "category": "cloud",
        "source": "github",
        "timestamp": ts,
        "action": record.get("action"),
        "user": record.get("actor") or record.get("user"),
        "src_ip": record.get("ip") or record.get("ip_address"),
        "cloud_account": record.get("org") or record.get("organization") or record.get("system"),
        "resource": record.get("repo") or record.get("repository"),
        "outcome": record.get("events_result") or record.get("result") or "unknown",
        "github_event": record,
    }


def entra_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """Map a Microsoft Entra ID sign-in log to the normalized raw-event shape.

    ``createdDateTime/activityDateTime``→timestamp, ``userPrincipalName``→user,
    ``resultType``→outcome, ``ipAddress``→src_ip, ``appDisplayName``→resource,
    ``deviceDetail.displayName``→host. A failed sign-in fires AUTO-AUTH-001 and a
    success fires AUTO-CRED-001.
    """
    result = str(record.get("resultType") or record.get("result") or "unknown").lower()
    device = (record.get("deviceDetail") or {}).get("displayName")
    if "fail" in result or "denied" in result or "error" in result or "notApply" in result:
        action = "login_failed"
    else:
        action = "login"
    return {
        "format": "entra_signin",
        "category": "authentication",
        "source": "microsoft.entra",
        "timestamp": record.get("createdDateTime") or record.get("activityDateTime") or record.get("timestamp"),
        "event_id": record.get("id"),
        "action": action,
        "user": record.get("userPrincipalName") or record.get("userDisplayName"),
        "src_ip": record.get("ipAddress") or record.get("ip_address"),
        "resource": record.get("appDisplayName"),
        "host": device,
        "cloud_account": record.get("tenantId") or record.get("userId"),
        "outcome": result,
        "entra_event": record,
    }


def _sysmon_dict(rec: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Sysmon JSON / Winlogbeat event-dict from client-shaped input."""
    event_raw = rec.get("Event")
    event: dict[str, Any] = event_raw if isinstance(event_raw, dict) else {}
    system_raw = event.get("System") or rec.get("System")
    system: dict[str, Any] = system_raw if isinstance(system_raw, dict) else {}
    ed_raw = event.get("EventData") or rec.get("EventData")
    ed: dict[str, Any] = ed_raw if isinstance(ed_raw, dict) else {}
    image = ed.get("Image") or system.get("Image") or rec.get("Image")
    cmdline = ed.get("CommandLine") or system.get("CommandLine") or rec.get("CommandLine")
    parent = ed.get("ParentImage") or system.get("ParentImage") or rec.get("ParentImage")
    utc = system.get("UtcTime") or ed.get("UtcTime") or rec.get("UtcTime")
    computer = system.get("Computer") or rec.get("Computer")
    event_id = system.get("EventID") or rec.get("EventID")
    return {
        "format": "sysmon",
        "category": "process",
        "source": "sysmon",
        "timestamp": utc,
        "event_id": str(event_id) if event_id is not None else None,
        "action": "process_start",
        "process_name": _basename(image),
        "command_line": cmdline,
        "resource": parent,
        "host": computer,
        "user": None,
        "sysmon_event": rec,
    }


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _sysmon_xml(text: str) -> dict[str, Any]:
    import xml.etree.ElementTree as ET

    root = ET.fromstring(text)
    system: dict[str, str] = {}
    data: dict[str, str] = {}
    for child in root.iter():
        if _xml_local(child.tag) == "System":
            for scc in child:
                system[_xml_local(scc.tag)] = (scc.text or "")
        elif _xml_local(child.tag) == "EventData":
            for dc in child:
                name = dc.get("Name") or _xml_local(dc.tag)
                data[name] = (dc.text or "")
    image = data.get("Image") or system.get("Image")
    return {
        "format": "sysmon",
        "category": "process",
        "source": "sysmon",
        "timestamp": system.get("UtcTime") or data.get("UtcTime"),
        "event_id": system.get("EventID"),
        "action": "process_start",
        "process_name": _basename(image),
        "command_line": data.get("CommandLine") or system.get("CommandLine"),
        "resource": data.get("ParentImage") or system.get("ParentImage"),
        "host": system.get("Computer"),
        "sysmon_event": {"System": system, "EventData": data},
    }


def sysmon_to_raw(record: dict[str, Any] | str) -> dict[str, Any]:
    """Map a Windows Sysmon event (JSON dict or Windows-Event XML string).

    ``Image``→process_name, ``CommandLine``→command_line,
    ``ParentImage``→resource, ``UtcTime``→timestamp, ``Computer``→host.
    With the process category set explicitly, credential-dumping and
    masquerading rules fire on Sysmon records automatically.
    """
    if isinstance(record, str):
        return _sysmon_xml(record)
    return _sysmon_dict(record)


def zeek_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """Map a Zeek log JSON record to the normalized raw-event shape.

    ``ts``→timestamp, ``id.orig_h``→src_ip, ``id.resp_h``→dst_ip. HTTP-log
    records (those with a ``uri``) also project a ``url``/``host`` so the
    web-exploit rule (AUTO-WEB-001) can fire on path-traversal probes.
    """
    ts = record.get("ts")
    if isinstance(ts, (int, float)) and ts > 1e12:
        ts = ts / 1000.0
    uri = record.get("uri")
    host = record.get("host")
    url = None
    if uri and host:
        url = host + (str(uri) if str(uri).startswith("/") else "/" + str(uri))
    mapped: dict[str, Any] = {
        "format": "zeek",
        "category": "network",
        "source": "zeek",
        "timestamp": ts,
        "event_id": record.get("uid"),
        "action": "http_request" if uri else "network_connection",
        "src_ip": record.get("id.orig_h"),
        "dst_ip": record.get("id.resp_h"),
        "resource": record.get("proto") or None,
    }
    if url:
        mapped["url"] = url
        mapped["host"] = host
    return mapped


def suricata_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """Map a Suricata eve.json event to the normalized raw-event shape.

    ``src_ip``/``dest_ip``→pairs, ``alert.signature``→resource, ``timestamp``→
    timestamp, ``event_type``→action. Suricata's 1..4 alert severity is mapped
    to the verbose names the normalizer understands.
    """
    alert = record.get("alert") or {}
    severity = alert.get("severity")
    severity_map: dict[Any, str] = {1: "critical", 2: "high", 3: "medium", 4: "low"}
    return {
        "format": "suricata_eve",
        "category": "network",
        "source": "suricata",
        "timestamp": record.get("timestamp"),
        "event_id": record.get("event_id"),
        "action": record.get("event_type") or "alert",
        "src_ip": record.get("src_ip"),
        "dst_ip": record.get("dest_ip") or record.get("dst_ip"),
        "resource": alert.get("signature"),
        "severity": str(severity_map.get(severity, "info")),
        "suricata_event": record,
    }


def asset_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """Map an asset-inventory record to the normalized raw-event shape.

    Feed for entity-risk scoring rather than detection: ``hostname/fqdn``→
    host, ``ip``→src_ip, ``owner``→user, ``os``→resource, ``account``→
    cloud_account. category is ``endpoint``.
    """
    return {
        "format": "asset_inventory",
        "category": "endpoint",
        "source": "asset",
        "action": "asset_inventory_observed",
        "host": record.get("hostname") or record.get("fqdn") or record.get("name"),
        "src_ip": record.get("ip") or record.get("ip_address"),
        "user": record.get("owner") or record.get("responsible_owner"),
        "cloud_account": record.get("account") or record.get("org"),
        "resource": record.get("os") or record.get("os_version"),
        "asset_event": record,
    }


class _MapperPollerConnector(FilePollerConnector):
    """File poller that runs a pure mapper over each JSON line."""

    mapper: Any = None

    def parse(self, raw: str) -> dict[str, Any]:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("connector record must be a JSON object")
        return self.mapper(value)


class OktaConnector(_MapperPollerConnector):
    """Okta system-log connector (JSONL of Okta log entries exported to disk)."""

    name = "okta"
    mapper = staticmethod(okta_to_raw)


class GitHubConnector(_MapperPollerConnector):
    """GitHub audit-log connector (JSONL of audit-log entries)."""

    name = "github"
    mapper = staticmethod(github_to_raw)


class EntraConnector(_MapperPollerConnector):
    """Microsoft Entra ID sign-in connector (JSONL of sign-in logs)."""

    name = "entra"
    mapper = staticmethod(entra_to_raw)


class SysmonConnector(_MapperPollerConnector):
    """Sysmon connector (JSONL of WinEvent/Sysmon dicts; XML strings on a line are parsed)."""

    name = "sysmon"

    def parse(self, raw: str) -> dict[str, Any]:
        stripped = raw.strip()
        if not stripped:
            raise ValueError("empty connector record")
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            value = stripped  # treat as XML string
        return sysmon_to_raw(value)


class ZeekConnector(_MapperPollerConnector):
    name = "zeek"
    mapper = staticmethod(zeek_to_raw)


class SuricataConnector(_MapperPollerConnector):
    name = "suricata"
    mapper = staticmethod(suricata_to_raw)


class AssetConnector(_MapperPollerConnector):
    name = "asset"
    mapper = staticmethod(asset_to_raw)


# --- API-native connectors -------------------------------------------------
#: Default page size for the Okta System Log API (Okta's own maximum is 1000).
OKTA_DEFAULT_LIMIT = 200
#: Safety bound on pages followed in a single poll, so one call cannot run away.
OKTA_DEFAULT_MAX_PAGES = 10
#: How far back a first-ever poll reaches when no cursor exists yet.
OKTA_DEFAULT_LOOKBACK_HOURS = 24
#: Attempts for a rate-limited or transient request before giving up.
OKTA_MAX_RETRIES = 3
#: Never sleep longer than this on a 429, however far out the reset header is.
OKTA_MAX_BACKOFF_SECONDS = 60.0


class ConnectorAuthError(RuntimeError):
    """Raised when a connector has no usable credential."""


def _parse_next_link(link_header: str) -> str | None:
    """Extract the ``rel="next"`` URL from an RFC 5988 Link header.

    Okta paginates with ``Link: <url>; rel="next"``, and also sends a ``self``
    link, so matching on rel is required rather than taking the first URL.
    """
    for part in (link_header or "").split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url = segments[0].strip()
        if not (url.startswith("<") and url.endswith(">")):
            continue
        for attr in segments[1:]:
            key, _, value = attr.strip().partition("=")
            if key.strip().lower() == "rel" and value.strip().strip('"\'') == "next":
                return url[1:-1]
    return None


class OktaApiConnector(BaseConnector):
    """Polls the Okta System Log API directly (no file export step).

    Config:
      ``url``         org base URL, e.g. ``https://dev-123456.okta.com``
      ``token``       API token; prefer ``token_env`` so it stays out of argv
      ``token_env``   env var holding the token (default ``AUTOSIEM_OKTA_TOKEN``)
      ``state_path``  where the pagination cursor is persisted
      ``limit``       page size (default 200)
      ``max_pages``   pages per poll (default 10)
      ``lookback_hours`` how far back the very first poll reaches (default 24)

    Okta's documented polling pattern is to follow the ``rel="next"`` link
    forever: it stays valid and simply returns an empty page when there is
    nothing new. The cursor is persisted so a restart resumes exactly where it
    stopped instead of replaying or skipping a window.
    """

    name = "okta-api"
    mapper = staticmethod(okta_to_raw)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.base_url = str(self.config.get("url") or "").rstrip("/")
        self.token_env = str(self.config.get("token_env") or "AUTOSIEM_OKTA_TOKEN")
        self._token = self.config.get("token") or os.environ.get(self.token_env)
        self.limit = int(self.config.get("limit") or OKTA_DEFAULT_LIMIT)
        self.max_pages = int(self.config.get("max_pages") or OKTA_DEFAULT_MAX_PAGES)
        self.lookback_hours = int(self.config.get("lookback_hours") or OKTA_DEFAULT_LOOKBACK_HOURS)
        raw_state = self.config.get("state_path")
        self.state_path: Path | None = Path(raw_state) if raw_state else None
        # Injected in tests; production uses urllib.
        self._transport: Callable[[str, dict[str, str]], tuple[int, dict[str, str], str]] = (
            self.config.get("transport") or _urllib_get
        )
        self._sleep: Callable[[float], None] = self.config.get("sleep") or time.sleep
        self._cursor: str | None = None

    # -- credentials -------------------------------------------------------
    def _require_token(self) -> str:
        if not self._token:
            raise ConnectorAuthError(
                f"no Okta API token: set {self.token_env} or pass token in the connector config"
            )
        return str(self._token)

    # -- cursor persistence ------------------------------------------------
    def _load_cursor(self) -> str | None:
        if self._cursor:
            return self._cursor
        if self.state_path and self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
            cursor = data.get("next")
            self._cursor = str(cursor) if cursor else None
        return self._cursor

    def _save_cursor(self, cursor: str | None) -> None:
        self._cursor = cursor
        if not (self.state_path and cursor):
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps({"next": cursor, "updated_at": datetime.now(timezone.utc).isoformat()}, indent=2),
                encoding="utf-8",
            )
        except OSError:
            # Losing the cursor costs a replay, not correctness; never fail a poll.
            pass

    def _start_url(self) -> str:
        cursor = self._load_cursor()
        if cursor:
            return cursor
        since = self.config.get("since")
        if not since:
            start = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
            since = start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        query = urllib.parse.urlencode({"since": since, "limit": self.limit})
        return f"{self.base_url}/api/v1/logs?{query}"

    # -- HTTP --------------------------------------------------------------
    def _request(self, url: str) -> tuple[list[dict[str, Any]], str | None]:
        """One page, with bounded retry on rate limiting and transient errors."""
        headers = {
            "Authorization": f"SSWS {self._require_token()}",
            "Accept": "application/json",
            "User-Agent": "AutoSIEM",
        }
        for attempt in range(1, OKTA_MAX_RETRIES + 1):
            status, response_headers, body = self._transport(url, headers)
            lowered = {key.lower(): value for key, value in response_headers.items()}
            if status == 429 or 500 <= status < 600:
                if attempt == OKTA_MAX_RETRIES:
                    raise RuntimeError(f"Okta API returned {status} after {attempt} attempts")
                self._sleep(_okta_backoff_seconds(lowered, attempt))
                continue
            if status == 401 or status == 403:
                raise ConnectorAuthError(f"Okta API rejected the token ({status})")
            if status >= 400:
                raise RuntimeError(f"Okta API returned {status}")
            try:
                payload = json.loads(body) if body.strip() else []
            except ValueError as exc:
                raise RuntimeError(f"Okta API returned invalid JSON: {exc}") from exc
            records = [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
            return records, _parse_next_link(lowered.get("link", ""))
        raise RuntimeError("Okta API request exhausted its retries")

    # -- BaseConnector -----------------------------------------------------
    def parse(self, raw: str) -> dict[str, Any]:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("connector record must be a JSON object")
        return self.mapper(value)

    def poll(self) -> list[dict[str, Any]]:
        if not self.base_url:
            self.last_error = "no Okta org url configured"
            return self._record([])
        events: list[dict[str, Any]] = []
        url: str | None = self._start_url()
        try:
            for _ in range(self.max_pages):
                if not url:
                    break
                records, next_url = self._request(url)
                events.extend(self.mapper(record) for record in records)
                # Advance the cursor even on an empty page: that is how Okta
                # tells us the window moved forward.
                if next_url:
                    self._save_cursor(next_url)
                if not records:
                    break
                url = next_url
            self.last_error = None
        except ConnectorAuthError as exc:
            self.last_error = str(exc)
        except (RuntimeError, urllib.error.URLError, OSError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
        return self._record(events)


def _okta_backoff_seconds(headers: dict[str, str], attempt: int) -> float:
    """Seconds to wait before retrying, from Okta's reset header or backoff."""
    reset = headers.get("x-rate-limit-reset")
    if reset:
        try:
            wait = float(reset) - time.time()
            if wait > 0:
                return min(wait, OKTA_MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(float(2 ** (attempt - 1)), OKTA_MAX_BACKOFF_SECONDS)


def _urllib_get(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
    """Stdlib GET returning ``(status, headers, body)``; no third-party deps."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, dict(response.headers.items()), response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8")
        except Exception:
            pass
        return exc.code, dict(exc.headers.items() if exc.headers else {}), body


class ConnectorRegistry:
    """Name -> connector factory, so the CLI/API can drive any connector."""

    def __init__(self) -> None:
        self._factories: dict[str, Callable[[dict[str, Any] | None], BaseConnector]] = {}

    def register(self, name: str, factory: Callable[[dict[str, Any] | None], BaseConnector]) -> None:
        self._factories[name] = factory

    def create(self, name: str, config: dict[str, Any] | None = None) -> BaseConnector:
        factory = self._factories.get(name)
        if factory is None:
            raise KeyError(f"unknown connector: {name}")
        return factory(config)

    def names(self) -> list[str]:
        return sorted(self._factories)


registry = ConnectorRegistry()
registry.register(FilePollerConnector.name, FilePollerConnector)
registry.register(CloudTrailConnector.name, CloudTrailConnector)
registry.register(OktaConnector.name, OktaConnector)
registry.register(GitHubConnector.name, GitHubConnector)
registry.register(EntraConnector.name, EntraConnector)
registry.register(SysmonConnector.name, SysmonConnector)
registry.register(ZeekConnector.name, ZeekConnector)
registry.register(SuricataConnector.name, SuricataConnector)
registry.register(AssetConnector.name, AssetConnector)
registry.register(OktaApiConnector.name, OktaApiConnector)

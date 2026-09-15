"""Connector SDK: parser + poller + health per source.

A connector is the smallest unit of "get data into AutoSIEM": it knows how to
parse one vendor's raw records and how to poll for new ones. This module ships
the interface, a registry, and a reference implementation
(``FilePollerConnector``) that tails JSONL files — write a ``BaseConnector``
subclass to add a vendor (CloudTrail, Okta, ...); register it and the CLI/API
can drive it. Zero runtime dependencies.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import time
import zlib
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .net import InsecureURLError, require_https
from .sigv4 import sign_request

#: Socket timeout for every connector HTTP call. Without it urlopen inherits
#: the global default, which is None, so a silent peer hangs a poll forever and
#: collection stops with no error to alert on.
HTTP_TIMEOUT_SECONDS = 30.0


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
        "log_product": "aws",
        "log_service": "cloudtrail",
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
        "log_product": "okta",
        "log_service": "okta",
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
        "log_product": "github",
        "log_service": "audit",
        "timestamp": ts,
        "action": record.get("action"),
        "user": record.get("actor") or record.get("user"),
        "src_ip": record.get("ip") or record.get("ip_address"),
        "cloud_account": record.get("org") or record.get("organization") or record.get("system"),
        "resource": record.get("repo") or record.get("repository"),
        "outcome": record.get("events_result") or record.get("result") or "unknown",
        "github_event": record,
    }


def _entra_outcome(record: dict[str, Any]) -> tuple[str, str | None]:
    """Classify an Entra sign-in as success/failure, and keep the raw code.

    Entra reports ``resultType`` as a *numeric* code in a string: ``"0"`` is
    success and anything else is a failure reason (50126 bad password, 50053
    account locked, ...). Matching those against the words "fail"/"denied"
    classified every real failed sign-in as a successful login, so
    AUTO-AUTH-001 never fired on Entra data - and because the raw code was
    passed straight through as ``outcome``, AUTO-CRED-001 never fired either,
    since "0" is not "success". Text values are still understood, because
    ``status.failureReason`` and hand-written exports use words.
    """
    raw = record.get("resultType")
    if raw is None:
        raw = record.get("result")
    if raw is None or str(raw).strip() == "":
        return "unknown", None
    text = str(raw).strip()
    code = text if text.lstrip("-").isdigit() else None
    if code is not None:
        return ("success" if code.lstrip("-") == "0" else "failure"), code
    lowered = text.lower()
    if any(word in lowered for word in ("fail", "denied", "error", "notapply")):
        return "failure", text
    if "success" in lowered:
        return "success", text
    return lowered, text


def entra_to_raw(record: dict[str, Any]) -> dict[str, Any]:
    """Map a Microsoft Entra ID sign-in log to the normalized raw-event shape.

    ``createdDateTime/activityDateTime``→timestamp, ``userPrincipalName``→user,
    ``resultType``→outcome, ``ipAddress``→src_ip, ``appDisplayName``→resource,
    ``deviceDetail.displayName``→host. A failed sign-in fires AUTO-AUTH-001 and a
    success fires AUTO-CRED-001. See :func:`_entra_outcome` for why the result
    code is normalized rather than passed through.
    """
    result, result_code = _entra_outcome(record)
    device = (record.get("deviceDetail") or {}).get("displayName")
    action = "login_failed" if result == "failure" else "login"
    return {
        "format": "entra_signin",
        "category": "authentication",
        "source": "microsoft.entra",
        "log_product": "azure",
        "log_service": "signinlogs",
        "timestamp": record.get("createdDateTime") or record.get("activityDateTime") or record.get("timestamp"),
        "event_id": record.get("id"),
        "action": action,
        "user": record.get("userPrincipalName") or record.get("userDisplayName"),
        "src_ip": record.get("ipAddress") or record.get("ip_address"),
        "resource": record.get("appDisplayName"),
        "host": device,
        "cloud_account": record.get("tenantId") or record.get("userId"),
        "outcome": result,
        # The analyst still wants 50126 vs 50053; the rules want success/failure.
        "result_code": result_code,
        "entra_event": record,
    }


def _event_code(value: Any) -> Any:
    """Coerce a Windows EventID to int so XML and JSON events match alike.

    The XML parser leaves `<EventID>1</EventID>` as the string "1" while a JSON
    Sysmon event carries the int 1, and Sigma compiles `EventID: 1` to an int.
    Scalar matching is type-sensitive, so XML events silently failed every
    numeric EventID rule that JSON events matched. Non-numeric values (a named
    channel, an empty tag) pass through untouched.
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text) if text.lstrip("-").isdigit() else value


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
    event_code = _event_code(system.get("EventID") or rec.get("EventID"))
    event_id = system.get("EventRecordID") or rec.get("EventRecordID")
    provider_raw = system.get("Provider") or rec.get("ProviderName")
    provider = provider_raw.get("Name") if isinstance(provider_raw, dict) else provider_raw
    return {
        "format": "sysmon",
        "category": "process",
        "source": "sysmon",
        "log_product": "windows",
        "log_service": "sysmon",
        "timestamp": utc,
        "event_id": str(event_id) if event_id is not None else None,
        "event_code": event_code,
        "action": "process_start",
        "process_name": _basename(image),
        "command_line": cmdline,
        "resource": parent,
        "original_file_name": ed.get("OriginalFileName") or rec.get("OriginalFileName"),
        "parent_process_name": parent,
        "parent_command_line": ed.get("ParentCommandLine") or rec.get("ParentCommandLine"),
        "target_object": ed.get("TargetObject") or rec.get("TargetObject"),
        "target_file_name": ed.get("TargetFilename") or rec.get("TargetFilename"),
        "details": ed.get("Details") or rec.get("Details"),
        "script_block_text": ed.get("ScriptBlockText") or rec.get("ScriptBlockText"),
        "image_loaded": ed.get("ImageLoaded") or rec.get("ImageLoaded"),
        "provider_name": provider,
        "hashes": ed.get("Hashes") or rec.get("Hashes"),
        "integrity_level": ed.get("IntegrityLevel") or rec.get("IntegrityLevel"),
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
                name = _xml_local(scc.tag)
                system[name] = (scc.get("Name") or "") if name == "Provider" else (scc.text or "")
        elif _xml_local(child.tag) == "EventData":
            for dc in child:
                name = dc.get("Name") or _xml_local(dc.tag)
                data[name] = (dc.text or "")
    image = data.get("Image") or system.get("Image")
    return {
        "format": "sysmon",
        "category": "process",
        "source": "sysmon",
        "log_product": "windows",
        "log_service": "sysmon",
        "timestamp": system.get("UtcTime") or data.get("UtcTime"),
        "event_id": system.get("EventRecordID"),
        "event_code": _event_code(system.get("EventID")),
        "action": "process_start",
        "process_name": _basename(image),
        "command_line": data.get("CommandLine") or system.get("CommandLine"),
        "resource": data.get("ParentImage") or system.get("ParentImage"),
        "original_file_name": data.get("OriginalFileName"),
        "parent_process_name": data.get("ParentImage") or system.get("ParentImage"),
        "parent_command_line": data.get("ParentCommandLine"),
        "target_object": data.get("TargetObject"),
        "target_file_name": data.get("TargetFilename"),
        "details": data.get("Details"),
        "script_block_text": data.get("ScriptBlockText"),
        "image_loaded": data.get("ImageLoaded"),
        "provider_name": system.get("Provider"),
        "hashes": data.get("Hashes"),
        "integrity_level": data.get("IntegrityLevel"),
        "host": system.get("Computer"),
        "sysmon_event": {"System": system, "EventData": data},
    }


def sysmon_to_raw(record: dict[str, Any] | str) -> dict[str, Any]:
    """Map a Windows Sysmon event (JSON dict or Windows-Event XML string).

    ``Image`` to process_name, ``CommandLine`` to command_line, and the common
    EventID/process-parent/file/registry/image-load fields used by Sigma rules.
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
        target = require_https(url, what="the Okta System Log")
        for attempt in range(1, OKTA_MAX_RETRIES + 1):
            status, response_headers, body = self._transport(target, headers)
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
        except (InsecureURLError, RuntimeError, urllib.error.URLError, OSError) as exc:
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
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return response.status, dict(response.headers.items()), response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8")
        except Exception:
            pass
        return exc.code, dict(exc.headers.items() if exc.headers else {}), body


#: GitHub's own API host. Override for GitHub Enterprise Server, whose API
#: lives under ``https://<host>/api/v3``.
GITHUB_API_DEFAULT_URL = "https://api.github.com"
#: Audit-log page size. 100 is GitHub's documented maximum.
GITHUB_DEFAULT_PER_PAGE = 100
#: Safety bound on pages followed in a single poll.
GITHUB_DEFAULT_MAX_PAGES = 10
#: How far back a first-ever poll reaches when no cursor exists yet.
GITHUB_DEFAULT_LOOKBACK_HOURS = 24
#: Attempts for a rate-limited or transient request before giving up.
GITHUB_MAX_RETRIES = 3
#: Never sleep longer than this on a 429, however far out the reset header is.
GITHUB_MAX_BACKOFF_SECONDS = 60.0
#: Recently delivered ``_document_id`` values kept to suppress the replay
#: window described in :class:`GitHubApiConnector`.
GITHUB_SEEN_IDS = 1000
#: Audit-log records carry this stable unique id.
GITHUB_ID_FIELD = "_document_id"


def _filter_seen(records: list[dict[str, Any]], id_field: str,
                 seen: list[str], cap: int) -> list[dict[str, Any]]:
    """Drop records already delivered and remember the new ones, in place.

    Needed by any API that stops issuing a cursor once you are caught up: the
    only resume point left is the last cursor, which overlaps the final page.
    Records with no id are never dropped, because a missing id cannot prove a
    duplicate and losing a real event is worse than delivering one twice.
    """
    known = set(seen)
    fresh = []
    for record in records:
        identifier = record.get(id_field)
        if identifier is None:
            fresh.append(record)
            continue
        identifier = str(identifier)
        if identifier in known:
            continue
        known.add(identifier)
        seen.append(identifier)
        fresh.append(record)
    del seen[:-cap]
    return fresh


class GitHubApiConnector(BaseConnector):
    """Polls the GitHub organization audit log API directly (no file export).

    Config:
      ``org``          organization login, required
      ``url``          API base (default ``https://api.github.com``; for GHES
                       use ``https://<host>/api/v3``)
      ``token``        API token; prefer ``token_env`` so it stays out of argv
      ``token_env``    env var holding the token (default
                       ``AUTOSIEM_GITHUB_TOKEN``)
      ``state_path``   where the cursor and seen-id window are persisted
      ``include``      ``web``, ``git`` or ``all`` (default ``all``)
      ``per_page``     page size (default 100, GitHub's maximum)
      ``max_pages``    pages per poll (default 10)
      ``lookback_hours`` how far back the very first poll reaches (default 24)

    Two things differ from :class:`OktaApiConnector`, which is otherwise the
    template for this class.

    Okta's ``rel="next"`` link stays valid forever and returns an empty page
    when there is nothing new, so the cursor alone is a complete resume point.
    GitHub instead *omits* the Link header once you catch up, which leaves no
    cursor covering the final page. Re-requesting the last cursor we do have
    would re-deliver that page, so the ids of recently delivered records are
    persisted alongside the cursor and filtered out on the next poll. Replay is
    suppressed rather than risked, because nothing downstream deduplicates.

    GitHub also answers rate limiting with 403 as well as 429, and 403 is the
    same status it uses for a bad token. They are told apart by the rate-limit
    headers, so a throttled poll backs off instead of reporting bad credentials.

    The audit log API requires GitHub Enterprise Cloud and a token with
    ``read:audit_log``. A 404 usually means one of those is missing rather than
    a wrong org name.
    """

    name = "github-api"
    mapper = staticmethod(github_to_raw)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.org = str(self.config.get("org") or "").strip()
        self.base_url = str(self.config.get("url") or GITHUB_API_DEFAULT_URL).rstrip("/")
        self.token_env = str(self.config.get("token_env") or "AUTOSIEM_GITHUB_TOKEN")
        self._token = self.config.get("token") or os.environ.get(self.token_env)
        self.include = str(self.config.get("include") or "all")
        # "limit" is the CLI's page-size flag, shared with the Okta connector.
        requested = self.config.get("per_page") or self.config.get("limit") or GITHUB_DEFAULT_PER_PAGE
        self.per_page = min(int(requested), GITHUB_DEFAULT_PER_PAGE)
        self.max_pages = int(self.config.get("max_pages") or GITHUB_DEFAULT_MAX_PAGES)
        self.lookback_hours = int(self.config.get("lookback_hours") or GITHUB_DEFAULT_LOOKBACK_HOURS)
        raw_state = self.config.get("state_path")
        self.state_path: Path | None = Path(raw_state) if raw_state else None
        # Injected in tests; production uses urllib.
        self._transport: Callable[[str, dict[str, str]], tuple[int, dict[str, str], str]] = (
            self.config.get("transport") or _urllib_get
        )
        self._sleep: Callable[[float], None] = self.config.get("sleep") or time.sleep
        self._cursor: str | None = None
        self._seen: list[str] = []
        self._state_loaded = False

    # -- credentials -------------------------------------------------------
    def _require_token(self) -> str:
        if not self._token:
            raise ConnectorAuthError(
                f"no GitHub API token: set {self.token_env} or pass token in the connector config"
            )
        return str(self._token)

    # -- cursor persistence ------------------------------------------------
    def _load_state(self) -> None:
        if self._state_loaded:
            return
        self._state_loaded = True
        if not (self.state_path and self.state_path.exists()):
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        cursor = data.get("next")
        self._cursor = str(cursor) if cursor else None
        seen = data.get("seen")
        if isinstance(seen, list):
            self._seen = [str(item) for item in seen][-GITHUB_SEEN_IDS:]

    def _save_state(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps({
                    "next": self._cursor,
                    "seen": self._seen[-GITHUB_SEEN_IDS:],
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }, indent=2),
                encoding="utf-8",
            )
        except OSError:
            # Losing the cursor costs a replay, not correctness; never fail a poll.
            pass

    def _start_url(self) -> str:
        self._load_state()
        if self._cursor:
            return self._cursor
        since = self.config.get("since")
        if not since:
            start = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
            since = start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        query = urllib.parse.urlencode({
            "include": self.include,
            "order": "asc",
            "per_page": self.per_page,
            "phrase": f"created:>={since}",
        })
        return f"{self.base_url}/orgs/{urllib.parse.quote(self.org, safe='')}/audit-log?{query}"

    # -- HTTP --------------------------------------------------------------
    def _request(self, url: str) -> tuple[list[dict[str, Any]], str | None]:
        """One page, with bounded retry on rate limiting and transient errors."""
        headers = {
            "Authorization": f"Bearer {self._require_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AutoSIEM",
        }
        target = require_https(url, what="the GitHub audit log")
        for attempt in range(1, GITHUB_MAX_RETRIES + 1):
            status, response_headers, body = self._transport(target, headers)
            lowered = {key.lower(): value for key, value in response_headers.items()}
            if status == 429 or 500 <= status < 600 or (status == 403 and _github_rate_limited(lowered)):
                if attempt == GITHUB_MAX_RETRIES:
                    raise RuntimeError(f"GitHub API returned {status} after {attempt} attempts")
                self._sleep(_github_backoff_seconds(lowered, attempt))
                continue
            if status in (401, 403):
                raise ConnectorAuthError(f"GitHub API rejected the token ({status})")
            if status == 404:
                raise RuntimeError(
                    f"GitHub API returned 404 for org {self.org!r}: the audit log API needs "
                    "GitHub Enterprise Cloud and a token with read:audit_log"
                )
            if status >= 400:
                raise RuntimeError(f"GitHub API returned {status}")
            try:
                payload = json.loads(body) if body.strip() else []
            except ValueError as exc:
                raise RuntimeError(f"GitHub API returned invalid JSON: {exc}") from exc
            records = [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
            return records, _parse_next_link(lowered.get("link", ""))
        raise RuntimeError("GitHub API request exhausted its retries")

    def _unseen(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return _filter_seen(records, GITHUB_ID_FIELD, self._seen, GITHUB_SEEN_IDS)

    # -- BaseConnector -----------------------------------------------------
    def parse(self, raw: str) -> dict[str, Any]:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("connector record must be a JSON object")
        return self.mapper(value)

    def poll(self) -> list[dict[str, Any]]:
        if not self.org:
            self.last_error = "no GitHub org configured"
            return self._record([])
        events: list[dict[str, Any]] = []
        url: str | None = self._start_url()
        try:
            for _ in range(self.max_pages):
                if not url:
                    break
                records, next_url = self._request(url)
                events.extend(self.mapper(record) for record in self._unseen(records))
                # Keep the last cursor when GitHub stops sending one: it is the
                # only resume point we have, and _unseen covers the overlap.
                if next_url:
                    self._cursor = next_url
                if not records:
                    break
                url = next_url
            self.last_error = None
        except ConnectorAuthError as exc:
            self.last_error = str(exc)
        except (InsecureURLError, RuntimeError, urllib.error.URLError, OSError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
        self._save_state()
        return self._record(events)


def _github_rate_limited(headers: dict[str, str]) -> bool:
    """True when a 403 is throttling rather than a rejected credential.

    GitHub answers both with 403, so the rate-limit headers are the only signal
    that backing off will help.
    """
    if headers.get("retry-after"):
        return True
    return headers.get("x-ratelimit-remaining") == "0"


def _github_backoff_seconds(headers: dict[str, str], attempt: int) -> float:
    """Seconds to wait before retrying, from GitHub's own headers.

    ``retry-after`` is a delta in seconds and ``x-ratelimit-reset`` is an epoch
    timestamp, so the two are read differently rather than interchangeably.
    """
    retry_after = headers.get("retry-after")
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), GITHUB_MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    reset = headers.get("x-ratelimit-reset")
    if reset:
        try:
            wait = float(reset) - time.time()
            if wait > 0:
                return min(wait, GITHUB_MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(float(2 ** (attempt - 1)), GITHUB_MAX_BACKOFF_SECONDS)


#: Microsoft identity platform token host.
ENTRA_LOGIN_URL = "https://login.microsoftonline.com"
#: Microsoft Graph API base.
ENTRA_GRAPH_URL = "https://graph.microsoft.com/v1.0"
#: Client-credentials scope: the app's own application permissions.
ENTRA_SCOPE = "https://graph.microsoft.com/.default"
#: Page size. Graph caps $top at 1000 for signIns but 100 keeps pages small.
ENTRA_DEFAULT_TOP = 100
#: Safety bound on pages followed in a single poll.
ENTRA_DEFAULT_MAX_PAGES = 10
#: How far back a first-ever poll reaches when no cursor exists yet.
ENTRA_DEFAULT_LOOKBACK_HOURS = 24
#: Attempts for a rate-limited or transient request before giving up.
ENTRA_MAX_RETRIES = 3
#: Never sleep longer than this on a 429, however far out Retry-After is.
ENTRA_MAX_BACKOFF_SECONDS = 60.0
#: Recently delivered sign-in ids kept to suppress the replay window.
ENTRA_SEEN_IDS = 1000
#: Sign-in records carry a stable GUID here.
ENTRA_ID_FIELD = "id"
#: Refresh this many seconds before the token actually expires, so a long page
#: fetch cannot start with a valid token and finish with an expired one.
ENTRA_TOKEN_SKEW_SECONDS = 60.0


class EntraApiConnector(BaseConnector):
    """Polls Microsoft Entra ID sign-in logs from Graph (no file export step).

    Config:
      ``tenant_id``      directory (tenant) GUID, required
      ``client_id``      app registration's application (client) id, required
      ``client_secret``  prefer ``client_secret_env`` so it stays out of argv
      ``client_secret_env`` env var holding the secret (default
                         ``AUTOSIEM_ENTRA_CLIENT_SECRET``)
      ``url``            Graph base (default ``https://graph.microsoft.com/v1.0``)
      ``login_url``      token host (default ``https://login.microsoftonline.com``)
      ``state_path``     where the cursor and seen-id window are persisted
      ``top``            page size (default 100)
      ``max_pages``      pages per poll (default 10)
      ``lookback_hours`` how far back the very first poll reaches (default 24)

    This is the first connector that has to *obtain* a credential rather than
    just carry one. Okta and GitHub take a long-lived token from the
    environment; Entra takes a client id and secret, exchanges them for an
    access token that expires in about an hour, and must refresh it mid-run.
    The token is fetched on demand, cached against a monotonic clock, and
    renewed ``ENTRA_TOKEN_SKEW_SECONDS`` early so a token cannot pass the check
    at the start of a page fetch and expire before the request lands. A 401 is
    still treated as a possible expiry and retried exactly once with a fresh
    token, because the clock is not authoritative -- the token can be revoked.

    Graph also paginates differently from both existing connectors: the next
    URL is ``@odata.nextLink`` *in the response body*, not an RFC 5988 Link
    header. Like GitHub it stops issuing one when you catch up, so the same
    bounded seen-id window suppresses the replay that the overlapping cursor
    would otherwise cause.

    The ``auditLogs/signIns`` endpoint needs an Entra ID P1 or P2 licence and
    the ``AuditLog.Read.All`` application permission with admin consent. A 403
    naming ``signIns`` usually means the licence, not the permission grant.
    """

    name = "entra-api"
    mapper = staticmethod(entra_to_raw)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.tenant_id = str(self.config.get("tenant_id") or "").strip()
        self.client_id = str(self.config.get("client_id") or "").strip()
        self.secret_env = str(self.config.get("client_secret_env")
                              or self.config.get("token_env") or "AUTOSIEM_ENTRA_CLIENT_SECRET")
        self._secret = self.config.get("client_secret") or os.environ.get(self.secret_env)
        self.base_url = str(self.config.get("url") or ENTRA_GRAPH_URL).rstrip("/")
        self.login_url = str(self.config.get("login_url") or ENTRA_LOGIN_URL).rstrip("/")
        requested = self.config.get("top") or self.config.get("limit") or ENTRA_DEFAULT_TOP
        self.top = min(int(requested), 1000)
        self.max_pages = int(self.config.get("max_pages") or ENTRA_DEFAULT_MAX_PAGES)
        self.lookback_hours = int(self.config.get("lookback_hours") or ENTRA_DEFAULT_LOOKBACK_HOURS)
        raw_state = self.config.get("state_path")
        self.state_path: Path | None = Path(raw_state) if raw_state else None
        # Injected in tests; production uses urllib. The token exchange is a
        # form POST, so it cannot share the GET transport the others use.
        self._transport: Callable[[str, dict[str, str]], tuple[int, dict[str, str], str]] = (
            self.config.get("transport") or _urllib_get
        )
        self._token_transport: Callable[
            [str, dict[str, str], dict[str, str]], tuple[int, dict[str, str], str]
        ] = self.config.get("token_transport") or _urllib_post_form
        self._sleep: Callable[[float], None] = self.config.get("sleep") or time.sleep
        self._clock: Callable[[], float] = self.config.get("clock") or time.monotonic
        self._cursor: str | None = None
        self._seen: list[str] = []
        self._state_loaded = False
        self._token: str | None = None
        self._token_expires_at = 0.0

    # -- credentials -------------------------------------------------------
    def _require_config(self) -> str:
        if not self.tenant_id or not self.client_id:
            raise ConnectorAuthError("Entra needs both tenant_id and client_id")
        if not self._secret:
            raise ConnectorAuthError(
                f"no Entra client secret: set {self.secret_env} or pass client_secret in the connector config"
            )
        return str(self._secret)

    def _fetch_token(self) -> str:
        """Exchange the client credentials for an access token."""
        secret = self._require_config()
        url = require_https(
            f"{self.login_url}/{urllib.parse.quote(self.tenant_id, safe='')}/oauth2/v2.0/token",
            what="an Entra access token",
        )
        form = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": secret,
            "scope": ENTRA_SCOPE,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "AutoSIEM"}
        status, _response_headers, body = self._token_transport(url, headers, form)
        if status in (400, 401, 403):
            # The body carries error_description, which repeats the client id
            # and sometimes the secret's thumbprint. Report the code only.
            raise ConnectorAuthError(f"Entra rejected the client credentials ({status})")
        if status >= 400:
            raise RuntimeError(f"Entra token endpoint returned {status}")
        try:
            payload = json.loads(body)
        except ValueError as exc:
            raise RuntimeError(f"Entra token endpoint returned invalid JSON: {exc}") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            raise ConnectorAuthError("Entra token response carried no access_token")
        try:
            lifetime = float(payload.get("expires_in") or 0)
        except (TypeError, ValueError):
            lifetime = 0.0
        self._token = str(token)
        # A missing or absurd lifetime means refresh on the next request rather
        # than trusting a token we cannot reason about.
        self._token_expires_at = self._clock() + max(lifetime - ENTRA_TOKEN_SKEW_SECONDS, 0.0)
        return self._token

    def _access_token(self, force: bool = False) -> str:
        if force or not self._token or self._clock() >= self._token_expires_at:
            return self._fetch_token()
        return self._token

    # -- cursor persistence ------------------------------------------------
    def _load_state(self) -> None:
        if self._state_loaded:
            return
        self._state_loaded = True
        if not (self.state_path and self.state_path.exists()):
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        cursor = data.get("next")
        self._cursor = str(cursor) if cursor else None
        seen = data.get("seen")
        if isinstance(seen, list):
            self._seen = [str(item) for item in seen][-ENTRA_SEEN_IDS:]

    def _save_state(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps({
                    "next": self._cursor,
                    "seen": self._seen[-ENTRA_SEEN_IDS:],
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }, indent=2),
                encoding="utf-8",
            )
        except OSError:
            # Losing the cursor costs a replay, not correctness; never fail a poll.
            pass

    def _start_url(self) -> str:
        self._load_state()
        if self._cursor:
            return self._cursor
        since = self.config.get("since")
        if not since:
            start = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
            since = start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        # ge rather than gt: two sign-ins can share a timestamp, and the
        # seen-id window already removes the duplicate that ge lets through.
        query = urllib.parse.urlencode({
            "$top": self.top,
            "$orderby": "createdDateTime",
            "$filter": f"createdDateTime ge {since}",
        })
        return f"{self.base_url}/auditLogs/signIns?{query}"

    # -- HTTP --------------------------------------------------------------
    def _request(self, url: str) -> tuple[list[dict[str, Any]], str | None]:
        """One page, refreshing an expired token and backing off on throttling."""
        target = require_https(url, what="Entra sign-in logs")
        refreshed = False
        for attempt in range(1, ENTRA_MAX_RETRIES + 1):
            headers = {
                "Authorization": f"Bearer {self._access_token()}",
                "Accept": "application/json",
                "User-Agent": "AutoSIEM",
            }
            status, response_headers, body = self._transport(target, headers)
            lowered = {key.lower(): value for key, value in response_headers.items()}
            if status == 401 and not refreshed:
                # The clock is not authoritative: a token can be revoked before
                # it expires. Spend exactly one retry finding out.
                refreshed = True
                self._access_token(force=True)
                continue
            if status == 429 or 500 <= status < 600:
                if attempt == ENTRA_MAX_RETRIES:
                    raise RuntimeError(f"Graph API returned {status} after {attempt} attempts")
                self._sleep(_entra_backoff_seconds(lowered, attempt))
                continue
            if status in (401, 403):
                raise ConnectorAuthError(
                    f"Graph API rejected the request ({status}); auditLogs/signIns needs "
                    "AuditLog.Read.All with admin consent and an Entra ID P1/P2 licence"
                )
            if status >= 400:
                raise RuntimeError(f"Graph API returned {status}")
            try:
                payload = json.loads(body) if body.strip() else {}
            except ValueError as exc:
                raise RuntimeError(f"Graph API returned invalid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise RuntimeError("Graph API returned a non-object payload")
            value = payload.get("value")
            records = [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
            next_link = payload.get("@odata.nextLink")
            return records, str(next_link) if next_link else None
        raise RuntimeError("Graph API request exhausted its retries")

    # -- BaseConnector -----------------------------------------------------
    def parse(self, raw: str) -> dict[str, Any]:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("connector record must be a JSON object")
        return self.mapper(value)

    def poll(self) -> list[dict[str, Any]]:
        if not (self.tenant_id and self.client_id):
            self.last_error = "no Entra tenant_id/client_id configured"
            return self._record([])
        events: list[dict[str, Any]] = []
        url: str | None = self._start_url()
        try:
            for _ in range(self.max_pages):
                if not url:
                    break
                records, next_url = self._request(url)
                fresh = _filter_seen(records, ENTRA_ID_FIELD, self._seen, ENTRA_SEEN_IDS)
                events.extend(self.mapper(record) for record in fresh)
                # Keep the last cursor when Graph stops sending one: it is the
                # only resume point we have, and the seen window covers the overlap.
                if next_url:
                    self._cursor = next_url
                if not records:
                    break
                url = next_url
            self.last_error = None
        except ConnectorAuthError as exc:
            self.last_error = str(exc)
        except (InsecureURLError, RuntimeError, urllib.error.URLError, OSError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
        self._save_state()
        return self._record(events)


def _entra_backoff_seconds(headers: dict[str, str], attempt: int) -> float:
    """Seconds to wait before retrying. Graph sends Retry-After in seconds."""
    retry_after = headers.get("retry-after")
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), ENTRA_MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(float(2 ** (attempt - 1)), ENTRA_MAX_BACKOFF_SECONDS)


def _urllib_post_form(url: str, headers: dict[str, str],
                      form: dict[str, str]) -> tuple[int, dict[str, str], str]:
    """Stdlib form POST returning ``(status, headers, body)``; no third-party deps.

    Separate from :func:`_urllib_get` because an OAuth token exchange is the
    only place a connector sends a body, and widening the GET signature would
    touch every connector that does not need it.
    """
    data = urllib.parse.urlencode(form).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return response.status, dict(response.headers.items()), response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8")
        except Exception:
            pass
        return exc.code, dict(exc.headers.items() if exc.headers else {}), body


#: CloudTrail delivers gzipped JSON to S3; that is the path this connector reads.
CLOUDTRAIL_DEFAULT_REGION = "us-east-1"
#: ListObjectsV2 caps at 1000 keys per page.
CLOUDTRAIL_DEFAULT_MAX_KEYS = 100
#: Safety bound on list pages followed in a single poll.
CLOUDTRAIL_DEFAULT_MAX_PAGES = 10
#: Safety bound on objects downloaded in a single poll, since each is a fetch.
CLOUDTRAIL_DEFAULT_MAX_OBJECTS = 50
#: Attempts for a throttled or transient request before giving up.
CLOUDTRAIL_MAX_RETRIES = 3
#: Never sleep longer than this on a throttle.
CLOUDTRAIL_MAX_BACKOFF_SECONDS = 60.0
#: Object keys already delivered, kept so a re-list does not replay them.
CLOUDTRAIL_SEEN_KEYS = 2000
#: A single CloudTrail object is small; this bounds a hostile or corrupt one.
CLOUDTRAIL_MAX_OBJECT_BYTES = 64 * 1024 * 1024


class CloudTrailApiConnector(BaseConnector):
    """Reads CloudTrail's gzipped JSON straight from S3, signing its own requests.

    Config:
      ``bucket``       S3 bucket CloudTrail delivers to, required
      ``prefix``       key prefix, e.g. ``AWSLogs/123456789012/CloudTrail/``
      ``region``       bucket region (default ``us-east-1``)
      ``access_key``   prefer the environment; see ``access_key_env``
      ``secret_key``   prefer the environment; see ``secret_key_env``
      ``session_token`` optional STS token, signed with the request
      ``*_env``        env vars holding each credential, defaulting to the
                       standard AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
                       AWS_SESSION_TOKEN
      ``state_path``   where the list cursor and seen-key window are persisted
      ``max_keys`` / ``max_pages`` / ``max_objects``  per-poll bounds

    This is the only connector whose auth is cryptographic rather than a header,
    because ``boto3`` is barred from the core. Signing lives in
    :mod:`autosiem.sigv4` and is checked against vectors generated by AWS's own
    botocore, not fixtures written here - a wrong signature returns 403, which
    is indistinguishable from a permissions problem.

    Progress is tracked by object KEY, not by a cursor over records. S3 keys
    sort lexicographically and CloudTrail keys embed the timestamp, so
    ``start-after`` resumes cleanly; the seen-key window then covers the
    boundary object the way the other connectors cover their final page.
    """

    name = "cloudtrail-api"
    mapper = staticmethod(cloudtrail_record_to_raw)

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.bucket = str(self.config.get("bucket") or "").strip()
        self.prefix = str(self.config.get("prefix") or "").lstrip("/")
        self.region = str(self.config.get("region") or CLOUDTRAIL_DEFAULT_REGION)
        self.access_env = str(self.config.get("access_key_env") or "AWS_ACCESS_KEY_ID")
        self.secret_env = str(self.config.get("secret_key_env") or "AWS_SECRET_ACCESS_KEY")
        self.token_env = str(self.config.get("session_token_env") or "AWS_SESSION_TOKEN")
        self._access = self.config.get("access_key") or os.environ.get(self.access_env)
        self._secret = self.config.get("secret_key") or os.environ.get(self.secret_env)
        self._token = self.config.get("session_token") or os.environ.get(self.token_env, "")
        self.max_keys = min(int(self.config.get("max_keys") or self.config.get("limit")
                                or CLOUDTRAIL_DEFAULT_MAX_KEYS), 1000)
        self.max_pages = int(self.config.get("max_pages") or CLOUDTRAIL_DEFAULT_MAX_PAGES)
        self.max_objects = int(self.config.get("max_objects") or CLOUDTRAIL_DEFAULT_MAX_OBJECTS)
        raw_state = self.config.get("state_path")
        self.state_path: Path | None = Path(raw_state) if raw_state else None
        # Injected in tests; production uses urllib.
        self._transport: Callable[[str, dict[str, str]], tuple[int, dict[str, str], bytes]] = (
            self.config.get("transport") or _urllib_get_bytes
        )
        self._sleep: Callable[[float], None] = self.config.get("sleep") or time.sleep
        self._clock: Callable[[], datetime] = self.config.get("clock") or (
            lambda: datetime.now(timezone.utc)
        )
        self._last_key: str | None = None
        self._seen: list[str] = []
        self._state_loaded = False

    @property
    def host(self) -> str:
        return f"{self.bucket}.s3.{self.region}.amazonaws.com"

    # -- credentials -------------------------------------------------------
    def _require_credentials(self) -> tuple[str, str]:
        if not self._access or not self._secret:
            raise ConnectorAuthError(
                f"no AWS credentials: set {self.access_env} and {self.secret_env}, "
                "or pass access_key/secret_key in the connector config"
            )
        return str(self._access), str(self._secret)

    # -- cursor persistence ------------------------------------------------
    def _load_state(self) -> None:
        if self._state_loaded:
            return
        self._state_loaded = True
        if not (self.state_path and self.state_path.exists()):
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        last = data.get("last_key")
        self._last_key = str(last) if last else None
        seen = data.get("seen")
        if isinstance(seen, list):
            self._seen = [str(item) for item in seen][-CLOUDTRAIL_SEEN_KEYS:]

    def _save_state(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps({
                    "last_key": self._last_key,
                    "seen": self._seen[-CLOUDTRAIL_SEEN_KEYS:],
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }, indent=2),
                encoding="utf-8",
            )
        except OSError:
            # Losing the cursor costs a replay, not correctness; never fail a poll.
            pass

    # -- HTTP --------------------------------------------------------------
    def _request(self, path: str, query: dict[str, str]) -> bytes:
        """One signed GET, with bounded retry on throttling and transient errors."""
        access, secret = self._require_credentials()
        url = require_https(
            f"https://{self.host}{urllib.parse.quote(path, safe='/')}", what="CloudTrail logs"
        )
        if query:
            url = f"{url}?{urllib.parse.urlencode(sorted(query.items()))}"
        for attempt in range(1, CLOUDTRAIL_MAX_RETRIES + 1):
            headers = sign_request(
                method="GET", host=self.host, path=path, query=query,
                region=self.region, service="s3", access_key=access, secret_key=secret,
                session_token=str(self._token or ""), now=self._clock(),
            )
            headers["User-Agent"] = "AutoSIEM"
            status, _response_headers, body = self._transport(url, headers)
            if status == 503 or status == 429 or 500 <= status < 600:
                if attempt == CLOUDTRAIL_MAX_RETRIES:
                    raise RuntimeError(f"S3 returned {status} after {attempt} attempts")
                self._sleep(min(float(2 ** (attempt - 1)), CLOUDTRAIL_MAX_BACKOFF_SECONDS))
                continue
            if status in (401, 403):
                raise ConnectorAuthError(
                    f"S3 rejected the signed request ({status}); check the key, the bucket "
                    "region, and that the principal has s3:ListBucket and s3:GetObject"
                )
            if status == 404:
                raise RuntimeError(f"S3 returned 404 for bucket {self.bucket!r}: wrong bucket or region")
            if status >= 400:
                raise RuntimeError(f"S3 returned {status}")
            if len(body) > CLOUDTRAIL_MAX_OBJECT_BYTES:
                raise RuntimeError("S3 object exceeds the size bound")
            return body
        raise RuntimeError("S3 request exhausted its retries")

    def _list_objects(self) -> list[str]:
        """Object keys to read, oldest first, resuming after the last one seen."""
        keys: list[str] = []
        token = ""
        for _ in range(self.max_pages):
            query = {"list-type": "2", "max-keys": str(self.max_keys)}
            if self.prefix:
                query["prefix"] = self.prefix
            if token:
                query["continuation-token"] = token
            elif self._last_key:
                # Keys sort lexicographically and CloudTrail embeds the
                # timestamp in them, so this resumes without rescanning.
                query["start-after"] = self._last_key
            page, token = _parse_list_objects(self._request("/", query).decode("utf-8", "replace"))
            keys.extend(key for key in page if key.endswith(".json.gz"))
            if not token or len(keys) >= self.max_objects:
                break
        return sorted(keys)[: self.max_objects]

    def _read_object(self, key: str) -> list[dict[str, Any]]:
        body = self._request(f"/{key}", {})
        try:
            payload = json.loads(gzip.decompress(body).decode("utf-8", "replace"))
        except (OSError, EOFError, zlib.error) as exc:
            raise RuntimeError(f"CloudTrail object {key} is not valid gzip: {type(exc).__name__}") from None
        except ValueError as exc:
            raise RuntimeError(f"CloudTrail object {key} is not valid JSON: {exc}") from None
        records = payload.get("Records") if isinstance(payload, dict) else None
        return [record for record in records if isinstance(record, dict)] if isinstance(records, list) else []

    # -- BaseConnector -----------------------------------------------------
    def parse(self, raw: str) -> dict[str, Any]:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("cloudtrail record must be a JSON object")
        records = value.get("Records")
        if isinstance(records, list):
            if not records:
                raise ValueError("cloudtrail export has no records")
            return self.mapper(records[0])
        return self.mapper(value)

    def poll(self) -> list[dict[str, Any]]:
        if not self.bucket:
            self.last_error = "no CloudTrail S3 bucket configured"
            return self._record([])
        events: list[dict[str, Any]] = []
        try:
            self._load_state()
            known = set(self._seen)
            for key in self._list_objects():
                if key in known:
                    continue
                events.extend(self.mapper(record) for record in self._read_object(key))
                known.add(key)
                self._seen.append(key)
                # Advance only after the object is fully read: a failure mid-way
                # must re-read it rather than skip it.
                if self._last_key is None or key > self._last_key:
                    self._last_key = key
            del self._seen[:-CLOUDTRAIL_SEEN_KEYS]
            self.last_error = None
        except ConnectorAuthError as exc:
            self.last_error = str(exc)
        except (InsecureURLError, RuntimeError, urllib.error.URLError, OSError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
        self._save_state()
        return self._record(events)


def _parse_list_objects(xml: str) -> tuple[list[str], str]:
    """Pull keys and the continuation token out of a ListObjectsV2 response.

    S3 answers in XML and there is no stdlib-free alternative, so this uses a
    narrow regex rather than an XML parser: the response shape is fixed, and
    `xml.etree` on attacker-influenced input brings its own considerations.
    Keys are XML-unescaped because S3 escapes & < > in them.
    """
    keys = [_xml_unescape(match) for match in re.findall(r"<Key>(.*?)</Key>", xml, re.S)]
    token_match = re.search(r"<NextContinuationToken>(.*?)</NextContinuationToken>", xml, re.S)
    truncated = re.search(r"<IsTruncated>(.*?)</IsTruncated>", xml, re.S)
    is_truncated = bool(truncated and truncated.group(1).strip().lower() == "true")
    token = _xml_unescape(token_match.group(1)) if token_match and is_truncated else ""
    return keys, token


def _xml_unescape(value: str) -> str:
    for entity, char in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'),
                         ("&#39;", "'"), ("&apos;", "'"), ("&amp;", "&")):
        value = value.replace(entity, char)
    return value


def _urllib_get_bytes(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    """Stdlib GET returning raw bytes; CloudTrail objects are gzip, not text."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read()
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
registry.register(GitHubApiConnector.name, GitHubApiConnector)
registry.register(EntraApiConnector.name, EntraApiConnector)
registry.register(CloudTrailApiConnector.name, CloudTrailApiConnector)

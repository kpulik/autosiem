from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, cast
from uuid import uuid4

from .schemas import EventCategory, NormalizedEvent, Severity

_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?P<ts>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)?\s*(?P<host>[\w.:-]+)?\s*(?P<msg>.*)$"
)


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def parse_raw_line(line: str) -> dict[str, Any]:
    stripped = line.strip()
    if not stripped:
        raise ValueError("empty event line")
    try:
        value = json.loads(stripped)
        if not isinstance(value, dict):
            return {"message": value}
        return value
    except json.JSONDecodeError:
        match = _SYSLOG_RE.match(stripped)
        if not match:
            return {"message": stripped}
        return {
            "timestamp": match.group("ts"),
            "host": match.group("host"),
            "message": match.group("msg"),
            "format": "syslog-ish",
        }


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    lower_keys = {str(k).lower(): v for k, v in raw.items()}
    message = str(lower_keys.get("message") or lower_keys.get("msg") or "")

    category = _infer_category(lower_keys, message)
    action = _first_str(
        lower_keys,
        "action",
        "event.action",
        "operation",
        "eventname",
        "event_name",
        "activitydisplayname",
        default=_infer_action(category, message),
    )
    outcome = _first_str(lower_keys, "outcome", "event.outcome", "result", "status", default="unknown")

    return NormalizedEvent(
        timestamp=parse_timestamp(
            lower_keys.get("timestamp")
            or lower_keys.get("@timestamp")
            or lower_keys.get("time")
            or lower_keys.get("eventtime")
        ),
        category=cast(EventCategory, category),
        action=action or "",
        outcome=str(outcome).lower(),
        event_id=_first_str(lower_keys, "event_id", "id", "uuid", default=None) or str(uuid4()),
        source=_first_str(lower_keys, "source", "vendor", "product", "event.provider", default="unknown") or "unknown",
        severity=Severity.from_value(lower_keys.get("severity") or lower_keys.get("level") or lower_keys.get("risk")),
        user=_first_str(lower_keys, "user", "username", "user.name", "actor", "principal", "account", default=None),
        host=_first_str(lower_keys, "host", "hostname", "computer", "device.name", "agent.hostname", default=None),
        src_ip=_first_str(lower_keys, "src_ip", "source.ip", "sourceipaddress", "client_ip", "ipaddress", "remoteaddress", default=None),
        dst_ip=_first_str(lower_keys, "dst_ip", "destination.ip", "dest_ip", "server_ip", default=None),
        process_name=_first_str(lower_keys, "process_name", "process.name", "image", "process", default=None),
        command_line=_first_str(lower_keys, "command_line", "process.command_line", "cmdline", "commandline", default=None),
        cloud_account=_first_str(lower_keys, "cloud_account", "accountid", "awsaccountid", "tenantid", "subscriptionid", default=None),
        resource=_first_str(lower_keys, "resource", "resourceid", "object", "target", default=None),
        labels={"format": str(lower_keys.get("format", "json"))},
        raw=raw,
    )


def _first_str(values: dict[str, Any], *keys: str, default: str | None) -> str | None:
    for key in keys:
        value = values.get(key)
        if value is not None and str(value).strip() != "":
            return str(value)
    return default


def _infer_category(values: dict[str, Any], message: str) -> str:
    explicit = str(values.get("category") or values.get("event.category") or "").lower()
    if explicit in {"authentication", "process", "network", "dns", "cloud", "file", "endpoint", "application", "email"}:
        return explicit
    haystack = " ".join(str(v).lower() for v in list(values.values())[:20]) + " " + message.lower()
    if any(term in haystack for term in ["login", "logon", "signin", "authentication", "mfa", "password"]):
        return "authentication"
    if any(term in haystack for term in ["powershell", "cmd.exe", "bash", "process", "commandline", "exec"]):
        return "process"
    if any(term in haystack for term in ["dns", "query_name", "domain"]):
        return "dns"
    if any(term in haystack for term in ["phish", "spam", "mailbox", "recipient"]):
        return "email"
    if any(term in haystack for term in ["cloudtrail", "assumerole", "iam", "azure", "aws", "gcp"]):
        return "cloud"
    if any(term in haystack for term in ["connection", "firewall", "src_ip", "dst_ip", "port"]):
        return "network"
    return "unknown"


def _infer_action(category: str, message: str) -> str:
    text = message.lower()
    if category == "authentication":
        if "fail" in text:
            return "login_failed"
        if "success" in text or "accept" in text:
            return "login_success"
        return "login"
    if category == "process":
        return "process_start"
    if category == "dns":
        return "dns_query"
    if category == "network":
        return "network_connection"
    return "observed"

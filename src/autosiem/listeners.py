"""Syslog (RFC 5424 / RFC 3164) and CEF ingest listeners.

Pure parsing functions turn wire lines into raw event dicts the normalizer
understands; ``SyslogServer`` wraps them in a zero-dependency UDP socket
listener that any forwarder (rsyslog, syslog-ng, Filebeat, Vector, ...) can
send to. CEF-over-syslog (a CEF payload inside a syslog message) is merged
automatically so detection rules see the CEF fields.

Supported subset: RFC 5424 with standard 8 fields, RFC 3164 (year-less
timestamp, tag included in the message), and CEF 0..9 headers with
``key=value`` extensions. This is deliberately the common denominator of
real-world syslog/CEF feeds — no full protocol state machine.
"""
from __future__ import annotations

import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

_CEF_RE = re.compile(
    r"^CEF:(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<product_version>[^|]*)\|"
    r"(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>\d*)\|(?P<extension>.*)$",
    re.DOTALL,
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s*"
    r"(?P<structured>\[[^\]]*(?:\][^\[]*\[[^\]]*)*\]|-)\s*"
    r"(?P<msg>.*)$",
)

# RFC 3164: <PRI>MMM dd HH:MM:SS [host] msg
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>\s*(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?:(?P<host>\S+)\s+)?(?P<msg>.*)$",
)

# CEF extension: key=value pairs; a value runs until the next " key=" token.
_CEF_EXT_RE = re.compile(r"([a-zA-Z0-9_.-]+)=([^=]*?)(?=\s+[a-zA-Z0-9_.-]+=|\s*$)")

_MONTHS = {
    month: index
    for index, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1
    )
}

# syslog severity (0=emerg .. 7=debug) -> product severity values.
_SYSLOG_SEVERITY: dict[int, int] = {
    0: 100, 1: 100, 2: 100,  # emerg/alert/crit -> critical
    3: 75,  # err -> high
    4: 50,  # warning -> medium
    5: 25, 6: 25,  # notice/info -> low
    7: 0,  # debug -> informational
}

_EPOCH_RE = re.compile(r"^\d{10}(\.\d+)?$")

# Common syslog message shapes worth extracting into structured fields.
_FAILED_PASSWORD_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)", re.IGNORECASE)
_ACCEPTED_PASSWORD_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)", re.IGNORECASE)
_SESSION_OPEN_RE = re.compile(r"session opened for user (?P<user>\S+)", re.IGNORECASE)


def parse_cef(line: str) -> dict[str, Any] | None:
    """Parse a CEF line into a raw event dict, or return None if not CEF."""
    match = _CEF_RE.match(line.strip())
    if not match:
        return None
    groups = match.groupdict()
    raw: dict[str, Any] = {
        "format": "cef",
        "vendor": groups["vendor"],
        "product": groups["product"],
        "product_version": groups["product_version"],
        "signature_id": groups["signature_id"],
        "message": groups["name"],
        "severity": min(int(groups["severity"] or 0), 10) * 10,
        "raw_message": line,
    }
    extensions = _parse_cef_extensions(groups["extension"])
    for key, value in extensions.items():
        if key == "src":
            raw["src_ip"] = value
        elif key == "dst":
            raw["dst_ip"] = value
        elif key == "rt" and _EPOCH_RE.fullmatch(value):
            raw["timestamp"] = datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        else:
            raw[key] = value
    if "outcome" not in raw:
        outcome = _infer_cef_outcome(raw["message"], raw.get("msg", ""))
        if outcome:
            raw["outcome"] = outcome
    # Actor wins over target for "user"; destination host is the subject of security events.
    if "suser" in raw:
        raw["user"] = raw["suser"]
    elif "duser" in raw:
        raw["user"] = raw["duser"]
    if "dhost" in raw:
        raw["host"] = raw["dhost"]
    elif "shost" in raw:
        raw["host"] = raw["shost"]
    return raw


def parse_syslog(line: str) -> dict[str, Any] | None:
    """Parse an RFC 5424 or RFC 3164 syslog line into a raw event dict."""
    stripped = line.strip()
    match = _RFC5424_RE.match(stripped)
    if match:
        groups = match.groupdict()
        pri = int(groups["pri"])
        raw: dict[str, Any] = {
            "format": "syslog",
            "host": groups["host"] if groups["host"] != "-" else None,
            "app": groups["app"] if groups["app"] != "-" else None,
            "message": groups["msg"],
            "severity": _SYSLOG_SEVERITY[pri % 8],
            "facility": pri // 8,
        }
        if groups["structured"] != "-":
            raw["structured_data"] = groups["structured"]
        if groups["timestamp"] != "-":
            raw["timestamp"] = groups["timestamp"]
        raw.update(_infer_syslog_fields(raw["message"]))
        return raw
    match = _RFC3164_RE.match(stripped)
    if match:
        groups = match.groupdict()
        pri = int(groups["pri"])
        raw = {
            "format": "syslog",
            "host": groups["host"] or None,
            "message": groups["msg"],
            "severity": _SYSLOG_SEVERITY[pri % 8],
            "facility": pri // 8,
        }
        month = _MONTHS.get(groups["month"][:3].title())
        if month:
            raw["timestamp"] = _parse_3164_timestamp(
                datetime.now(timezone.utc).year, month, int(groups["day"]), groups["time"]
            ).isoformat()
        raw.update(_infer_syslog_fields(raw["message"]))
        return raw
    return None


def line_to_raw(line: str) -> dict[str, Any]:
    """Dispatch any ingest line to a raw event dict.

    CEF lines parse as CEF; syslog lines parse as syslog; a CEF payload
    embedded in syslog is merged (CEF fields win); anything else is treated as
    a free-text message for the normalizer.
    """
    stripped = line.strip()
    if not stripped:
        raise ValueError("empty event line")
    cef = parse_cef(stripped)
    if cef:
        return cef
    syslog = parse_syslog(stripped)
    if syslog is None:
        return {"message": stripped}
    body = parse_cef(syslog.get("message", ""))
    if body:
        body.pop("raw_message", None)
        merged = {**syslog, **body}
        merged["format"] = "syslog+cef"
        return merged
    return syslog


class SyslogServer:
    """Zero-dependency UDP listener: datagrams -> raw event dicts via a handler.

    Includes security hardening (SEC-004):
    - IP allowlist check (`allowed_hosts`)
    - Bounded worker pool to prevent socket thread starvation
    """

    def __init__(
        self,
        handler: Callable[[dict[str, Any]], None],
        host: str = "127.0.0.1",
        port: int = 0,
        buffer_size: int = 65536,
        allowed_hosts: set[str] | list[str] | None = None,
        max_workers: int = 4,
    ) -> None:
        self.handler = handler
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.allowed_hosts = set(allowed_hosts) if allowed_hosts else None
        self.max_workers = max_workers
        self._executor: ThreadPoolExecutor | None = None
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        self._socket = sock
        self.port = sock.getsockname()[1]
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="syslog-worker")
        self._running.set()
        self._thread = threading.Thread(target=self._serve, name="autosiem-listener", daemon=True)
        self._thread.start()

    def _process_line(self, line: str, addr: tuple[str, int]) -> None:
        try:
            raw = line_to_raw(line)
            # Annotate with source IP if missing
            if isinstance(raw, dict) and "src_ip" not in raw and addr:
                raw["src_ip"] = addr[0]
            self.handler(raw)
        except Exception:
            pass

    def _serve(self) -> None:
        assert self._socket is not None
        while self._running.is_set():
            try:
                data, address = self._socket.recvfrom(self.buffer_size)
            except OSError:
                break

            # SEC-004: IP Allowlist filter
            client_ip = address[0]
            if self.allowed_hosts and client_ip not in self.allowed_hosts:
                continue

            for line in data.decode("utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                if self._executor:
                    self._executor.submit(self._process_line, line, address)
                else:
                    self._process_line(line, address)

    def stop(self) -> None:
        self._running.clear()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        if self._executor is not None:
            self._executor.shutdown(wait=False)
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port


_OUTCOME_FAILURE_TERMS = ("fail", "denied", "deny", "error", "reject", "blocked", "block", "invalid")
_OUTCOME_SUCCESS_TERMS = ("success", "accepted", "allowed", "permitted", "granted", "passed")


def _infer_cef_outcome(name: str, msg: str) -> str | None:
    """Infer login/event outcome from the CEF Name field + msg extension."""
    text = f"{name} {msg}".lower()
    if any(term in text for term in _OUTCOME_FAILURE_TERMS):
        return "failure"
    if any(term in text for term in _OUTCOME_SUCCESS_TERMS):
        return "success"
    return None


def _infer_syslog_fields(message: str) -> dict[str, str]:
    """Pull user / src_ip / outcome out of common daemon message shapes.

    Covers the sshd-style ``Failed password for ... from <ip>``,
    ``Accepted password for ... from <ip>``, and
    ``session opened for user ...`` lines that make up the bulk of real
    syslog authentication feeds.
    """
    match = _FAILED_PASSWORD_RE.search(message)
    if match:
        return {
            "user": match.group("user"),
            "src_ip": match.group("ip"),
            "outcome": "failure",
        }
    match = _ACCEPTED_PASSWORD_RE.search(message)
    if match:
        return {
            "user": match.group("user"),
            "src_ip": match.group("ip"),
            "outcome": "success",
        }
    match = _SESSION_OPEN_RE.search(message)
    if match:
        return {"user": match.group("user"), "outcome": "success"}
    return {}


def _parse_cef_extensions(extension: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for match in _CEF_EXT_RE.finditer(extension):
        pairs[match.group(1).lower()] = _unescape_cef(match.group(2).strip())
    return pairs


def _unescape_cef(value: str) -> str:
    return (
        value.replace("\\=", "=")
        .replace("\\|", "|")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\\\", "\\")
    )


def _parse_3164_timestamp(year: int, month: int, day: int, clock: str) -> datetime:
    hour, minute, second = (int(part) for part in clock.split(":"))
    parsed = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    # Year-less logs: roll back one year if the timestamp is in the future.
    if parsed > datetime.now(timezone.utc) + timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed

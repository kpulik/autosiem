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

import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

_LOG = logging.getLogger(__name__)


def _printable(text: str, limit: int = 300) -> str:
    """Escape every control character, so text that may carry event data (an
    exception message can quote a field) cannot forge log lines with CR, LF or
    terminal escape sequences."""
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text[:limit])

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


#: Longest a batch may wait to fill. Also the bound `--batch-wait` accepts.
MAX_BATCH_WAIT_SECONDS = 3600.0


class BatchingHandler:
    """Collect parsed events and hand them to ``process`` in batches.

    ``AutoSIEMPipeline.process_lines`` builds incidents from the findings of one
    call, so a listener that makes one call per datagram can never correlate:
    1500 failed logins for one user gave 1500 incidents. A batch is flushed when
    it holds ``max_batch`` events or ``max_wait`` seconds after its first event,
    whichever comes first. One thread runs ``process``, so batches are serial,
    which the pipeline needs (its baseline and planner are not thread-safe).

    ``max_batch <= 1`` is the old behaviour: each event is processed before the
    call returns, one at a time, and a failure propagates to the caller.
    Buffered events live in memory until flushed; ``close()`` flushes them.
    Events in a batch are correlated with each other, not with earlier batches.
    """

    def __init__(
        self,
        process: Callable[[list[dict[str, Any]]], None],
        on_failure: Callable[[Exception, int], None],
        max_batch: int = 200,
        max_wait: float = 1.0,
    ) -> None:
        self._process = process
        self._on_failure = on_failure
        self.max_batch = max(1, max_batch)
        # Condition.wait raises OverflowError for a huge timeout and blocks on
        # NaN; either killed the flusher thread and stranded buffered events.
        self.max_wait = 0.0 if not (max_wait > 0) else min(max_wait, MAX_BATCH_WAIT_SECONDS)
        self._buffer: list[dict[str, Any]] = []
        self._first_at = 0.0
        self._closed = False
        self._cond = threading.Condition()
        self._sync_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        if self.max_batch > 1:
            self._thread = threading.Thread(target=self._run, name="autosiem-batcher", daemon=True)
            self._thread.start()

    def __call__(self, raw: dict[str, Any]) -> None:
        if self._thread is None:
            with self._sync_lock:
                self._process([raw])
            return
        with self._cond:
            first = not self._buffer
            if first:
                self._first_at = time.monotonic()
            self._buffer.append(raw)
            # Wake the flusher on the first event (it sleeps while idle, and
            # needs to start its max_wait clock) and when the batch is full.
            if first or len(self._buffer) >= self.max_batch:
                self._cond.notify()

    def close(self) -> None:
        """Flush everything buffered and stop the thread."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join()

    def _run(self) -> None:
        while True:
            with self._cond:
                while not self._buffer and not self._closed:
                    self._cond.wait()
                if not self._buffer:
                    return
                while len(self._buffer) < self.max_batch and not self._closed:
                    remaining = self._first_at + self.max_wait - time.monotonic()
                    if remaining <= 0:
                        break
                    self._cond.wait(remaining)
                batch = self._buffer[: self.max_batch]
                del self._buffer[: self.max_batch]
                if self._buffer:
                    self._first_at = time.monotonic()
            try:
                self._process(batch)
            except Exception as exc:
                try:
                    self._on_failure(exc, len(batch))
                except Exception:
                    # A broken callback must not kill the only thread that
                    # drains the buffer: every later batch would be stranded.
                    _LOG.exception("batch failure callback raised; %d line(s) not counted", len(batch))


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
        warn_interval: float = 10.0,
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
        #: Lines that could not be parsed or processed, in total and per stage.
        #: Warnings are rate-limited to one per ``warn_interval`` seconds for
        #: each (stage, error type), carrying a count of the lines they stand
        #: for: any sender can make every line fail, and one stderr line per
        #: datagram let a flood fill an undrained pipe and stall workers. The
        #: limit is per kind so a flood of unparseable lines cannot hide the
        #: first storage failure.
        self.failures = 0
        self.failures_by_stage: dict[str, int] = {"parse": 0, "process": 0}
        self.warn_interval = warn_interval
        self._failures_lock = threading.Lock()
        self._last_warning: dict[tuple[str, str], float] = {}
        self._suppressed: dict[tuple[str, str], int] = {}

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
        # Both stages used to sit under a bare `except Exception: pass`: with
        # AUTOSIEM_QUEUE_PATH set every event failed and the listener still
        # looked healthy. Whether a failed event was stored depends on where the
        # handler failed, so the warning says "could not process", not "dropped".
        try:
            raw = line_to_raw(line)
        except Exception as exc:
            self.record_failure("parse", addr, exc)
            return
        # Annotate with source IP if missing
        if isinstance(raw, dict) and "src_ip" not in raw and addr:
            raw["src_ip"] = addr[0]
        try:
            self.handler(raw)
        except Exception as exc:
            self.record_failure("process", addr, exc)

    def record_failure(self, stage: str, source: tuple[str, int] | str, exc: Exception, count: int = 1) -> None:
        """Count ``count`` failed lines and warn, rate-limited per (stage, error type).

        ``source`` is the sender's ``(ip, port)``, or a label such as ``"batch"``
        for lines whose senders are no longer known.
        """
        addr = source if isinstance(source, tuple) else (source, 0)
        key = (stage, type(exc).__name__)
        with self._failures_lock:
            self.failures += count
            self.failures_by_stage[stage] = self.failures_by_stage.get(stage, 0) + count
            total = self.failures
            now = time.monotonic()
            last = self._last_warning.get(key)
            if last is not None and now - last < self.warn_interval:
                self._suppressed[key] = self._suppressed.get(key, 0) + count
                return
            suppressed = self._suppressed.pop(key, 0)
            self._last_warning[key] = now
        # Logged outside the lock. The line itself is never logged, and the
        # exception text is escaped because it can quote untrusted event data.
        _LOG.warning(
            "listener could not %s a line from %s: %s: %s (%d failures so far%s)",
            stage,
            addr[0] if addr else "?",
            type(exc).__name__,
            _printable(str(exc)),
            total,
            f"; {suppressed} more like this not shown" if suppressed else "",
        )

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
                    try:
                        self._executor.submit(self._process_line, line, address)
                        continue
                    except RuntimeError:
                        # The pool was shut down mid-datagram. Handle the line
                        # here rather than lose it uncounted.
                        pass
                self._process_line(line, address)

    def stop(self) -> None:
        self._running.clear()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        # Let the receiver finish handing off the datagram it is on before the
        # pool closes; closing first made the rest of its lines vanish.
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)
        if self._executor is not None:
            # Wait for lines already handed to workers. Python joins these
            # threads at exit anyway, so this changes no timing; it makes
            # `failures` final when stop() returns, so a caller's summary is not
            # an undercount followed by late warnings. A worker that calls stop()
            # cannot wait on itself.
            in_worker = threading.current_thread().name.startswith("syslog-worker")
            self._executor.shutdown(wait=not in_worker)

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

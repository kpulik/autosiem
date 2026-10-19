from __future__ import annotations

import socket
import threading

from autosiem.listeners import SyslogServer, line_to_raw, parse_cef, parse_syslog
from autosiem.normalization import normalize


def test_parse_syslog_rfc5424() -> None:
    line = '<34>1 2026-08-05T09:30:00Z vpn-1 sshd 1234 ID47 [meta sequenceId="1"] Failed password for alice from 198.51.100.25'
    raw = parse_syslog(line)
    assert raw is not None
    assert raw["format"] == "syslog"
    assert raw["host"] == "vpn-1"
    assert raw["app"] == "sshd"
    assert raw["severity"] == 100  # pri 34 -> facility 4, severity 2 (crit)
    assert raw["facility"] == 4
    assert raw["timestamp"] == "2026-08-05T09:30:00Z"
    assert raw["message"].startswith("Failed password for alice")
    event = normalize(raw)
    assert event.host == "vpn-1"
    assert event.source == "unknown"


def test_parse_syslog_rfc3164() -> None:
    line = "<13>Aug  5 09:30:00 vpn-1 sshd[1234]: Failed password for alice from 198.51.100.25"
    raw = parse_syslog(line)
    assert raw is not None
    assert raw["format"] == "syslog"
    assert raw["host"] == "vpn-1"
    assert raw["severity"] == 25  # pri 13 -> facility 1, severity 5 (notice)
    assert raw["timestamp"].startswith("2026-08-05T09:30:00")
    assert "Failed password" in raw["message"]


def test_parse_cef_maps_extensions_and_severity() -> None:
    line = "CEF:0|Palo Alto|PAN-OS|10.0|USER_LOGIN|User Login|5|src=198.51.100.25 suser=alice dhost=workstation-7 msg=Successful login from VPN rt=1754416800"
    raw = parse_cef(line)
    assert raw is not None
    assert raw["format"] == "cef"
    assert raw["vendor"] == "Palo Alto"
    assert raw["src_ip"] == "198.51.100.25"
    assert raw["user"] == "alice"
    assert raw["host"] == "workstation-7"
    assert raw["message"] == "User Login"
    assert raw["severity"] == 50  # CEF 5 -> medium
    assert "Successful login" in raw["msg"]
    event = normalize(raw)
    assert event.user == "alice"
    assert event.host == "workstation-7"
    assert event.src_ip == "198.51.100.25"
    assert event.category == "authentication"
    assert event.severity.value == 50


def test_parse_cef_actor_wins_over_target_user() -> None:
    line = "CEF:0|V|P|1|E|Event|2|suser=admin duser=alice dhost=dc-1 shost=vpn-1"
    raw = parse_cef(line)
    assert raw is not None
    assert raw["user"] == "admin"  # suser (actor) wins
    assert raw["host"] == "dc-1"  # dhost wins over shost
    assert "duser" in raw and "shost" in raw  # original keys kept for context


def test_line_to_raw_dispatch_cef() -> None:
    line = 'CEF:0|Check Point|Firewall|R80|CONNECT|Connection Established|4|src=203.0.113.5'
    raw = line_to_raw(line)
    assert raw["format"] == "cef"
    assert raw["src_ip"] == "203.0.113.5"


def test_line_to_raw_merges_cef_over_syslog() -> None:
    line = "<132>1 2026-08-05T09:30:00Z fw-1 CEF 42 - [meta] CEF:0|Check Point|Firewall|R80|CONNECT|Connection Established|4|src=203.0.113.5 suser=alice dhost=web-01"
    raw = line_to_raw(line)
    assert raw is not None
    assert raw["format"] == "syslog+cef"
    assert raw["host"] == "web-01"  # CEF dhost wins over syslog host
    assert raw["user"] == "alice"
    assert raw["src_ip"] == "203.0.113.5"


def test_line_to_raw_plain_text_fallback() -> None:
    raw = line_to_raw("just some text with no structure")
    assert raw == {"message": "just some text with no structure"}


def test_parse_syslog_extracts_sshd_fields() -> None:
    line = "<34>1 2026-08-05T09:30:00Z vpn-1 sshd 1234 ID47 - Failed password for alice from 198.51.100.25"
    raw = parse_syslog(line)
    assert raw is not None
    assert raw["user"] == "alice"
    assert raw["src_ip"] == "198.51.100.25"
    assert raw["outcome"] == "failure"
    event = normalize(raw)
    assert event.user == "alice"
    assert event.category == "authentication"
    assert event.outcome == "failure"


def test_line_to_raw_sshd_failed_login_fires_rule() -> None:
    import json
    from pathlib import Path

    from autosiem.pipeline import AutoSIEMPipeline
    from autosiem.rules import load_rules

    # Mirrors the SyslogServer -> line_to_raw -> pipeline flow in cli._run_listener.
    line = "<34>1 2026-08-05T09:30:00Z vpn-1 sshd 1234 ID47 - Failed password for alice from 198.51.100.25"
    raw = line_to_raw(line)
    assert raw["outcome"] == "failure"
    root = Path(__file__).resolve().parents[1]
    pipeline = AutoSIEMPipeline(load_rules(root / "rules"))
    result = pipeline.process_lines([json.dumps(raw)])
    assert any(finding.rule_id == "AUTO-AUTH-001" for finding in result.findings)


def test_parse_syslog_extracts_accepted_and_session_fields() -> None:
    accepted = parse_syslog("<34>1 2026-08-05T09:30:00Z vpn-1 sshd 1234 ID47 - Accepted password for bob from 203.0.113.9")
    assert accepted is not None
    assert accepted["user"] == "bob"
    assert accepted["src_ip"] == "203.0.113.9"
    assert accepted["outcome"] == "success"
    opened = parse_syslog("<34>1 2026-08-05T09:30:00Z vpn-1 sshd 1234 ID47 - pam_unix(sshd:session): session opened for user carol")
    assert opened is not None
    assert opened["user"] == "carol"
    assert opened["outcome"] == "success"
    assert "src_ip" not in opened


def test_parse_syslog_rfc5424_dash_placeholders() -> None:
    line = "<30>1 - - - - - - a bare message"
    raw = parse_syslog(line)
    assert raw is not None
    assert raw["host"] is None
    assert raw["app"] is None
    assert raw["message"] == "a bare message"
    assert "timestamp" not in raw


def test_parse_cef_infers_outcome_from_name_and_msg() -> None:
    success = parse_cef("CEF:0|Palo Alto|PAN-OS|10.0|USER_LOGIN|User Login|5|src=198.51.100.25 msg=Successful login from VPN")
    assert success is not None
    assert success["outcome"] == "success"
    denied = parse_cef("CEF:0|Check Point|Firewall|R80|LOGIN|Login Denied|4|src=203.0.113.5 duser=bob")
    assert denied is not None
    assert denied["outcome"] == "failure"


def test_parse_cef_keeps_vendor_outcome_extension() -> None:
    raw = parse_cef("CEF:0|V|P|1|E|Login Denied|5|duser=alice outcome=success")
    assert raw is not None
    assert raw["outcome"] == "success"  # vendor value wins over Name-field inference


def test_parse_syslog_server_udp_end_to_end() -> None:
    received: list[dict] = []
    done = threading.Event()

    def handler(raw: dict) -> None:
        received.append(raw)
        done.set()

    server = SyslogServer(handler, host="127.0.0.1", port=0)
    server.start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        payload = b"<13>Aug  5 09:30:00 vpn-1 sshd[1234]: Failed password for alice from 198.51.100.25"
        sock.sendto(payload, server.address)
        assert done.wait(timeout=5)
        assert received
        assert received[0]["host"] == "vpn-1"
        assert "Failed password" in received[0]["message"]
    finally:
        sock.close()
        server.stop()


def test_a_failing_handler_is_logged_and_counted_not_swallowed(caplog) -> None:
    """A handler error used to vanish (`except Exception: pass`), so a listener
    that stored nothing looked healthy. One line per failure, and the listener
    keeps serving."""
    import logging

    seen: list[dict] = []
    done = threading.Event()

    def handler(raw: dict) -> None:
        if "boom" in raw.get("message", ""):
            raise RuntimeError("database is locked")
        seen.append(raw)
        done.set()

    server = SyslogServer(handler, host="127.0.0.1", port=0)
    server.start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with caplog.at_level(logging.WARNING, logger="autosiem.listeners"):
            sock.sendto(b"boom one", server.address)
            sock.sendto(b"<13>Aug  5 09:30:00 vpn-1 sshd[1]: ok", server.address)
            assert done.wait(timeout=5)
            # The worker counts the failure and then logs it, so wait for the
            # log record itself, not the counter (that order flaked ~3%).
            pause = threading.Event()
            messages: list[str] = []
            for _ in range(100):
                messages = [record.getMessage() for record in caplog.records if record.name == "autosiem.listeners"]
                if messages:
                    break
                pause.wait(0.05)
        assert server.failures == 1
        assert seen and seen[0]["host"] == "vpn-1"
        assert any("RuntimeError: database is locked" in message for message in messages), messages
        assert all("\n" not in message for message in messages)
    finally:
        sock.close()
        server.stop()


def _failing_server(monkeypatch, *, warn_interval: float = 10.0) -> tuple[SyslogServer, list[float]]:
    import autosiem.listeners as listeners

    clock = [100.0]
    monkeypatch.setattr(listeners.time, "monotonic", lambda: clock[0])

    def handler(raw: dict) -> None:
        raise RuntimeError("database is locked")

    return SyslogServer(handler, warn_interval=warn_interval), clock


def test_a_flood_of_failures_is_rate_limited_and_counted(monkeypatch, caplog) -> None:
    """Any sender can make every line fail. One stderr line per datagram let a
    flood fill an undrained pipe and stall every worker."""
    import logging

    server, clock = _failing_server(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="autosiem.listeners"):
        for _ in range(1000):
            server._process_line("x", ("203.0.113.9", 514))
        clock[0] += 11
        server._process_line("x", ("203.0.113.9", 514))
    messages = [r.getMessage() for r in caplog.records if r.name == "autosiem.listeners"]
    assert server.failures == 1001
    assert len(messages) == 2
    assert "(1 failures so far)" in messages[0]
    assert "(1001 failures so far; 999 more not shown)" in messages[1]


def test_a_parse_failure_is_reported_as_parse_and_skips_the_handler(monkeypatch, caplog) -> None:
    import logging

    import autosiem.listeners as listeners

    def bad_parse(line: str) -> dict:
        raise ValueError("day is out of range for month")

    called: list[dict] = []
    monkeypatch.setattr(listeners, "line_to_raw", bad_parse)
    server = SyslogServer(called.append)
    with caplog.at_level(logging.WARNING, logger="autosiem.listeners"):
        server._process_line("<13>Oct 99 25:61:61 host x", ("203.0.113.9", 514))
    messages = [r.getMessage() for r in caplog.records if r.name == "autosiem.listeners"]
    assert called == []
    assert server.failures == 1
    assert messages and messages[0].startswith("listener could not parse a line from 203.0.113.9: ValueError")
    assert "25:61:61" not in messages[0], "the untrusted line itself is never logged"


def test_exception_text_cannot_forge_log_lines(monkeypatch, caplog) -> None:
    """A handler's exception can quote event data; CR, LF and escape sequences
    in it would let a sender forge or hide log lines."""
    import logging

    def handler(raw: dict) -> None:
        raise ValueError("bad\r\nlistener could not parse a line from 10.0.0.1\x1b[2K\x1b[1A")

    server = SyslogServer(handler)
    with caplog.at_level(logging.WARNING, logger="autosiem.listeners"):
        server._process_line("x", ("203.0.113.9", 514))
    [message] = [r.getMessage() for r in caplog.records if r.name == "autosiem.listeners"]
    assert not any(ch in message for ch in "\r\n\x1b")
    assert "\\r\\n" in message and "\\x1b[2K" in message


def test_stop_waits_for_queued_lines_so_failures_is_final() -> None:
    """stop() used shutdown(wait=False): the CLI's exit summary read the counter
    while workers were still failing lines, so it undercounted."""
    def slow_failure(raw: dict) -> None:
        threading.Event().wait(0.05)
        raise RuntimeError("database is locked")

    server = SyslogServer(slow_failure, host="127.0.0.1", port=0, warn_interval=3600)
    server.start()
    assert server._executor is not None
    for _ in range(12):
        server._executor.submit(server._process_line, "x", ("203.0.113.9", 514))
    server.stop()
    assert server.failures == 12

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

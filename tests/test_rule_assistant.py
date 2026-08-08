"""Tests for the deterministic rule assistant (rule_assistant.py)."""
from __future__ import annotations

import json
from pathlib import Path

from autosiem.rule_assistant import RuleAssistant


def test_draft_rule_from_description_and_techniques() -> None:
    assistant = RuleAssistant()
    rule = assistant.draft_rule(
        "Failed login attempts by user against the VPN endpoint",
        techniques=["T1110"],
    )
    assert rule["selection"]
    assert rule["mitre_attack"] == ["T1110"]
    assert rule["id"].startswith("AUTO-GEN-")
    assert rule["enabled"] is True
    assert rule["severity"] in {"low", "medium", "high", "critical"}
    # failed login -> authentication category, with an action selector
    assert rule["selection"]["category"] == "authentication"
    assert "action" in rule["selection"]


def test_generate_test_cases_returns_positive_and_negative() -> None:
    assistant = RuleAssistant()
    rule = assistant.draft_rule("process spawned a suspicious powershell command")
    cases = assistant.generate_test_cases(rule)
    matching = [case for case in cases if case["should_match"]]
    non_matching = [case for case in cases if not case["should_match"]]
    assert matching
    assert non_matching


def test_write_rule_file_writes_id(tmp_path: Path) -> None:
    assistant = RuleAssistant()
    rule = assistant.draft_rule("Network flow with large outbound transfer")
    path = assistant.write_rule_file(rule, tmp_path)
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["id"] == rule["id"]
    assert data["id"].startswith("AUTO-GEN-")


def test_draft_from_text_returns_suggested_rule() -> None:
    from autosiem.rule_assistant import SuggestedRule

    assistant = RuleAssistant()
    suggested = assistant.draft_from_text("phishing email delivered to mailbox", techniques=["T1566"])
    assert isinstance(suggested, SuggestedRule)
    assert suggested.rule["mitre_attack"] == ["T1566"]
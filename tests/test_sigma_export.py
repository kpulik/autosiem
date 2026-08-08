"""Tests for Sigma rule export (rule_to_sigma / export_rules in sigma.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from autosiem.rules import load_rules
from autosiem.schemas import DetectionRule, Severity
from autosiem.sigma import export_rules, parse_sigma_yaml, rule_to_sigma, sigma_to_rule


def round_trip(rule: DetectionRule) -> DetectionRule:
    """Export a rule to Sigma YAML and import it back."""
    return sigma_to_rule(parse_sigma_yaml(rule_to_sigma(rule)))


def assert_round_trips(rule: DetectionRule) -> None:
    """Assert the Sigma round-trip preserves everything Sigma can carry."""
    reloaded = round_trip(rule)
    assert reloaded.rule_id == rule.rule_id
    assert reloaded.name == rule.name
    assert reloaded.severity == rule.severity
    assert reloaded.mitre_attack == rule.mitre_attack
    assert reloaded.selection == rule.selection


def make_rule(
    selection: dict[str, Any] | None = None,
    severity: Severity = Severity.MEDIUM,
    mitre_attack: list[str] | None = None,
    name: str = "Test rule",
    rule_id: str = "TEST-001",
) -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        name=name,
        description="A rule for export tests.",
        severity=severity,
        risk_points=severity.value,
        selection=selection or {},
        mitre_attack=mitre_attack or ["T1059"],
        tags=["test-tag"],
        enabled=True,
    )


def test_export_simple_rule() -> None:
    rule = make_rule(selection={"category": "process", "action": "process_start"})
    text = rule_to_sigma(rule)
    assert "title: Test rule" in text
    assert "id: TEST-001" in text
    assert "status: stable" in text
    assert "author: AutoSIEM" in text
    assert "category: process" in text
    assert "action: process_start" in text
    assert "condition: selection" in text
    assert "level: medium" in text
    assert "  - test-tag" in text
    assert "  - attack.t1059" in text
    assert_round_trips(rule)


def test_export_operator_mapping_and_round_trip() -> None:
    rule = make_rule(
        selection={
            "process_name": {"endswith_any": ["\\powershell.exe", "\\pwsh.exe"]},
            "command_line": {"contains_any": ["-enc", "IEX"]},
            "host": {"startswith": "workstation"},
            "raw.bytes_sent": {"regex": "^[5-9][0-9]{6,}$"},
            "raw.url": {"contains_any": ["/etc/passwd", "../"]},
        }
    )
    text = rule_to_sigma(rule)
    assert "process_name|endswith:" in text
    assert "command_line|contains:" in text
    assert "host|startswith: workstation" in text
    assert "raw.bytes_sent|re:" in text
    assert "raw.url|contains:" in text
    assert_round_trips(rule)


def test_export_negation_becomes_filter_group() -> None:
    rule = make_rule(
        selection={
            "process_name": {"endswith_any": ["\\powershell.exe"]},
            "command_line": {"not_equals": "benign"},
            "user": {"not_in": ["SYSTEM", "svc-account"]},
        }
    )
    text = rule_to_sigma(rule)
    assert "filter:" in text
    assert "condition: selection and not filter" in text
    assert_round_trips(rule)


def test_export_keywords_mapping() -> None:
    rule = make_rule(selection={"raw.message": {"contains_any": ["whoami", "net user"]}})
    text = rule_to_sigma(rule)
    assert "keywords:" in text
    assert_round_trips(rule)


def test_export_quotes_numeric_strings() -> None:
    rule = make_rule(selection={"command_line": {"contains_any": ["3389", "5985"]}})
    text = rule_to_sigma(rule)
    assert "- 3389" not in text
    assert '"- 3389"' not in text
    assert_round_trips(rule)


def test_export_quotes_whitespace_and_backslashes() -> None:
    # "iex " would lose its trailing space unquoted; "\powershell.exe" must not
    # go through double-quote unescaping (our subset parser does not unescape).
    rule = make_rule(
        selection={
            "command_line": {"contains_any": ["iex ", "-d "]},
            "process_name": {"endswith_any": ["\\powershell.exe"]},
        }
    )
    text = rule_to_sigma(rule)
    assert '"iex "' in text
    assert "'\\powershell.exe'" in text
    assert_round_trips(rule)


def test_export_rejects_unknown_operator() -> None:
    rule = make_rule(selection={"category": {"bogus": "x"}})
    with pytest.raises(ValueError):
        rule_to_sigma(rule)


def test_export_rejects_multi_operator_dict() -> None:
    rule = make_rule(selection={"category": {"contains": "a", "contains_any": ["b"]}})
    with pytest.raises(ValueError):
        rule_to_sigma(rule)


def test_round_trip_all_bundled_rules() -> None:
    rules_dir = Path(__file__).resolve().parents[1] / "rules"
    rules = load_rules(rules_dir)
    assert len(rules) == 16
    for rule in rules:
        assert_round_trips(rule)


def test_export_rules_writes_yaml_files(tmp_path: Path) -> None:
    rules = [make_rule(rule_id="A-1"), make_rule(rule_id="B-2", name="Second rule")]
    paths = export_rules(rules, tmp_path)
    assert len(paths) == 2
    assert (tmp_path / "A-1.yaml").exists()
    assert (tmp_path / "B-2.yaml").exists()
    # Written files parse back through the Sigma importer.
    for rule, path in zip(rules, paths):
        reloaded = sigma_to_rule(parse_sigma_yaml(path.read_text(encoding="utf-8")))
        assert reloaded.rule_id == rule.rule_id
        assert reloaded.selection == rule.selection

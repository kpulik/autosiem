"""Tests for Sigma rule import (sigma.py) and YAML-subset parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from autosiem.detection import evaluate_rule
from autosiem.normalization import normalize, parse_raw_line
from autosiem.rules import load_rules
from autosiem.schemas import DetectionRule, Severity
from autosiem.sigma import (
    SigmaParseError,
    load_sigma_file,
    parse_sigma_yaml,
    sigma_to_rule,
)

SAMPLE_YAML = """\
title: Encoded PowerShell Execution
id: SIG-EXEC-001
status: stable
description: Detects encoded PowerShell, an obfuscation technique.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
"""


def test_parse_yaml_mapping_and_nested_dict() -> None:
    data = parse_sigma_yaml(SAMPLE_YAML)
    assert data["title"] == "Encoded PowerShell Execution"
    assert data["logsource"]["product"] == "windows"
    assert data["logsource"]["category"] == "process_creation"
    assert data["level"] == "high"
    assert data["detection"]["condition"] == "selection"


def test_parse_yaml_list_values() -> None:
    data = parse_sigma_yaml(SAMPLE_YAML)
    selection = data["detection"]["selection"]
    # A block list under a field-keyed mapping.
    assert isinstance(selection["Image|endswith"], list)
    assert selection["Image|endswith"][0] == "\\powershell.exe"
    assert isinstance(selection["CommandLine|contains"], list)
    assert "-enc" in selection["CommandLine|contains"]


def test_parse_yaml_inline_list_and_comments() -> None:
    text = """\
title: T
tags: [attack.execution, attack.t1059]  # trailing comment
level: medium
# a full-line comment
description: hello # world
"""
    data = parse_sigma_yaml(text)
    assert data["tags"] == ["attack.execution", "attack.t1059"]
    assert data["description"] == "hello"


def test_sigma_to_rule_basic_mapping() -> None:
    rule = sigma_to_rule(parse_sigma_yaml(SAMPLE_YAML))
    assert rule.rule_id == "SIG-EXEC-001"
    assert rule.name == "Encoded PowerShell Execution"
    assert rule.severity == Severity.HIGH
    assert rule.risk_points == Severity.HIGH.value
    assert rule.mitre_attack == ["T1059.001"]
    assert rule.tags == ["attack.execution", "attack.t1059.001"]
    assert rule.enabled is True


def test_field_alias_and_modifier_mapping() -> None:
    data = {
        "title": "Aliases",
        "detection": {"selection": {"CommandLine|contains": "-enc", "ProcessName|contains": "pow"}, "condition": "selection"},
    }
    rule = sigma_to_rule(data)
    assert rule.selection["command_line"] == {"contains": "-enc"}
    assert rule.selection["process_name"] == {"contains": "pow"}


def test_contains_list_becomes_contains_any() -> None:
    rule = sigma_to_rule(parse_sigma_yaml(SAMPLE_YAML))
    sel = rule.selection
    assert sel["command_line"] == {"contains_any": ["-enc", "-encodedcommand"]}
    assert sel["process_name"] == {"endswith_any": ["\\powershell.exe", "\\pwsh.exe"]}


def test_scalar_equals_and_in_list() -> None:
    text = """\
title: T
detection:
  selection:
    EventID: 4688
    Channel: [Security, System]
  condition: selection
"""
    rule = sigma_to_rule(parse_sigma_yaml(text))
    assert rule.selection["eventid"] == 4688
    assert rule.selection["channel"] == {"in": ["Security", "System"]}


def test_condition_not_filter_negates_fields() -> None:
    text = """\
title: T
detection:
  selection:
    ProcessName|contains: powershell
  condition: selection and not filter
  filter:
    CommandLine|contains: AzureAD
"""
    rule = sigma_to_rule(parse_sigma_yaml(text))
    assert rule.selection["command_line"] == {"not_contains": "AzureAD"}


def test_condition_not_filter_preserves_include_on_the_same_field() -> None:
    """A filter must not overwrite the positive predicate it narrows."""
    text = """\
title: Encoded PowerShell
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  filter:
    CommandLine|contains:
      - 'AzureAD'
      - 'ModuleAnalyzer'
  condition: selection and not filter
"""
    rule = sigma_to_rule(parse_sigma_yaml(text))
    assert rule.selection["command_line"] == {
        "contains_any": ["-enc", "-encodedcommand"],
        "not_contains_any": ["AzureAD", "ModuleAnalyzer"],
    }

    def matches(command_line: str) -> bool:
        event = normalize(parse_raw_line(json.dumps({"category": "process", "command_line": command_line})))
        return evaluate_rule(event, rule) is not None

    assert matches("powershell.exe -enc SQBFAFgA") is True
    assert matches("powershell.exe -enc AzureAD") is False
    assert matches("powershell.exe Get-Date") is False


def test_condition_not_filter_maps_every_supported_operator_exactly() -> None:
    cases = [
        ("CommandLine|contains: benign", "command_line", {"not_contains": "benign"}),
        (
            r"Image|endswith: ['\trusted.exe', '\signed.exe']",
            "process_name",
            {"not_endswith_any": ["\\trusted.exe", "\\signed.exe"]},
        ),
        ("User|startswith: svc-", "user", {"not_startswith": "svc-"}),
        ("Host|re: '^lab-[0-9]+$'", "host", {"not_regex": "^lab-[0-9]+$"}),
    ]
    for filter_line, field, expected in cases:
        text = f"""\
title: Exact negation
detection:
  selection:
    Category: process
  filter:
    {filter_line}
  condition: selection and not filter
"""
        rule = sigma_to_rule(parse_sigma_yaml(text))
        assert rule.selection[field] == expected


@pytest.mark.parametrize(
    ("operator", "value", "allowed", "blocked"),
    [
        ("not_contains", "benign", "powershell -enc", "powershell -enc benign"),
        ("not_contains_any", ["benign", "trusted"], "powershell -enc", "trusted command"),
        ("not_startswith", "svc-", "alice", "svc-backup"),
        ("not_startswith_any", ["svc-", "system"], "alice", "SYSTEM-user"),
        ("not_endswith", ".signed.exe", "payload.exe", "payload.signed.exe"),
        ("not_endswith_any", [".signed.exe", ".trusted.exe"], "payload.exe", "tool.trusted.exe"),
        ("not_regex", r"^lab-[0-9]+$", "prod-7", "lab-42"),
    ],
)
def test_negated_detection_operators_enforce_exclusions(
    operator: str, value: object, allowed: str, blocked: str
) -> None:
    rule = DetectionRule(
        rule_id="NEGATION-TEST",
        name="Negation test",
        description="",
        severity=Severity.MEDIUM,
        risk_points=Severity.MEDIUM.value,
        selection={"command_line": {operator: value}},
    )

    def matches(command_line: str) -> bool:
        event = normalize(parse_raw_line(json.dumps({"category": "process", "command_line": command_line})))
        return evaluate_rule(event, rule) is not None

    assert matches(allowed) is True
    assert matches(blocked) is False


def test_multi_field_negated_filter_is_rejected_instead_of_approximated() -> None:
    """NOT(A AND B) cannot be represented by the flat AND selection model."""
    text = """\
title: Unsupported De Morgan filter
detection:
  selection:
    Category: process
  filter:
    User: SYSTEM
    Image|endswith: '\\trusted.exe'
  condition: selection and not filter
"""
    with pytest.raises(SigmaParseError, match="multi-field negated filter"):
        sigma_to_rule(parse_sigma_yaml(text))


def test_startswith_endswith_re_modifiers() -> None:
    text = """\
title: T
detection:
  selection:
    User|startswith: 'admin'
    Image|endswith: '.exe'
    CommandLine|re: 'whoami.*net'
  condition: selection
"""
    rule = sigma_to_rule(parse_sigma_yaml(text))
    assert rule.selection["user"] == {"startswith": "admin"}
    assert rule.selection["process_name"] == {"endswith": ".exe"}
    assert rule.selection["command_line"] == {"regex": "whoami.*net"}


def test_keywords_maps_to_raw_message() -> None:
    text = """\
title: T
detection:
  selection:
    EventID: 4688
  keywords:
    - whoami
    - net user
  condition: selection and keywords
"""
    rule = sigma_to_rule(parse_sigma_yaml(text))
    assert rule.selection["raw.message"] == {"contains_any": ["whoami", "net user"]}


def test_complex_condition_falls_back_to_selection() -> None:
    text = """\
title: T
detection:
  selection_a:
    EventID: 4688
  selection_b:
    EventID: 4689
  condition: 1 of selection*
"""
    rule = sigma_to_rule(parse_sigma_yaml(text))
    # We approximate by using the plain "selection" block (absent -> empty).
    assert rule.selection == {}


def test_unknown_level_defaults_to_informational() -> None:
    rule = sigma_to_rule({"title": "T", "level": "banana"})
    assert rule.severity == Severity.INFORMATIONAL


def test_empty_level_defaults_to_informational() -> None:
    rule = sigma_to_rule({"title": "T"})
    assert rule.severity == Severity.INFORMATIONAL


def test_load_sigma_file_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(SAMPLE_YAML, encoding="utf-8")
    rule = load_sigma_file(path)
    assert rule.rule_id == "SIG-EXEC-001"


def test_load_rules_mixes_json_and_yaml(tmp_path: Path) -> None:
    yaml_rule = tmp_path / "sigma.yaml"
    yaml_rule.write_text(SAMPLE_YAML, encoding="utf-8")
    json_rule = tmp_path / "json.json"
    json_rule.write_text('{"id": "J-1", "name": "J Rule", "severity": "low", "selection": {"a": 1}}', encoding="utf-8")
    rules = load_rules(tmp_path)
    ids = {r.rule_id for r in rules}
    assert ids == {"SIG-EXEC-001", "J-1"}


def test_repo_sample_sigma_rule_loads() -> None:
    rules_dir = Path(__file__).resolve().parents[1] / "rules"
    rules = [r for r in load_rules(rules_dir) if r.rule_id == "SIG-EXEC-001"]
    assert len(rules) == 1
    rule = rules[0]
    assert rule.severity == Severity.HIGH
    assert rule.mitre_attack == ["T1059.001", "T1027"]
    # The sample uses "condition: selection and not filter".
    assert rule.selection

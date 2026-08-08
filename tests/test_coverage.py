"""Tests for the ATT&CK coverage report (coverage.py)."""

from __future__ import annotations

from autosiem.coverage import WATCHLIST, coverage_report, tactic_for
from autosiem.schemas import DetectionRule, Severity


def _rule(rule_id: str, mitre: list[str] | None = None) -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        name=rule_id,
        description="",
        severity=Severity.LOW,
        risk_points=25,
        selection={},
        mitre_attack=mitre or [],
    )


def test_empty_rule_set() -> None:
    report = coverage_report([])
    assert report["total_rules"] == 0
    assert report["unique_techniques"] == 0
    assert report["gap_count"] == len(WATCHLIST)


def test_technique_collection_dedupes() -> None:
    rules = [
        _rule("A", ["T1059.001", "T1027"]),
        _rule("B", ["T1059.001", "T1110"]),
    ]
    report = coverage_report(rules)
    assert report["unique_techniques"] == 3
    assert set(report["techniques_covered"]) == {"T1027", "T1059.001", "T1110"}


def test_tactics_derived_from_techniques() -> None:
    rules = [_rule("A", ["T1059.001", "T1110", "T1486"])]
    report = coverage_report(rules)
    assert "execution" in report["tactics_covered"]
    assert "credential-access" in report["tactics_covered"]
    assert "impact" in report["tactics_covered"]


def test_watchlist_flags_and_gaps() -> None:
    rules = [_rule("A", ["T1059.001", "T1486"])]
    report = coverage_report(rules)
    by_technique = {entry["technique"]: entry for entry in report["watchlist_coverage"]}
    assert by_technique["T1059.001"]["covered"] is True
    assert by_technique["T1566"]["covered"] is False
    gap_techniques = [entry["technique"] for entry in report["gaps"]]
    assert "T1566" in gap_techniques
    assert "T1059.001" not in gap_techniques
    assert report["gap_count"] == len(gap_techniques)


def test_subtechnique_tactic_resolution() -> None:
    assert tactic_for("T1059.001") == "execution"
    assert tactic_for("T1003.001") == "credential-access"
    assert tactic_for("T9999") is None


def test_coverage_counts_mitre_rules() -> None:
    rules = [_rule("A", ["T1059"]), _rule("B")]
    report = coverage_report(rules)
    assert report["total_rules"] == 2
    assert report["rules_with_mitre_attack"] == 1


def test_rule_casing_is_normalized() -> None:
    rules = [_rule("A", ["t1059.001"])]
    report = coverage_report(rules)
    assert "T1059.001" in report["techniques_covered"]
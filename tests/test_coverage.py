"""Tests for the ATT&CK coverage report (coverage.py)."""

from __future__ import annotations

from autosiem.coverage import BASELINE_KIND, BASELINE_NAME, WATCHLIST, coverage_report, tactic_for
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
    assert report["watchlist_gap_count"] == len(WATCHLIST)


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
    gap_techniques = [entry["technique"] for entry in report["watchlist_gaps"]]
    assert "T1566" in gap_techniques
    assert "T1059.001" not in gap_techniques
    assert report["watchlist_gap_count"] == len(gap_techniques)


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

def test_report_names_the_baseline_it_measures_against() -> None:
    """The number travels with what it is a number of."""
    report = coverage_report([])
    baseline = report["baseline"]
    assert baseline["name"] == BASELINE_NAME
    assert baseline["kind"] == BASELINE_KIND
    assert baseline["technique_count"] == len(WATCHLIST)
    assert "not a measure of coverage across" in baseline["note"]


def test_no_unqualified_gap_key_is_exposed() -> None:
    """A bare `gap_count` reads as full ATT&CK coverage; it must not come back.

    Every gap key is watchlist-scoped by name so it cannot be quoted out of
    context into a doc or a slide.
    """
    report = coverage_report([_rule("A", ["T1059.001"])])
    assert "gap_count" not in report
    assert "gaps" not in report
    assert report["watchlist_gap_count"] == len(WATCHLIST) - 1
    assert report["watchlist_covered_count"] == 1


def test_full_watchlist_coverage_is_not_claimed_as_matrix_coverage() -> None:
    """Cover every watchlist technique and the report still says it is a subset."""
    rules = [_rule("ALL", [technique for technique, _ in WATCHLIST])]
    report = coverage_report(rules)
    assert report["watchlist_gap_count"] == 0
    assert report["watchlist_covered_count"] == len(WATCHLIST)
    # Nothing in the report asserts full-matrix coverage.
    assert report["baseline"]["kind"] == "curated_subset"
    assert "coverage_percent" not in report

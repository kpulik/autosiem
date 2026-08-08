"""Tests for entity risk aggregation and incident correlation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from autosiem.risk import (
    CORRELATION_WINDOW_SECONDS,
    UNKNOWN_ENTITY,
    aggregate_entity_risk,
    build_incidents,
    correlate_findings,
)
from autosiem.schemas import Finding, Severity

BASE_TIME = datetime(2026, 8, 4, 10, 0, 0, tzinfo=timezone.utc)


def _finding(
    finding_id: str,
    entities: list[str],
    *,
    offset_seconds: int = 0,
    risk_points: int = 10,
    severity: Severity = Severity.MEDIUM,
    mitre: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id=f"RULE-{finding_id}",
        rule_name=f"rule {finding_id}",
        event_id=f"event-{finding_id}",
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        severity=severity,
        risk_points=risk_points,
        entities=entities,
        mitre_attack=mitre or [],
        evidence={},
    )


def _ids(cluster: list[Finding]) -> set[str]:
    return {finding.finding_id for finding in cluster}


# --- correlation -----------------------------------------------------------


def test_no_findings_produces_no_incidents() -> None:
    assert correlate_findings([]) == []
    assert build_incidents([]) == []


def test_shared_entity_within_window_correlates() -> None:
    findings = [
        _finding("a", ["user:alice"], offset_seconds=0),
        _finding("b", ["user:alice"], offset_seconds=600),
    ]
    clusters = correlate_findings(findings)
    assert len(clusters) == 1
    assert _ids(clusters[0]) == {"a", "b"}


def test_shared_entity_outside_window_splits() -> None:
    """A long quiet gap starts a new episode, not one endless incident."""
    findings = [
        _finding("a", ["user:alice"], offset_seconds=0),
        _finding("b", ["user:alice"], offset_seconds=CORRELATION_WINDOW_SECONDS + 60),
    ]
    clusters = correlate_findings(findings)
    assert len(clusters) == 2
    assert [_ids(c) for c in clusters] == [{"a"}, {"b"}]


def test_disjoint_entities_stay_separate() -> None:
    findings = [
        _finding("a", ["user:alice"]),
        _finding("b", ["user:bob"], offset_seconds=60),
    ]
    assert len(correlate_findings(findings)) == 2


def test_correlation_is_transitive_across_entity_types() -> None:
    """user↔host and host↔ip links must produce ONE incident, not three."""
    findings = [
        _finding("a", ["user:alice", "host:ws-1"], offset_seconds=0),
        _finding("b", ["host:ws-1", "ip:10.0.0.5"], offset_seconds=60),
        _finding("c", ["ip:10.0.0.5", "cloud_account:prod"], offset_seconds=120),
    ]
    clusters = correlate_findings(findings)
    assert len(clusters) == 1
    assert _ids(clusters[0]) == {"a", "b", "c"}


def test_chain_stays_linked_when_each_hop_is_within_window() -> None:
    """Endpoints may exceed the window as long as every hop is inside it."""
    half = CORRELATION_WINDOW_SECONDS // 2 + 1
    findings = [
        _finding("a", ["user:alice"], offset_seconds=0),
        _finding("b", ["user:alice"], offset_seconds=half),
        _finding("c", ["user:alice"], offset_seconds=half * 2),
    ]
    clusters = correlate_findings(findings)
    assert len(clusters) == 1
    assert _ids(clusters[0]) == {"a", "b", "c"}


def test_cluster_findings_are_chronological() -> None:
    findings = [
        _finding("late", ["user:alice"], offset_seconds=300),
        _finding("early", ["user:alice"], offset_seconds=0),
    ]
    cluster = correlate_findings(findings)[0]
    assert [finding.finding_id for finding in cluster] == ["early", "late"]


def test_findings_without_entities_group_under_unknown() -> None:
    findings = [_finding("a", []), _finding("b", [], offset_seconds=60)]
    clusters = correlate_findings(findings)
    assert len(clusters) == 1
    incident = build_incidents(findings)[0]
    assert incident.entities == [UNKNOWN_ENTITY]


def test_custom_window_is_respected() -> None:
    findings = [
        _finding("a", ["user:alice"], offset_seconds=0),
        _finding("b", ["user:alice"], offset_seconds=120),
    ]
    assert len(correlate_findings(findings, window_seconds=60)) == 2
    assert len(correlate_findings(findings, window_seconds=600)) == 1


# --- incident construction -------------------------------------------------


def test_incident_spans_every_entity_in_the_cluster() -> None:
    findings = [
        _finding("a", ["user:alice", "host:ws-1"]),
        _finding("b", ["host:ws-1", "ip:10.0.0.5"], offset_seconds=60),
    ]
    incident = build_incidents(findings)[0]
    assert incident.entities == ["host:ws-1", "ip:10.0.0.5", "user:alice"]


def test_primary_entity_is_the_highest_risk_one() -> None:
    findings = [
        _finding("a", ["user:alice"], risk_points=10),
        _finding("b", ["user:alice", "host:ws-1"], offset_seconds=60, risk_points=200),
    ]
    incident = build_incidents(findings)[0]
    # alice carries 210 points, ws-1 only 200.
    assert "user:alice" in incident.title
    assert "Highest-risk entity: user:alice." in incident.summary


def test_kill_chain_is_time_ordered_and_deduped() -> None:
    findings = [
        _finding("a", ["user:alice"], offset_seconds=0, mitre=["T1566"]),
        _finding("b", ["user:alice"], offset_seconds=60, mitre=["T1059", "T1566"]),
        _finding("c", ["user:alice"], offset_seconds=120, mitre=["T1486"]),
    ]
    incident = build_incidents(findings)[0]
    assert incident.mitre_attack == ["T1566", "T1059", "T1486"]


def test_summary_names_the_attack_progression() -> None:
    findings = [
        _finding("a", ["user:alice"], offset_seconds=0, mitre=["T1566"]),
        _finding("b", ["user:alice"], offset_seconds=3600, mitre=["T1486"]),
    ]
    incident = build_incidents(findings)[0]
    assert "Attack progression:" in incident.summary
    assert "initial-access" in incident.summary
    assert "impact" in incident.summary
    assert "Spanning 1.0h" in incident.summary


def test_single_entity_incident_keeps_the_simple_title() -> None:
    incident = build_incidents([_finding("a", ["user:alice"])])[0]
    assert incident.title == "Suspicious activity involving user:alice"


def test_severity_is_the_max_in_the_cluster() -> None:
    findings = [
        _finding("a", ["user:alice"], severity=Severity.LOW),
        _finding("b", ["user:alice"], offset_seconds=60, severity=Severity.CRITICAL),
    ]
    assert build_incidents(findings)[0].severity is Severity.CRITICAL


def test_risk_score_is_capped_at_1000() -> None:
    findings = [
        _finding(str(index), ["user:alice"], offset_seconds=index * 60, risk_points=500)
        for index in range(5)
    ]
    assert build_incidents(findings)[0].risk_score == 1000


def test_incidents_are_sorted_by_risk_descending() -> None:
    findings = [
        _finding("low", ["user:low"], risk_points=10),
        _finding("high", ["user:high"], risk_points=900),
        _finding("mid", ["user:mid"], risk_points=100),
    ]
    scores = [incident.risk_score for incident in build_incidents(findings)]
    assert scores == sorted(scores, reverse=True)


def test_every_finding_lands_in_exactly_one_incident() -> None:
    """No finding may be dropped or duplicated by correlation."""
    findings = [
        _finding("a", ["user:alice", "host:ws-1"], offset_seconds=0),
        _finding("b", ["host:ws-1"], offset_seconds=60),
        _finding("c", ["user:bob"], offset_seconds=120),
        _finding("d", [], offset_seconds=180),
        _finding("e", ["user:alice"], offset_seconds=CORRELATION_WINDOW_SECONDS * 3),
    ]
    incidents = build_incidents(findings)
    assigned = [fid for incident in incidents for fid in incident.finding_ids]
    assert sorted(assigned) == ["a", "b", "c", "d", "e"]
    assert len(assigned) == len(set(assigned))


# --- entity risk -----------------------------------------------------------


def test_aggregate_entity_risk_sums_per_entity() -> None:
    findings = [
        _finding("a", ["user:alice", "host:ws-1"], risk_points=30),
        _finding("b", ["user:alice"], offset_seconds=60, risk_points=20),
    ]
    risk = aggregate_entity_risk(findings)
    assert risk["user:alice"].score == 50
    assert risk["host:ws-1"].score == 30
    assert risk["user:alice"].finding_ids == ["a", "b"]
    assert len(risk["user:alice"].reasons) == 2


def test_aggregate_entity_risk_caps_at_1000() -> None:
    findings = [
        _finding(str(index), ["user:alice"], offset_seconds=index * 60, risk_points=400)
        for index in range(5)
    ]
    assert aggregate_entity_risk(findings)["user:alice"].score == 1000


def test_aggregate_entity_risk_uses_unknown_placeholder() -> None:
    assert UNKNOWN_ENTITY in aggregate_entity_risk([_finding("a", [])])

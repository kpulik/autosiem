"""Tests for the analyst runtime tasks that were previously fixed strings.

`enrich_entities`, `link_duplicate_alerts` and `create_case_note` all perform
real work now. `search_related_events` has its own module
(`tests/test_related_events.py`).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from autosiem.schemas import Finding, Incident, Severity
from autosiem.soc_runtime import AIAnalystRuntime

BASE_TIME = datetime(2026, 8, 4, 10, 0, 0, tzinfo=timezone.utc)


class FakeStore:
    def __init__(self, rows_by_entity: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.rows_by_entity = rows_by_entity or {}

    def search_events(
        self,
        query: str | None = None,
        entity: str | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return list(self.rows_by_entity.get(entity or "", []))


def _event(event_id: str, action: str = "login", category: str = "authentication", offset: int = 0) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": (BASE_TIME + timedelta(seconds=offset)).isoformat(),
        "action": action,
        "category": category,
    }


def _finding(
    finding_id: str,
    entities: list[str],
    *,
    rule_id: str = "RULE-1",
    rule_name: str = "test rule",
    offset: int = 0,
    mitre: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        rule_name=rule_name,
        event_id=f"e-{finding_id}",
        timestamp=BASE_TIME + timedelta(seconds=offset),
        severity=Severity.MEDIUM,
        risk_points=10,
        entities=entities,
        mitre_attack=mitre or [],
        evidence=evidence or {},
    )


def _incident(entities: list[str], finding_ids: list[str], **kwargs: Any) -> Incident:
    return Incident(
        incident_id="inc-1",
        title=kwargs.get("title", "test incident"),
        severity=kwargs.get("severity", Severity.HIGH),
        risk_score=kwargs.get("risk_score", 300),
        entities=entities,
        finding_ids=finding_ids,
        mitre_attack=kwargs.get("mitre", []),
        summary="test",
    )


def _result(investigation: Any, action: str) -> str:
    task = next(item for item in investigation.tasks if item.action == action)
    assert task.result is not None
    return task.result


def _evidence(investigation: Any, kind: str) -> list[Any]:
    return [item for item in investigation.evidence if item.kind == kind]


# --- enrich_entities -------------------------------------------------------


def test_enrich_reports_when_no_store_is_configured() -> None:
    runtime = AIAnalystRuntime()
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), [_finding("f1", ["user:alice"])])
    assert "could not be enriched" in _result(investigation, "enrich_entities")
    assert _evidence(investigation, "entity_context") == []


def test_enrich_builds_a_profile_per_entity() -> None:
    store = FakeStore(
        {
            "user:alice": [
                _event("a1", action="login", offset=0),
                _event("a2", action="file_delete", offset=60),
            ]
        }
    )
    runtime = AIAnalystRuntime(event_search=store)
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), [_finding("f1", ["user:alice"])])

    profiles = _evidence(investigation, "entity_context")[0].data["profiles"]
    alice = next(profile for profile in profiles if profile["entity"] == "user:alice")
    assert alice["known"] is True
    assert alice["event_count"] == 2
    assert alice["distinct_actions"] == 2
    assert alice["first_seen"] < alice["last_seen"]
    assert alice["categories"] == ["authentication"]


def test_enrich_flags_entities_with_no_history() -> None:
    """A first observation is itself triage context, not an absence of data."""
    store = FakeStore({"user:alice": [_event("a1")]})
    runtime = AIAnalystRuntime(event_search=store)
    incident = _incident(["user:alice", "cloud_account:prod"], ["f1"])
    investigation = runtime.investigate(incident, [_finding("f1", ["user:alice"])])

    result = _result(investigation, "enrich_entities")
    assert "No prior history for 1 entity (cloud_account:prod)" in result
    profiles = _evidence(investigation, "entity_context")[0].data["profiles"]
    unknown = next(profile for profile in profiles if profile["entity"] == "cloud_account:prod")
    assert unknown["known"] is False
    assert unknown["event_count"] == 0


def test_enrich_names_the_busiest_entity() -> None:
    store = FakeStore(
        {
            "user:alice": [_event(f"a{i}", offset=i) for i in range(5)],
            "host:ws-1": [_event("b1")],
        }
    )
    runtime = AIAnalystRuntime(event_search=store)
    incident = _incident(["user:alice", "host:ws-1"], ["f1"])
    result = _result(runtime.investigate(incident, [_finding("f1", ["user:alice"])]), "enrich_entities")
    assert "Busiest: user:alice with 5 event(s)" in result


# --- link_duplicate_alerts -------------------------------------------------


def test_no_duplicates_is_reported_cleanly() -> None:
    findings = [
        _finding("f1", ["user:alice"], rule_id="RULE-A"),
        _finding("f2", ["user:alice"], rule_id="RULE-B", offset=60),
    ]
    investigation = AIAnalystRuntime().investigate(_incident(["user:alice"], ["f1", "f2"]), findings)
    result = _result(investigation, "link_duplicate_alerts")
    assert "2 distinct rule/entity pair(s)" in result
    assert "no duplicates to link" in result
    assert _evidence(investigation, "duplicate_alerts") == []


def test_repeated_rule_on_same_entity_is_collapsed() -> None:
    findings = [_finding(f"f{i}", ["user:alice"], rule_id="RULE-A", offset=i * 60) for i in range(4)]
    investigation = AIAnalystRuntime().investigate(
        _incident(["user:alice"], [f"f{i}" for i in range(4)]), findings
    )

    result = _result(investigation, "link_duplicate_alerts")
    assert "Linked 1 repeated pair(s), collapsing 3 duplicate finding(s)" in result

    cluster = _evidence(investigation, "duplicate_alerts")[0].data["clusters"][0]
    assert cluster["rule_id"] == "RULE-A"
    assert cluster["entity"] == "user:alice"
    assert cluster["count"] == 4
    assert cluster["first_seen"] < cluster["last_seen"]


def test_same_rule_on_different_entities_is_not_a_duplicate() -> None:
    findings = [
        _finding("f1", ["user:alice"], rule_id="RULE-A"),
        _finding("f2", ["user:bob"], rule_id="RULE-A", offset=60),
    ]
    investigation = AIAnalystRuntime().investigate(_incident(["user:alice", "user:bob"], ["f1", "f2"]), findings)
    assert "no duplicates to link" in _result(investigation, "link_duplicate_alerts")


def test_duplicate_clusters_are_ordered_by_size() -> None:
    findings = [_finding(f"a{i}", ["user:alice"], rule_id="RULE-A", offset=i) for i in range(4)]
    findings += [_finding(f"b{i}", ["user:bob"], rule_id="RULE-B", offset=i) for i in range(2)]
    ids = [finding.finding_id for finding in findings]
    investigation = AIAnalystRuntime().investigate(_incident(["user:alice", "user:bob"], ids), findings)

    clusters = _evidence(investigation, "duplicate_alerts")[0].data["clusters"]
    assert [cluster["count"] for cluster in clusters] == [4, 2]


# --- create_case_note ------------------------------------------------------


def test_case_note_is_attached_to_the_investigation() -> None:
    incident = _incident(["user:alice"], ["f1"], title="Suspicious activity involving user:alice", mitre=["T1566"])
    investigation = AIAnalystRuntime().investigate(incident, [_finding("f1", ["user:alice"], mitre=["T1566"])])

    assert investigation.case_note is not None
    assert investigation.case_note.startswith("AI triage note for Suspicious activity involving user:alice")
    assert "Risk 300 / severity high" in investigation.case_note
    assert "ATT&CK progression: T1566." in investigation.case_note
    assert "Entities: user:alice." in investigation.case_note


def test_case_note_lists_detection_rule_names() -> None:
    findings = [_finding("f1", ["user:alice"], rule_name="Encoded PowerShell command")]
    investigation = AIAnalystRuntime().investigate(_incident(["user:alice"], ["f1"]), findings)
    assert investigation.case_note is not None
    assert "Detections: Encoded PowerShell command." in investigation.case_note


def test_case_note_summarizes_behavioral_signals() -> None:
    findings = [
        _finding(
            "f1",
            ["user:alice"],
            rule_id="builtin-anomaly-baseline",
            rule_name="Behavioral anomaly",
            evidence={"signals": [{"signal": "novel_host"}, {"signal": "off_hours"}]},
        )
    ]
    investigation = AIAnalystRuntime().investigate(_incident(["user:alice"], ["f1"]), findings)
    assert investigation.case_note is not None
    assert "Behavioral signals: novel_host, off_hours." in investigation.case_note


def test_case_note_runs_last_so_it_sees_the_other_tasks_context() -> None:
    """Ordering guard: the note summarizes evidence the earlier tasks produced."""
    findings = [_finding(f"f{i}", ["user:alice"], rule_id="RULE-A", offset=i * 60) for i in range(3)]
    store = FakeStore({"user:alice": [_event("old-1")]})
    runtime = AIAnalystRuntime(event_search=store)
    investigation = runtime.investigate(_incident(["user:alice"], ["f0", "f1", "f2"]), findings)

    actions = [task.action for task in investigation.tasks]
    assert actions.index("create_case_note") == len(actions) - 1

    assert investigation.case_note is not None
    context = [line for line in investigation.case_note.splitlines() if line.startswith("Context:")]
    assert any("prior event(s)" in line for line in context)
    assert any("Local context" in line for line in context)
    assert any("repeated rule/entity pair(s)" in line for line in context)


def test_runtime_is_reentrant_across_incidents() -> None:
    """One runtime investigating two incidents must not leak the first note."""
    runtime = AIAnalystRuntime()
    first = runtime.investigate(
        _incident(["user:alice"], ["f1"], title="first"), [_finding("f1", ["user:alice"])]
    )
    second = runtime.investigate(
        _incident(["user:bob"], ["f2"], title="second"), [_finding("f2", ["user:bob"])]
    )

    assert first.case_note is not None and "first" in first.case_note
    assert second.case_note is not None and "second" in second.case_note
    assert "user:alice" not in second.case_note

"""Tests for approval-gated SOAR runbook recommendations (soar.py)."""
from __future__ import annotations

from autosiem.policy import AutomationPolicy
from autosiem.schemas import Incident, Severity
from autosiem.soar import SoarLibrary, SoarPlanner, SoarRunbook


def test_register_and_for_technique() -> None:
    library = SoarLibrary()
    library.register(
        SoarRunbook(
            name="Shell Triage",
            technique="T1059",
            actions=["search_related_events", "isolate_host", "notify_channel"],
            description="Triage suspicious command execution.",
        )
    )
    assert library.for_technique("T1059") == [library.runbooks[0]]
    assert library.for_technique("T9999") == []


def test_recommend_marks_high_risk_action_as_approval_required() -> None:
    incident = Incident(
        incident_id="INC-1",
        title="Suspicious shell",
        severity=Severity.HIGH,
        risk_score=75,
        entities=["host:web-1"],
        finding_ids=["F-1"],
        mitre_attack=["T1059"],
        summary="Suspicious command execution detected.",
    )
    planner = SoarPlanner(policy=AutomationPolicy())
    proposals = planner.recommend(incident)
    by_action = {p["action"]: p for p in proposals}
    assert "isolate_host" in by_action
    assert by_action["isolate_host"]["approval_required"] is True


def test_read_actions_are_not_approval_gated() -> None:
    incident = Incident(
        incident_id="INC-2",
        title="Read me",
        severity=Severity.MEDIUM,
        risk_score=50,
        entities=["user:alice"],
        finding_ids=["F-2"],
        mitre_attack=["T1059"],
        summary=".",
    )
    planner = SoarPlanner(policy=AutomationPolicy())
    proposals = planner.recommend(incident)
    read = [p for p in proposals if p["action"] == "search_related_events"]
    assert read
    assert read[0]["approval_required"] is False
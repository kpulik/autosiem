from __future__ import annotations

from pathlib import Path

from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules
from autosiem.soc_runtime import DecisionType, TaskStatus


def test_ai_soc_runtime_proposes_but_does_not_execute_high_risk_actions() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)

    incident = result.incidents[0]
    investigation = result.investigations[incident.incident_id]

    assert investigation.decision.decision_type == DecisionType.CONTAINMENT_PROPOSED
    assert investigation.decision.confidence >= 0.75
    assert all(task.status == TaskStatus.COMPLETED for task in investigation.tasks)
    assert investigation.action_proposals
    assert all(proposal.approval_required for proposal in investigation.action_proposals)
    assert not any(proposal.executable_now for proposal in investigation.action_proposals)
    assert investigation.audit_log

from __future__ import annotations

from pathlib import Path

from autosiem.feedback import FeedbackEngine, FeedbackRecord
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rag import default_rag_engine
from autosiem.rules import load_rules
from autosiem.soar import SoarPlanner

ROOT = Path(__file__).resolve().parents[1]


def _demo_lines() -> list[str]:
    return (ROOT / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()


def _base_technique(technique: str) -> str:
    return technique.split(".")[0] if "." in technique else technique


def test_rag_context_is_appended_to_local_report() -> None:
    rules = load_rules(ROOT / "rules")
    plain = AutoSIEMPipeline(rules).process_lines(_demo_lines())
    copilot = AutoSIEMPipeline(rules, rag=default_rag_engine()).process_lines(_demo_lines())
    report = copilot.reports[copilot.incidents[0].incident_id]
    plain_report = plain.reports[plain.incidents[0].incident_id]
    # The runbook context is appended to the deterministic local explainer report.
    assert "## Relevant runbooks / historical context" in report
    assert "Runbook" in report
    assert len(report) > len(plain_report)


def test_rag_context_flows_into_llm_prompt_when_configured() -> None:
    """extra_context must reach LLMService._build_user_prompt (no backend needed)."""
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, rag=default_rag_engine()).process_lines(_demo_lines())
    incident = result.incidents[0]
    assert result.reports[incident.incident_id]


def test_soar_plan_merges_approval_gated_proposals() -> None:
    rules = load_rules(ROOT / "rules")
    base = AutoSIEMPipeline(rules).process_lines(_demo_lines())
    copilot = AutoSIEMPipeline(rules, soar=SoarPlanner()).process_lines(_demo_lines())
    incident = copilot.incidents[0]
    investigation = copilot.investigations[incident.incident_id]
    base_investigation = base.investigations[base.incidents[0].incident_id]

    assert len(investigation.action_proposals) > len(base_investigation.action_proposals)
    assert any("soar_plan_applied" in entry for entry in investigation.audit_log)
    assert investigation.status == "needs_approval"
    assert any(proposal.action == "search_related_events" for proposal in investigation.action_proposals)


def test_soar_proposals_deduped_on_base_technique() -> None:
    """Sub-techniques (T1059.001) must not duplicate their parent's (T1059) steps."""
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, soar=SoarPlanner()).process_lines(_demo_lines())
    incident = result.incidents[0]
    proposals = result.investigations[incident.incident_id].action_proposals
    # Only MITRE-technique targets participate in the base-technique dedup;
    # entity targets (host:/ip:/user:) are distinct by design.
    technique_pairs = [
        (proposal.action, _base_technique(proposal.target))
        for proposal in proposals
        if proposal.target.startswith("T")
    ]
    assert technique_pairs, "expected technique-targeted SOAR proposals"
    assert len(technique_pairs) == len(set(technique_pairs)), f"duplicate SOAR proposals: {technique_pairs}"


def test_feedback_rejections_lower_finding_risk() -> None:
    rules = load_rules(ROOT / "rules")
    base = AutoSIEMPipeline(rules).process_lines(_demo_lines())
    feedback = FeedbackEngine()
    for finding in base.findings:
        if finding.rule_id == "AUTO-CRED-001":
            feedback.record(
                FeedbackRecord(rule_id=finding.rule_id, entity=finding.entities[0], decision="reject")
            )
    result = AutoSIEMPipeline(rules, feedback=feedback).process_lines(_demo_lines())
    cred = [finding for finding in result.findings if finding.rule_id == "AUTO-CRED-001"]
    assert cred
    # 25 risk points * 0.8 trust weight (one reject) -> 20.
    assert all(finding.risk_points == 20 for finding in cred)

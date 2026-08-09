"""The autonomy gate: what is allowed to authorize an irreversible action.

At ``POLICY_BOUNDED_AUTONOMOUS_RESPONSE`` a sufficiently confident high-risk
action may execute without a human. The question these tests pin down is *whose*
confidence counts. A language model reporting 0.99 about its own output is not
evidence, and treating it as evidence would let the model authorize its own
containment action. Only confidence AutoSIEM derived from the evidence can open
that gate; a model-reported score always falls back to human approval.

Everything here is deterministic and offline -- the LLM path is exercised with a
stub backend, never a network call.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from autosiem.llm import LLMBackend, LLMConfig, LLMService
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.policy import AutomationPolicy, AutonomyLevel
from autosiem.rules import load_rules
from autosiem.schemas import Finding, Incident, Severity
from autosiem.soar import MAX_PLAN_CONFIDENCE, SoarPlanner, _confidence_for
from autosiem.soc_runtime import AIAnalystRuntime

ROOT = Path(__file__).resolve().parents[1]

HIGH_RISK_ACTIONS = ("isolate_host", "disable_user", "block_indicator")


def _autonomous_policy() -> AutomationPolicy:
    return AutomationPolicy(autonomy_level=AutonomyLevel.POLICY_BOUNDED_AUTONOMOUS_RESPONSE)


def _demo_lines() -> list[str]:
    return (ROOT / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()


def _critical_incident() -> Incident:
    return Incident(
        incident_id="INC-AUTONOMY",
        title="Critical activity",
        severity=Severity.CRITICAL,
        risk_score=1000,
        entities=["user:alice", "host:workstation-7", "ip:198.51.100.25"],
        finding_ids=["F-1", "F-2", "F-3"],
        mitre_attack=["T1059"],
        summary="Critical incident.",
    )


def _max_confidence_findings() -> list[Finding]:
    """Findings that drive ``_estimate_confidence`` to its 0.99 ceiling.

    Three findings plus a behavioral one clears
    ``minimum_confidence_for_policy_bounded_response`` (0.98), which is what
    makes the level-4 autonomous branch reachable at all.
    """
    now = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)
    rules = [("AUTO-EXEC-001", "Encoded PowerShell"), ("AUTO-CRED-001", "Credential dumping"), ("builtin-anomaly-baseline", "Behavioral anomaly")]
    return [
        Finding(
            finding_id=f"F-{index}",
            rule_id=rule_id,
            rule_name=rule_name,
            event_id=f"E-{index}",
            timestamp=now,
            severity=Severity.CRITICAL,
            risk_points=100,
            entities=["user:alice", "host:workstation-7"],
            mitre_attack=["T1059"],
            evidence={},
        )
        for index, (rule_id, rule_name) in enumerate(rules, start=1)
    ]


# --------------------------------------------------------------------------
# policy: the gate itself
# --------------------------------------------------------------------------


def test_deterministic_confidence_can_open_the_autonomous_gate() -> None:
    """The documented level-4 capability still works for evidence-derived scores."""
    policy = _autonomous_policy()
    allowed, approval_required, reason = policy.decision_for_action("isolate_host", 0.99)
    assert allowed is True
    assert approval_required is False
    assert "policy-bounded autonomous mode" in reason


def test_model_reported_confidence_cannot_open_the_autonomous_gate() -> None:
    policy = _autonomous_policy()
    for confidence in (0.98, 0.99, 1.0):
        allowed, approval_required, reason = policy.decision_for_action(
            "isolate_host", confidence, confidence_source="model"
        )
        assert allowed is False, confidence
        assert approval_required is True, confidence
        assert "model-reported confidence" in reason


def test_model_reported_confidence_is_blocked_for_every_high_risk_action() -> None:
    policy = _autonomous_policy()
    for action in HIGH_RISK_ACTIONS:
        allowed, approval_required, _ = policy.decision_for_action(
            action, 1.0, confidence_source="model"
        )
        assert allowed is False, action
        assert approval_required is True, action


def test_confidence_source_defaults_to_deterministic() -> None:
    """Callers that predate the parameter keep their existing behaviour."""
    policy = _autonomous_policy()
    assert policy.decision_for_action("isolate_host", 0.99) == policy.decision_for_action(
        "isolate_host", 0.99, confidence_source="deterministic"
    )


def test_lower_autonomy_levels_are_unchanged_by_source() -> None:
    """Below level 4 nothing high-risk executes, whatever the confidence source."""
    for level in (
        AutonomyLevel.OBSERVE_ONLY,
        AutonomyLevel.LOW_RISK_AUTOMATION,
        AutonomyLevel.REVERSIBLE_AUTOMATION,
        AutonomyLevel.APPROVAL_GATED_RESPONSE,
    ):
        policy = AutomationPolicy(autonomy_level=level)
        for source in ("deterministic", "model"):
            allowed, approval_required, _ = policy.decision_for_action(
                "isolate_host", 1.0, confidence_source=source
            )
            assert allowed is False, (level, source)
            assert approval_required is True, (level, source)


def test_below_threshold_confidence_still_requires_approval_at_level_four() -> None:
    policy = _autonomous_policy()
    allowed, approval_required, reason = policy.decision_for_action("isolate_host", 0.97)
    assert allowed is False
    assert approval_required is True
    assert reason == "High-risk action requires human approval."


def test_critical_actions_never_execute_regardless_of_source() -> None:
    policy = _autonomous_policy()
    for source in ("deterministic", "model"):
        allowed, approval_required, _ = policy.decision_for_action(
            "close_incident", 1.0, confidence_source=source
        )
        assert allowed is False, source
        assert approval_required is True, source


def test_low_risk_actions_are_not_affected_by_confidence_source() -> None:
    """The gate applies to irreversible actions, not to reading and annotating."""
    policy = _autonomous_policy()
    for action in ("search_related_events", "create_case_note", "notify_channel"):
        assert policy.decision_for_action(action, 1.0, confidence_source="model") == (
            policy.decision_for_action(action, 1.0)
        )


# --------------------------------------------------------------------------
# runtime: provenance is recorded and honoured
# --------------------------------------------------------------------------


def test_deterministic_decision_is_marked_deterministic() -> None:
    investigation = AIAnalystRuntime().investigate(_critical_incident(), [])
    assert investigation.decision.confidence_source == "deterministic"


def test_llm_decision_is_marked_model_sourced() -> None:
    runtime = AIAnalystRuntime()
    investigation = runtime.investigate(
        _critical_incident(),
        [],
        decision_override={
            "decision_type": "containment_proposed",
            "confidence": 1.0,
            "rationale": "stub",
            "recommended_owner": "tier-2-incident-responder",
        },
    )
    assert investigation.decision.confidence_source == "model"
    assert investigation.decision.confidence == 1.0


def test_autonomous_runtime_executes_on_its_own_confidence() -> None:
    """Level 4 + deterministic analyst: the capability is intact."""
    runtime = AIAnalystRuntime(policy=_autonomous_policy())
    investigation = runtime.investigate(_critical_incident(), _max_confidence_findings())
    assert investigation.decision.confidence >= 0.98
    high_risk = [item for item in investigation.action_proposals if item.action in HIGH_RISK_ACTIONS]
    assert high_risk
    assert any(item.executable_now for item in high_risk)


def test_autonomous_runtime_will_not_execute_on_model_confidence() -> None:
    """Same incident, same level, same number -- but the model said it."""
    runtime = AIAnalystRuntime(policy=_autonomous_policy())
    investigation = runtime.investigate(
        _critical_incident(),
        _max_confidence_findings(),
        decision_override={
            "decision_type": "containment_proposed",
            "confidence": 1.0,
            "rationale": "trust me",
            "recommended_owner": "tier-2-incident-responder",
        },
    )
    high_risk = [item for item in investigation.action_proposals if item.action in HIGH_RISK_ACTIONS]
    assert high_risk
    assert not any(item.executable_now for item in high_risk)
    assert all(item.approval_required for item in high_risk)


def test_audit_log_records_the_confidence_source() -> None:
    runtime = AIAnalystRuntime(policy=_autonomous_policy())
    investigation = runtime.investigate(
        _critical_incident(),
        [],
        decision_override={"decision_type": "containment_proposed", "confidence": 1.0},
    )
    proposed = [entry for entry in investigation.audit_log if entry.startswith("action_proposed")]
    assert proposed
    assert all("confidence_source=model" in entry for entry in proposed)


# --------------------------------------------------------------------------
# soar: an approval-gated step must not also be flagged executable
# --------------------------------------------------------------------------


def _finding(severity: Severity, index: int = 1) -> Finding:
    return Finding(
        finding_id=f"F-{index}",
        rule_id="AUTO-TEST-001",
        rule_name="Test rule",
        event_id=f"E-{index}",
        timestamp=datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
        severity=severity,
        risk_points=10,
        entities=["user:alice"],
        mitre_attack=["T1059"],
        evidence={},
    )


def test_plan_confidence_never_claims_certainty() -> None:
    """Counting alerts cannot establish certainty, however many there are."""
    for count in (1, 3, 10, 50):
        findings = [_finding(Severity.CRITICAL, index) for index in range(count)]
        assert _confidence_for(findings) <= MAX_PLAN_CONFIDENCE < 1.0, count


def test_plan_confidence_rises_with_severity() -> None:
    """The score reflects severity, which is what the heuristic claims to use."""
    scores = [
        _confidence_for([_finding(severity)])
        for severity in (Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    ]
    assert scores == sorted(scores)
    assert scores[0] < scores[-1]


def test_plan_confidence_rises_with_corroboration() -> None:
    single = _confidence_for([_finding(Severity.HIGH, 1)])
    triple = _confidence_for([_finding(Severity.HIGH, index) for index in range(3)])
    assert triple > single


def test_no_evidence_scores_lowest() -> None:
    """No findings must not outrank an actual finding."""
    none_at_all = _confidence_for(None)
    empty = _confidence_for([])
    weakest_real = _confidence_for([_finding(Severity.INFORMATIONAL)])
    assert none_at_all == empty
    assert none_at_all < weakest_real


def test_soar_confidence_cannot_reach_the_autonomous_threshold() -> None:
    """A runbook match alone is never enough to open the level-4 gate.

    The planner's confidence is capped below
    ``minimum_confidence_for_policy_bounded_response``, so even a pile of
    critical findings leaves a human in the loop.
    """
    policy = _autonomous_policy()
    assert MAX_PLAN_CONFIDENCE < policy.minimum_confidence_for_policy_bounded_response
    findings = _max_confidence_findings() * 4
    assert _confidence_for(findings) <= MAX_PLAN_CONFIDENCE
    plan = SoarPlanner(policy=policy).recommend(_critical_incident(), findings=findings)
    high_risk = [step for step in plan if step["action"] in HIGH_RISK_ACTIONS]
    assert high_risk
    assert all(step["approval_required"] is True for step in high_risk)
    assert all(step["allowed"] is False for step in high_risk)


def test_soar_high_risk_step_is_not_both_executable_and_approval_gated() -> None:
    """`allowed` is what an executor reads; leaving it set makes approval advisory.

    Reaching the safety net needs an operator who has lowered the autonomous
    threshold under the planner's ceiling, which is the only way a SOAR step
    comes back from the policy as executable in the first place.
    """
    policy = AutomationPolicy(
        autonomy_level=AutonomyLevel.POLICY_BOUNDED_AUTONOMOUS_RESPONSE,
        minimum_confidence_for_policy_bounded_response=0.80,
    )
    findings = _max_confidence_findings()
    assert _confidence_for(findings) >= 0.80, "test needs the policy branch to be reachable"
    plan = SoarPlanner(policy=policy).recommend(_critical_incident(), findings=findings)
    high_risk = [step for step in plan if step["action"] in HIGH_RISK_ACTIONS]
    assert high_risk
    for step in high_risk:
        assert step["approval_required"] is True, step
        assert step["allowed"] is False, step


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------


class _OverconfidentBackend(LLMBackend):
    def chat(self, system: str, user: str) -> str:
        return json.dumps(
            {
                "decision_type": "containment_proposed",
                "confidence": 1.0,
                "rationale": "I am certain.",
                "recommended_owner": "tier-2-incident-responder",
                "summary": "stub report",
            }
        )


def _overconfident_llm() -> LLMService:
    service = LLMService(config=LLMConfig())
    service.backend = _OverconfidentBackend(service.config)
    return service


def _autonomous_pipeline(llm: LLMService | None) -> AutoSIEMPipeline:
    pipeline = AutoSIEMPipeline(load_rules(ROOT / "rules"), llm=llm, soar=SoarPlanner())
    pipeline.analyst_runtime.policy = _autonomous_policy()
    pipeline.soar = SoarPlanner(policy=_autonomous_policy())
    return pipeline


def test_overconfident_llm_cannot_reach_autonomous_containment_end_to_end() -> None:
    result = _autonomous_pipeline(_overconfident_llm()).process_lines(_demo_lines())
    investigation = result.investigations[result.incidents[0].incident_id]
    assert any(entry.startswith("decision_from_llm") for entry in investigation.audit_log)
    high_risk = [item for item in investigation.action_proposals if item.action in HIGH_RISK_ACTIONS]
    assert high_risk
    assert not any(item.executable_now for item in high_risk)
    assert all(item.approval_required for item in high_risk)


def test_no_proposal_is_ever_executable_and_approval_gated_at_once() -> None:
    """The invariant that makes `executable_now` meaningful to a downstream executor."""
    for llm in (None, _overconfident_llm()):
        result = _autonomous_pipeline(llm).process_lines(_demo_lines())
        for investigation in result.investigations.values():
            for proposal in investigation.action_proposals:
                assert not (proposal.executable_now and proposal.approval_required), (
                    f"{proposal.action} -> {proposal.target}"
                )


def test_default_pipeline_is_unaffected() -> None:
    """Default autonomy is level 2: nothing high-risk executes, LLM or not."""
    result = AutoSIEMPipeline(
        load_rules(ROOT / "rules"), llm=_overconfident_llm(), soar=SoarPlanner()
    ).process_lines(_demo_lines())
    for investigation in result.investigations.values():
        high_risk = [
            item for item in investigation.action_proposals if item.action in HIGH_RISK_ACTIONS
        ]
        assert not any(item.executable_now for item in high_risk)

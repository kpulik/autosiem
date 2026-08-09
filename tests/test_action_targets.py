"""Action/target semantics: a response action may only be pointed at a kind of
thing it can actually act on.

The bug this file guards against: SOAR runbooks are keyed by MITRE technique, and
the runbook steps used to inherit the technique id as their target, so the
approval queue filled up with ``isolate_host -> T1059`` and
``disable_user -> T1078``. A technique is a detection scope, not a host or an
account. See ``policy.ActionPolicy.target_kinds``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from autosiem.llm import LLMBackend, LLMConfig, LLMService
from autosiem.pipeline import AutoSIEMPipeline, _dedup_key
from autosiem.policy import (
    AutomationPolicy,
    DEFAULT_NOTIFY_CHANNEL,
    base_technique,
    classify_target,
    is_shared_infrastructure,
)
from autosiem.rules import load_rules
from autosiem.schemas import Incident, Severity
from autosiem.soar import SoarLibrary, SoarPlanner, SoarRunbook
from autosiem.soc_runtime import AIAnalystRuntime

ROOT = Path(__file__).resolve().parents[1]

#: Actions that act on a concrete thing and must never carry a technique target.
ENTITY_ACTIONS = ("isolate_host", "disable_user", "block_indicator")

TECHNIQUES = ("T1059", "T1078", "T1110", "T1566", "T1059.001")


def _demo_lines() -> list[str]:
    return (ROOT / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()


def _incident(entities: list[str], techniques: list[str] | None = None) -> Incident:
    return Incident(
        incident_id="INC-TARGETS",
        title="Suspicious activity",
        severity=Severity.CRITICAL,
        risk_score=400,
        entities=entities,
        finding_ids=["F-1"],
        mitre_attack=techniques or ["T1059"],
        summary="Test incident.",
    )


# --------------------------------------------------------------------------
# policy: target classification
# --------------------------------------------------------------------------


def test_classify_target_recognizes_entity_kinds() -> None:
    assert classify_target("user:alice") == "user"
    assert classify_target("host:web-01") == "host"
    assert classify_target("ip:198.51.100.25") == "indicator"
    assert classify_target("domain:evil.example") == "indicator"
    assert classify_target("sha256:abc123") == "indicator"
    assert classify_target("cloud_account:123456789012") == "cloud_account"
    assert classify_target("channel:soc-escalations") == "channel"
    assert classify_target("incident:INC-1") == "incident"


def test_classify_target_recognizes_techniques() -> None:
    assert classify_target("T1059") == "technique"
    assert classify_target("T1059.001") == "technique"


def test_classify_target_rejects_what_it_cannot_name() -> None:
    """Unclassifiable targets fail closed rather than being guessed at."""
    for value in ("", "   ", "soc-escalations", "web-01", "T1059x", "T105", "host:", "nope:x"):
        assert classify_target(value) is None, value


def test_base_technique_collapses_sub_techniques() -> None:
    assert base_technique("T1059.001") == "T1059"
    assert base_technique("T1059") == "T1059"


# --------------------------------------------------------------------------
# policy: target validation is the enforcement boundary
# --------------------------------------------------------------------------


def test_host_action_rejects_technique_target() -> None:
    policy = AutomationPolicy()
    for technique in TECHNIQUES:
        valid, reason = policy.validate_target("isolate_host", technique)
        assert valid is False, technique
        assert "technique" in reason


def test_user_action_rejects_technique_target() -> None:
    policy = AutomationPolicy()
    for technique in TECHNIQUES:
        valid, reason = policy.validate_target("disable_user", technique)
        assert valid is False, technique
        assert "technique" in reason


def test_indicator_action_rejects_technique_target() -> None:
    policy = AutomationPolicy()
    valid, _ = policy.validate_target("block_indicator", "T1566")
    assert valid is False


def test_entity_actions_reject_each_others_targets() -> None:
    """A host action on a user (and vice versa) is just as wrong as a technique."""
    policy = AutomationPolicy()
    assert policy.validate_target("isolate_host", "user:alice")[0] is False
    assert policy.validate_target("disable_user", "host:web-01")[0] is False
    assert policy.validate_target("block_indicator", "user:alice")[0] is False
    # A cloud account is an identity record, not a blockable network indicator.
    assert policy.validate_target("block_indicator", "cloud_account:123456789012")[0] is False


def test_valid_action_target_combinations_are_accepted() -> None:
    policy = AutomationPolicy()
    valid_pairs = [
        ("isolate_host", "host:workstation-7"),
        ("isolate_host", "host:web-01"),
        ("disable_user", "user:alice"),
        ("block_indicator", "ip:198.51.100.25"),
        ("block_indicator", "domain:evil.example"),
        ("notify_channel", DEFAULT_NOTIFY_CHANNEL),
        ("notify_channel", "T1059"),
        ("search_related_events", "T1059"),
        ("search_related_events", "user:alice"),
        ("enrich_entities", "T1059"),
        ("close_incident", "incident:INC-1"),
    ]
    for action, target in valid_pairs:
        valid, reason = policy.validate_target(action, target)
        assert valid is True, f"{action} -> {target}: {reason}"


def test_unknown_action_has_no_valid_target() -> None:
    policy = AutomationPolicy()
    assert policy.target_kinds_for("wipe_disk") == ()
    valid, reason = policy.validate_target("wipe_disk", "host:web-01")
    assert valid is False
    assert "Unknown action" in reason


def test_tuning_one_policy_does_not_rewrite_the_defaults() -> None:
    """Each AutomationPolicy owns its action table, so per-tenant tuning is local."""
    tuned = AutomationPolicy()
    tuned.action_policies["isolate_host"].target_kinds = ("host", "technique")
    assert AutomationPolicy().target_kinds_for("isolate_host") == ("host",)
    assert AutomationPolicy().validate_target("isolate_host", "T1059")[0] is False


def test_shared_infrastructure_is_never_an_isolation_target() -> None:
    policy = AutomationPolicy()
    assert is_shared_infrastructure("host:vpn-1") is True
    assert is_shared_infrastructure("host:workstation-7") is False
    # Not a host at all, so the shared-infrastructure rule does not apply.
    assert is_shared_infrastructure("user:vpn-admin") is False
    valid, reason = policy.validate_target("isolate_host", "host:vpn-1")
    assert valid is False
    assert "shared network infrastructure" in reason


# --------------------------------------------------------------------------
# soar: the planner resolves real targets from the incident
# --------------------------------------------------------------------------


def test_planner_resolves_host_action_to_every_host_entity() -> None:
    incident = _incident(["user:alice", "host:web-01", "host:workstation-7", "ip:198.51.100.25"])
    plan = SoarPlanner().recommend(incident)
    isolate = sorted(step["target"] for step in plan if step["action"] == "isolate_host")
    assert isolate == ["host:web-01", "host:workstation-7"]


def test_planner_resolves_user_and_indicator_actions_to_entities() -> None:
    incident = _incident(
        ["user:alice", "host:web-01", "ip:198.51.100.25", "ip:203.0.113.10"],
        techniques=["T1078", "T1566"],
    )
    plan = SoarPlanner().recommend(incident)
    assert {step["target"] for step in plan if step["action"] == "disable_user"} == {"user:alice"}
    assert {step["target"] for step in plan if step["action"] == "block_indicator"} == {
        "ip:198.51.100.25",
        "ip:203.0.113.10",
    }


def test_planner_never_targets_a_technique_with_an_entity_action() -> None:
    incident = _incident(
        ["user:alice", "host:web-01", "ip:198.51.100.25"],
        techniques=["T1059", "T1078", "T1110", "T1566"],
    )
    plan = SoarPlanner().recommend(incident)
    offenders = [
        step for step in plan
        if step["action"] in ENTITY_ACTIONS and classify_target(step["target"]) == "technique"
    ]
    assert offenders == []


def test_planner_keeps_technique_scope_for_read_and_notify_steps() -> None:
    incident = _incident(["user:alice", "host:web-01"], techniques=["T1059.001"])
    plan = SoarPlanner().recommend(incident)
    by_action: dict[str, set[str]] = {}
    for step in plan:
        by_action.setdefault(step["action"], set()).add(step["target"])
    # The runbook is registered for the parent technique, so that is its scope.
    assert by_action["search_related_events"] == {"T1059"}
    assert by_action["enrich_entities"] == {"T1059"}
    assert by_action["notify_channel"] == {"T1059"}


def test_planner_drops_untargetable_step_and_records_why() -> None:
    """No host in scope means no isolate_host proposal -- and a stated reason."""
    incident = _incident(["user:alice"], techniques=["T1059"])
    planner = SoarPlanner()
    plan = planner.recommend(incident)
    assert not [step for step in plan if step["action"] == "isolate_host"]
    dropped = [item for item in planner.dropped if item["action"] == "isolate_host"]
    assert dropped
    assert "host" in dropped[0]["reason"]


def test_planner_drops_shared_infrastructure_isolation() -> None:
    incident = _incident(["user:alice", "host:vpn-1"], techniques=["T1059"])
    planner = SoarPlanner()
    plan = planner.recommend(incident)
    assert not [step for step in plan if step["action"] == "isolate_host"]
    assert any("shared network infrastructure" in item["reason"] for item in planner.dropped)


def test_every_planned_step_validates_against_the_policy() -> None:
    incident = _incident(
        ["user:alice", "host:web-01", "host:mail-gw", "ip:198.51.100.25", "cloud_account:1234"],
        techniques=["T1059", "T1078", "T1110", "T1566"],
    )
    policy = AutomationPolicy()
    for step in SoarPlanner().recommend(incident):
        valid, reason = policy.validate_target(step["action"], step["target"])
        assert valid is True, f"{step['action']} -> {step['target']}: {reason}"


def test_planner_falls_back_to_the_default_channel_without_a_technique_scope() -> None:
    """A notify step for a runbook with no technique scope still has somewhere to go."""
    library = SoarLibrary()
    library.register(
        SoarRunbook(
            name="Notify only",
            technique="T1059",
            actions=["notify_channel"],
            description="Notify.",
        )
    )
    policy = AutomationPolicy()
    policy.action_policies["notify_channel"].target_kinds = ("channel",)
    plan = SoarPlanner(library=library, policy=policy).recommend(_incident(["user:alice"]))
    assert [step["target"] for step in plan] == [DEFAULT_NOTIFY_CHANNEL]


# --------------------------------------------------------------------------
# soc_runtime: the runtime validates its own proposals
# --------------------------------------------------------------------------


def test_runtime_rejects_its_own_invalid_target_and_audits_it() -> None:
    incident = _incident(["user:alice", "host:vpn-1"])
    investigation = AIAnalystRuntime().investigate(incident, [])
    isolate = [item for item in investigation.action_proposals if item.action == "isolate_host"]
    assert isolate == []
    assert any(
        entry.startswith("action_rejected action=isolate_host target=host:vpn-1")
        for entry in investigation.audit_log
    )


def test_runtime_notify_target_is_a_classifiable_channel() -> None:
    """Escalation notifies a channel, and that channel must be nameable."""
    incident = Incident(
        incident_id="INC-ESC",
        title="Escalate me",
        severity=Severity.MEDIUM,
        risk_score=120,
        entities=["user:alice"],
        finding_ids=["F-1"],
        mitre_attack=[],
        summary="Moderate risk.",
    )
    investigation = AIAnalystRuntime().investigate(incident, [])
    notify = [item for item in investigation.action_proposals if item.action == "notify_channel"]
    assert notify
    assert classify_target(notify[0].target) == "channel"


# --------------------------------------------------------------------------
# pipeline: independent enforcement + dedup
# --------------------------------------------------------------------------


class _RoguePlanner(SoarPlanner):
    """A planner that emits an invalid action/target pair on purpose.

    The pipeline must reject it regardless of what produced the plan -- that is
    what makes the check a boundary rather than a fix in one code path.
    """

    def recommend(
        self,
        incident: Incident,
        findings: list[Any] | None = None,
        method: str = "local",
        policy: AutomationPolicy | None = None,
    ) -> list[dict[str, Any]]:
        self.dropped = []
        self.plan = [
            {
                "action": "isolate_host",
                "target": "T1059",
                "technique": "T1059",
                "confidence": 0.9,
                "approval_required": True,
                "allowed": False,
                "description": "rogue step",
            },
            {
                "action": "disable_user",
                "target": "T1078",
                "technique": "T1078",
                "confidence": 0.9,
                "approval_required": True,
                "allowed": False,
                "description": "rogue step",
            },
            {
                "action": "notify_channel",
                "target": "T1059",
                "technique": "T1059",
                "confidence": 0.9,
                "approval_required": False,
                "allowed": True,
                "description": "valid step",
            },
        ]
        return self.plan


def test_pipeline_rejects_invalid_plan_steps_from_any_planner() -> None:
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, soar=_RoguePlanner()).process_lines(_demo_lines())
    incident = result.incidents[0]
    investigation = result.investigations[incident.incident_id]
    invalid = [
        item for item in investigation.action_proposals
        if item.action in ENTITY_ACTIONS and classify_target(item.target) == "technique"
    ]
    assert invalid == []
    rejected = [entry for entry in investigation.audit_log if entry.startswith("soar_step_rejected")]
    assert len(rejected) == 2
    # The valid step in the same plan still lands.
    assert any(
        item.action == "notify_channel" and item.target == "T1059"
        for item in investigation.action_proposals
    )


def test_dedup_key_collapses_sub_techniques_but_not_addresses() -> None:
    assert _dedup_key("T1059.001") == "T1059"
    assert _dedup_key("T1059") == "T1059"
    # Regression: splitting on "." would have merged every 198.51.100.x address.
    assert _dedup_key("ip:198.51.100.25") == "ip:198.51.100.25"
    assert _dedup_key("ip:198.51.100.55") != _dedup_key("ip:198.51.100.25")
    assert _dedup_key("host:mail-gw.corp.example") == "host:mail-gw.corp.example"


def test_demo_pipeline_produces_no_invalid_action_target_pairs() -> None:
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, soar=SoarPlanner()).process_lines(_demo_lines())
    policy = AutomationPolicy()
    checked = 0
    for investigation in result.investigations.values():
        for proposal in investigation.action_proposals:
            valid, reason = policy.validate_target(proposal.action, proposal.target)
            assert valid is True, f"{proposal.action} -> {proposal.target}: {reason}"
            checked += 1
    assert checked, "expected the demo run to produce proposals"


def test_demo_pipeline_keeps_valid_entity_proposals() -> None:
    """The fix must not sweep away the proposals that were right all along."""
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, soar=SoarPlanner()).process_lines(_demo_lines())
    proposals = result.investigations[result.incidents[0].incident_id].action_proposals
    by_action: dict[str, set[str]] = {}
    for proposal in proposals:
        by_action.setdefault(proposal.action, set()).add(proposal.target)
    assert "host:workstation-7" in by_action["isolate_host"]
    assert "host:web-01" in by_action["isolate_host"]
    assert by_action["disable_user"] == {"user:alice"}
    # Every distinct address survives dedup.
    assert len(by_action["block_indicator"]) >= 4
    assert all(target.startswith("ip:") for target in by_action["block_indicator"])


def test_demo_pipeline_preserves_policy_gating_on_high_risk_actions() -> None:
    """Fixing targets must not make anything destructive auto-executable."""
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, soar=SoarPlanner()).process_lines(_demo_lines())
    proposals = result.investigations[result.incidents[0].incident_id].action_proposals
    high_risk = [item for item in proposals if item.action in ENTITY_ACTIONS]
    assert high_risk
    assert all(item.approval_required for item in high_risk)
    assert not any(item.executable_now for item in high_risk)


class _StubBackend(LLMBackend):
    """An LLM that returns a maximally confident containment decision.

    No network: the backend is swapped in directly, so this stays deterministic.
    """

    def chat(self, system: str, user: str) -> str:
        return json.dumps(
            {
                "decision_type": "containment_proposed",
                "confidence": 1.0,
                "rationale": "stub",
                "recommended_owner": "tier-2-incident-responder",
                "summary": "stub report",
            }
        )


def _stub_llm() -> LLMService:
    service = LLMService(config=LLMConfig())
    service.backend = _StubBackend(service.config)
    return service


def test_llm_decision_path_produces_valid_targets_only() -> None:
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, llm=_stub_llm(), soar=SoarPlanner()).process_lines(_demo_lines())
    investigation = result.investigations[result.incidents[0].incident_id]
    assert any(entry.startswith("decision_from_llm") for entry in investigation.audit_log)
    policy = AutomationPolicy()
    for proposal in investigation.action_proposals:
        valid, reason = policy.validate_target(proposal.action, proposal.target)
        assert valid is True, f"{proposal.action} -> {proposal.target}: {reason}"


def test_llm_confidence_cannot_unlock_high_risk_execution() -> None:
    """A confident LLM must not be able to talk the policy into auto-containment."""
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, llm=_stub_llm(), soar=SoarPlanner()).process_lines(_demo_lines())
    investigation = result.investigations[result.incidents[0].incident_id]
    high_risk = [item for item in investigation.action_proposals if item.action in ENTITY_ACTIONS]
    assert high_risk
    assert all(item.approval_required for item in high_risk)
    assert not any(item.executable_now for item in high_risk)


def test_demo_pipeline_audits_dropped_steps() -> None:
    rules = load_rules(ROOT / "rules")
    result = AutoSIEMPipeline(rules, soar=SoarPlanner()).process_lines(_demo_lines())
    audit = result.investigations[result.incidents[0].incident_id].audit_log
    # host:vpn-1 is in scope but is shared infrastructure, so the step is
    # dropped with a stated reason instead of disappearing.
    assert any(entry.startswith("soar_step_dropped action=isolate_host") for entry in audit)

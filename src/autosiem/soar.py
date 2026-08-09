"""Approval-gated SOAR runbook recommendation.

Given an incident, recommend which runbook actions make sense, resolve what each
action should act on, then gate it through the automation policy. High/critical-risk
actions are never auto-executed -- they are always marked ``approval_required`` so a
human signs off before anything irreversible or destructive runs.

Runbooks are keyed by MITRE technique, but a technique is a scope, not a thing you
can act on. Steps that operate on something concrete -- an account, an endpoint, an
indicator -- are resolved against the incident's entities, and dropped when the
incident holds nothing of the required kind. See ``policy.ActionPolicy.target_kinds``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .policy import (
    AutomationPolicy,
    DEFAULT_ACTION_POLICIES,
    DEFAULT_NOTIFY_CHANNEL,
    base_technique,
    classify_target,
)
from .schemas import Finding, Incident, Severity

# Runbook actions spelled identically to the policy action names where possible
# so the heuristic match is trivial. Any action not in the policy table is
# treated as unknown and therefore blocked / approval-required.
_POLICY_NAMES = set(DEFAULT_ACTION_POLICIES)


#: Ceiling on a runbook-match confidence. Severity and corroboration can make a
#: recommendation strong; they cannot make it certain. Kept below
#: ``minimum_confidence_for_policy_bounded_response`` so a runbook match on its
#: own is never what opens the autonomous gate.
MAX_PLAN_CONFIDENCE = 0.90

#: Findings past this point stop adding corroboration. A fourth alert on the
#: same technique says little the third did not.
_CORROBORATION_CAP = 3


def _confidence_for(findings: list[Finding] | None) -> float:
    """Confidence that a runbook fits this incident.

    Severity carries most of the signal and corroborating findings add the rest
    with diminishing returns, floored at 0.50 when there is no evidence at all
    and capped at ``MAX_PLAN_CONFIDENCE``: counting alerts can make a
    recommendation strong, never certain.
    """
    if not findings:
        return 0.50
    severity = max(finding.severity for finding in findings)
    corroboration = min(len(findings), _CORROBORATION_CAP) / _CORROBORATION_CAP
    score = 0.50 + 0.25 * (severity.value / Severity.CRITICAL.value) + 0.15 * corroboration
    return round(min(score, MAX_PLAN_CONFIDENCE), 2)


@dataclass(slots=True)
class SoarRunbook:
    """A named, ordered set of recommended response actions."""

    name: str
    technique: str
    actions: list[str]
    description: str = ""


@dataclass
class SoarLibrary:
    """Registry of runbooks keyed by MITRE technique."""

    runbooks: list[SoarRunbook] = field(default_factory=list)

    def register(self, *runbooks: SoarRunbook) -> None:
        self.runbooks.extend(runbooks)

    def for_technique(self, technique: str) -> list[SoarRunbook]:
        base = technique.split(".")[0]
        return [
            rb
            for rb in self.runbooks
            if rb.technique == technique or rb.technique == base
        ]

    def recommend(self, incident: Incident) -> list[dict[str, Any]]:
        """Pick runbooks matching the incident's techniques."""
        recommendations: list[dict[str, Any]] = []
        for technique in incident.mitre_attack:
            for runbook in self.for_technique(technique):
                recommendations.append(
                    {
                        "runbook": runbook.name,
                        "technique": technique,
                        "description": runbook.description,
                        "actions": list(runbook.actions),
                    }
                )
        return recommendations


def default_library() -> SoarLibrary:
    library = SoarLibrary()
    library.register(
        SoarRunbook(
            name="Command & Scripting Interpreter Response",
            technique="T1059",
            actions=["search_related_events", "enrich_entities", "isolate_host", "notify_channel"],
            description="Triage and contain a suspicious command or scripting interpreter execution.",
        ),
        SoarRunbook(
            name="Credential Access Response",
            technique="T1110",
            actions=["search_related_events", "disable_user", "notify_channel"],
            description="Investigate brute force / password guessing and disable the affected account.",
        ),
        SoarRunbook(
            name="Phishing Triage",
            technique="T1566",
            actions=["search_related_events", "block_indicator", "isolate_host", "notify_channel"],
            description="Analyse a delivered phishing message, block indicators, and contain the host.",
        ),
        SoarRunbook(
            name="Valid Accounts Response",
            technique="T1078",
            actions=["search_related_events", "disable_user", "isolate_host", "notify_channel"],
            description="Contain use of valid accounts and disable identities in scope.",
        ),
    )
    return library


class SoarPlanner:
    """Produces approval-gated runbook action proposals for an incident."""

    def __init__(self, library: SoarLibrary | None = None, policy: AutomationPolicy | None = None) -> None:
        self.library = library or _default_library()
        self.policy = policy or AutomationPolicy()
        self.plan: list[dict[str, Any]] = []
        #: Steps the last ``recommend`` could not target, so callers can report
        #: them instead of silently losing a runbook step.
        self.dropped: list[dict[str, str]] = []

    def recommend(
        self,
        incident: Incident,
        findings: list[Finding] | None = None,
        method: str = "local",
        policy: AutomationPolicy | None = None,
    ) -> list[dict[str, Any]]:
        """Build and store the plan of proposed actions for an incident.

        One step can produce several proposals: a runbook says "isolate the
        host", and an incident spanning three hosts needs three proposals.
        """
        policy = policy or self.policy
        confidence = _confidence_for(findings)
        findings = findings or []
        self.plan = []
        self.dropped = []

        for recommendation in self.library.recommend(incident):
            technique = recommendation["technique"]
            for action in recommendation["actions"]:
                if action not in _POLICY_NAMES:
                    # Unknown action: surface for human review, scoped to the
                    # only thing known about it -- the runbook's technique.
                    self.plan.append(self._unknown_action(action, technique, confidence))
                    continue
                targets = self._targets_for(action, incident, technique, policy)
                if not targets:
                    self.dropped.append(
                        {
                            "action": action,
                            "technique": technique,
                            "reason": (
                                f"incident has no {'/'.join(policy.target_kinds_for(action))} "
                                "entity to act on"
                            ),
                        }
                    )
                    continue
                for target in targets:
                    proposal = self._propose(action, technique, target, confidence, policy)
                    if proposal is not None:
                        self.plan.append(proposal)
        return self.plan

    def _targets_for(
        self,
        action: str,
        incident: Incident,
        technique: str,
        policy: AutomationPolicy,
    ) -> list[str]:
        """Resolve what a runbook step should act on.

        Investigation and notification steps stay scoped to the runbook's
        technique, which is what they are actually about. Steps that act on
        something concrete are resolved against the incident's entities of the
        kind the action accepts, and return empty when the incident holds none --
        an ``isolate_host`` proposal without a host is not actionable.
        """
        kinds = policy.target_kinds_for(action)
        if not kinds:
            return []
        if "technique" in kinds:
            # The runbook is written for the parent technique, so that is the
            # scope of the step even when a sub-technique triggered it.
            return [base_technique(technique)]
        matched = [entity for entity in incident.entities if classify_target(entity) in kinds]
        if matched:
            return matched
        if "channel" in kinds:
            return [DEFAULT_NOTIFY_CHANNEL]
        if "incident" in kinds:
            return [f"incident:{incident.incident_id}"]
        return []

    def _unknown_action(self, action: str, technique: str, confidence: float) -> dict[str, Any]:
        return {
            "action": action,
            "description": f"Unknown action '{action}' — needs human review.",
            "approval_required": True,
            "technique": technique,
            "target": technique,
            "confidence": confidence,
            "allowed": False,
        }

    def _propose(
        self,
        action: str,
        technique: str,
        target: str,
        confidence: float,
        policy: AutomationPolicy,
    ) -> dict[str, Any] | None:
        valid, target_reason = policy.validate_target(action, target)
        if not valid:
            self.dropped.append({"action": action, "technique": technique, "reason": target_reason})
            return None
        allowed, approval_required, reason = policy.decision_for_action(action, confidence)
        proposal = {
            "action": action,
            "description": reason,
            "approval_required": approval_required,
            "technique": technique,
            "target": target,
            "confidence": confidence,
            "allowed": allowed,
        }
        # High/critical risk actions must never run without a human approval.
        risk = policy.action_policies[action].risk
        if risk in ("high", "critical") and not approval_required:
            proposal["approval_required"] = True
            # ...and must not stay flagged executable while requiring approval:
            # `allowed` is what an executor reads, so leaving it set would make
            # the approval requirement advisory.
            proposal["allowed"] = False
        return proposal


def _default_library() -> SoarLibrary:
    return default_library()
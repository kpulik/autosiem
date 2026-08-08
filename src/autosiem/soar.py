"""Approval-gated SOAR runbook recommendation.

Given an incident, recommend which runbook actions make sense, then gate each
action through the automation policy. High/critical-risk actions are never
auto-executed -- they are always marked ``approval_required`` so a human signs
off before anything irreversible or destructive runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .policy import AutomationPolicy, DEFAULT_ACTION_POLICIES
from .schemas import Incident

# Runbook actions spelled identically to the policy action names where possible
# so the heuristic match is trivial. Any action not in the policy table is
# treated as unknown and therefore blocked / approval-required.
_POLICY_NAMES = set(DEFAULT_ACTION_POLICIES)


def _confidence_for(findings: list[Any] | None) -> float:
    """Heuristic confidence from available findings: higher severity => higher."""
    if not findings:
        return 0.8
    return max(0.5, min(1.0, 0.7 + 0.1 * min(len(findings), 3)))


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

    def recommend(
        self,
        incident: Incident,
        findings: list[Any] | None = None,
        method: str = "local",
        policy: AutomationPolicy | None = None,
    ) -> list[dict[str, Any]]:
        """Build and store the plan of proposed actions for an incident."""
        policy = policy or self.policy
        confidence = _confidence_for(findings)
        findings = findings or []
        self.plan = []

        for recommendation in self.library.recommend(incident):
            technique = recommendation["technique"]
            for action in recommendation["actions"]:
                proposal = self._propose(action, technique, confidence, policy)
                if proposal is not None:
                    self.plan.append(proposal)
        return self.plan

    def _propose(
        self,
        action: str,
        technique: str,
        confidence: float,
        policy: AutomationPolicy,
    ) -> dict[str, Any] | None:
        if action not in _POLICY_NAMES:
            # Unknown action: surface as proposal but force approval.
            return {
                "action": action,
                "description": f"Unknown action '{action}' — needs human review.",
                "approval_required": True,
                "technique": technique,
                "confidence": confidence,
                "allowed": False,
            }
        allowed, approval_required, reason = policy.decision_for_action(action, confidence)
        proposal = {
            "action": action,
            "description": reason,
            "approval_required": approval_required,
            "technique": technique,
            "confidence": confidence,
            "allowed": allowed,
        }
        # High/critical risk actions must never run without a human approval.
        risk = policy.action_policies[action].risk
        if risk in ("high", "critical") and not approval_required:
            proposal["approval_required"] = True
        return proposal


def _default_library() -> SoarLibrary:
    return default_library()
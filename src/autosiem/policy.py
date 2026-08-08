from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Literal


class AutonomyLevel(IntEnum):
    OBSERVE_ONLY = 0
    LOW_RISK_AUTOMATION = 1
    REVERSIBLE_AUTOMATION = 2
    APPROVAL_GATED_RESPONSE = 3
    POLICY_BOUNDED_AUTONOMOUS_RESPONSE = 4


ActionRisk = Literal["read", "low", "reversible", "high", "critical"]


@dataclass(slots=True)
class ActionPolicy:
    name: str
    risk: ActionRisk
    requires_approval: bool
    description: str


DEFAULT_ACTION_POLICIES: dict[str, ActionPolicy] = {
    "search_related_events": ActionPolicy(
        name="search_related_events",
        risk="read",
        requires_approval=False,
        description="Read-only search for events related to incident entities.",
    ),
    "enrich_entities": ActionPolicy(
        name="enrich_entities",
        risk="read",
        requires_approval=False,
        description="Read-only enrichment of users, hosts, IPs, and cloud accounts.",
    ),
    "create_case_note": ActionPolicy(
        name="create_case_note",
        risk="low",
        requires_approval=False,
        description="Create an auditable case note.",
    ),
    "link_duplicate_alerts": ActionPolicy(
        name="link_duplicate_alerts",
        risk="low",
        requires_approval=False,
        description="Link related alerts without closing or suppressing them.",
    ),
    "notify_channel": ActionPolicy(
        name="notify_channel",
        risk="reversible",
        requires_approval=False,
        description="Notify an approved Slack/Teams/email channel.",
    ),
    "disable_user": ActionPolicy(
        name="disable_user",
        risk="high",
        requires_approval=True,
        description="Disable or lock an identity account.",
    ),
    "isolate_host": ActionPolicy(
        name="isolate_host",
        risk="high",
        requires_approval=True,
        description="Isolate an endpoint through EDR or network control.",
    ),
    "block_indicator": ActionPolicy(
        name="block_indicator",
        risk="high",
        requires_approval=True,
        description="Block an IP, domain, URL, or hash in enforcement tooling.",
    ),
    "close_incident": ActionPolicy(
        name="close_incident",
        risk="critical",
        requires_approval=True,
        description="Close an incident as benign/false-positive/accepted risk.",
    ),
}


@dataclass(slots=True)
class AutomationPolicy:
    autonomy_level: AutonomyLevel = AutonomyLevel.REVERSIBLE_AUTOMATION
    action_policies: dict[str, ActionPolicy] = field(default_factory=lambda: DEFAULT_ACTION_POLICIES.copy())
    minimum_confidence_for_auto_note: float = 0.50
    minimum_confidence_for_response_proposal: float = 0.75
    minimum_confidence_for_policy_bounded_response: float = 0.98

    def decision_for_action(self, action_name: str, confidence: float) -> tuple[bool, bool, str]:
        """Return (allowed_to_execute, approval_required, reason)."""
        policy = self.action_policies.get(action_name)
        if policy is None:
            return False, True, f"Unknown action '{action_name}' is blocked by default."

        if policy.risk == "read":
            return True, False, "Read-only action allowed."
        if policy.risk == "low":
            if self.autonomy_level >= AutonomyLevel.LOW_RISK_AUTOMATION:
                return True, False, "Low-risk action allowed by autonomy policy."
            return False, False, "Low-risk automation disabled by autonomy policy."
        if policy.risk == "reversible":
            if self.autonomy_level >= AutonomyLevel.REVERSIBLE_AUTOMATION:
                return True, False, "Reversible action allowed by autonomy policy."
            return False, False, "Reversible automation disabled by autonomy policy."
        if policy.risk == "high":
            if self.autonomy_level >= AutonomyLevel.APPROVAL_GATED_RESPONSE:
                if confidence >= self.minimum_confidence_for_policy_bounded_response and self.autonomy_level >= AutonomyLevel.POLICY_BOUNDED_AUTONOMOUS_RESPONSE:
                    return True, False, "High-risk action allowed by explicit policy-bounded autonomous mode."
                return False, True, "High-risk action requires human approval."
            return False, True, "High-risk action can only be proposed, not executed."
        return False, True, "Critical action always requires human approval."

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Literal


class AutonomyLevel(IntEnum):
    OBSERVE_ONLY = 0
    LOW_RISK_AUTOMATION = 1
    REVERSIBLE_AUTOMATION = 2
    APPROVAL_GATED_RESPONSE = 3
    POLICY_BOUNDED_AUTONOMOUS_RESPONSE = 4


ActionRisk = Literal["read", "low", "reversible", "high", "critical"]

#: Where a confidence score came from. ``deterministic`` means AutoSIEM derived
#: it from the evidence itself; ``model`` means a language model reported it about
#: its own output. Only the former is evidence, so only the former can satisfy the
#: policy-bounded autonomous gate -- a model must never be able to authorize an
#: irreversible action by asserting that it is confident.
ConfidenceSource = Literal["deterministic", "model"]

#: What kind of thing an action operates on. ``user``/``host``/``indicator``/
#: ``cloud_account`` are the entity kinds ``NormalizedEvent.entities`` emits;
#: ``technique`` is a MITRE ATT&CK id, which is a *scope*, never a thing you
#: can isolate, disable or block.
TargetKind = Literal["user", "host", "indicator", "cloud_account", "channel", "incident", "technique"]

#: Target prefixes AutoSIEM emits, mapped to the kind they name. Keep in sync
#: with ``NormalizedEvent.entities`` in ``schemas.py``.
TARGET_PREFIXES: dict[str, TargetKind] = {
    "user": "user",
    "host": "host",
    "ip": "indicator",
    "domain": "indicator",
    "url": "indicator",
    "hash": "indicator",
    "md5": "indicator",
    "sha1": "indicator",
    "sha256": "indicator",
    "file_hash": "indicator",
    "cloud_account": "cloud_account",
    "channel": "channel",
    "incident": "incident",
}

#: Channel a notification step falls back to when nothing better is in scope.
DEFAULT_NOTIFY_CHANNEL = "channel:soc-escalations"

#: Hostname fragments marking shared network infrastructure. Isolating one of
#: these cuts off everyone behind it, so it is never proposed automatically --
#: an analyst makes that call deliberately.
SHARED_INFRASTRUCTURE_MARKERS: tuple[str, ...] = ("vpn",)

_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

#: Read-only and annotation actions describe or record context, so they may be
#: scoped to an ATT&CK technique, an incident, or any single entity.
_CONTEXT_TARGETS: tuple[TargetKind, ...] = (
    "technique",
    "incident",
    "user",
    "host",
    "indicator",
    "cloud_account",
)


def classify_target(target: str) -> TargetKind | None:
    """Kind of thing ``target`` names, or ``None`` when it cannot be classified.

    Unclassifiable targets are not guessed at: an action whose target nobody can
    name is an action nobody can safely approve.
    """
    value = target.strip()
    if not value:
        return None
    if _TECHNIQUE_PATTERN.match(value):
        return "technique"
    prefix, separator, rest = value.partition(":")
    if separator and rest.strip():
        return TARGET_PREFIXES.get(prefix.strip().lower())
    return None


def base_technique(technique: str) -> str:
    """Parent technique of a sub-technique (``T1059.001`` -> ``T1059``)."""
    return technique.split(".", 1)[0]


def is_shared_infrastructure(target: str) -> bool:
    """True when ``target`` is a host everyone else depends on."""
    if classify_target(target) != "host":
        return False
    return any(marker in target.lower() for marker in SHARED_INFRASTRUCTURE_MARKERS)


@dataclass(slots=True)
class ActionPolicy:
    name: str
    risk: ActionRisk
    requires_approval: bool
    description: str
    #: Target kinds this action may be pointed at. Anything else is rejected
    #: before the action is ever proposed.
    target_kinds: tuple[TargetKind, ...] = _CONTEXT_TARGETS


DEFAULT_ACTION_POLICIES: dict[str, ActionPolicy] = {
    "search_related_events": ActionPolicy(
        name="search_related_events",
        risk="read",
        requires_approval=False,
        description="Read-only search for events related to incident entities.",
        target_kinds=_CONTEXT_TARGETS,
    ),
    "enrich_entities": ActionPolicy(
        name="enrich_entities",
        risk="read",
        requires_approval=False,
        description="Read-only enrichment of users, hosts, IPs, and cloud accounts.",
        target_kinds=_CONTEXT_TARGETS,
    ),
    "create_case_note": ActionPolicy(
        name="create_case_note",
        risk="low",
        requires_approval=False,
        description="Create an auditable case note.",
        target_kinds=_CONTEXT_TARGETS,
    ),
    "link_duplicate_alerts": ActionPolicy(
        name="link_duplicate_alerts",
        risk="low",
        requires_approval=False,
        description="Link related alerts without closing or suppressing them.",
        target_kinds=_CONTEXT_TARGETS,
    ),
    "notify_channel": ActionPolicy(
        name="notify_channel",
        risk="reversible",
        requires_approval=False,
        description="Notify an approved Slack/Teams/email channel.",
        target_kinds=("channel", "technique", "incident"),
    ),
    "disable_user": ActionPolicy(
        name="disable_user",
        risk="high",
        requires_approval=True,
        description="Disable or lock an identity account.",
        target_kinds=("user",),
    ),
    "isolate_host": ActionPolicy(
        name="isolate_host",
        risk="high",
        requires_approval=True,
        description="Isolate an endpoint through EDR or network control.",
        target_kinds=("host",),
    ),
    "block_indicator": ActionPolicy(
        name="block_indicator",
        risk="high",
        requires_approval=True,
        description="Block an IP, domain, URL, or hash in enforcement tooling.",
        target_kinds=("indicator",),
    ),
    "close_incident": ActionPolicy(
        name="close_incident",
        risk="critical",
        requires_approval=True,
        description="Close an incident as benign/false-positive/accepted risk.",
        target_kinds=("incident",),
    ),
}


def _default_action_policies() -> dict[str, ActionPolicy]:
    """Per-instance copies of the action table.

    A plain ``dict.copy()`` shares the ``ActionPolicy`` objects, so tuning one
    policy on one ``AutomationPolicy`` would silently rewrite the defaults for
    every other caller in the process.
    """
    return {name: replace(policy) for name, policy in DEFAULT_ACTION_POLICIES.items()}


@dataclass(slots=True)
class AutomationPolicy:
    autonomy_level: AutonomyLevel = AutonomyLevel.REVERSIBLE_AUTOMATION
    action_policies: dict[str, ActionPolicy] = field(default_factory=_default_action_policies)
    minimum_confidence_for_auto_note: float = 0.50
    minimum_confidence_for_response_proposal: float = 0.75
    minimum_confidence_for_policy_bounded_response: float = 0.98

    def target_kinds_for(self, action_name: str) -> tuple[TargetKind, ...]:
        """Target kinds ``action_name`` accepts; empty for an unknown action."""
        policy = self.action_policies.get(action_name)
        return policy.target_kinds if policy else ()

    def validate_target(self, action_name: str, target: str) -> tuple[bool, str]:
        """Return ``(valid, reason)`` for pointing ``action_name`` at ``target``.

        Fail-closed on both sides: an unknown action has no valid targets, and a
        target that cannot be classified is rejected rather than assumed. This is
        what stops a host or identity action being raised against an ATT&CK
        technique id, which is a detection scope and not something you can
        isolate, disable or block.
        """
        policy = self.action_policies.get(action_name)
        if policy is None:
            return False, f"Unknown action '{action_name}' has no valid targets."
        kind = classify_target(target)
        if kind is None:
            return False, (
                f"Target '{target}' is not a recognized entity, indicator, channel, "
                "incident or ATT&CK technique."
            )
        if kind not in policy.target_kinds:
            return False, (
                f"Action '{action_name}' operates on {'/'.join(policy.target_kinds)} targets, "
                f"but '{target}' is a {kind}."
            )
        if action_name == "isolate_host" and is_shared_infrastructure(target):
            return False, (
                f"'{target}' is shared network infrastructure; isolating it would cut off "
                "every user behind it."
            )
        return True, f"Target '{target}' is a valid {kind} for '{action_name}'."

    def decision_for_action(
        self,
        action_name: str,
        confidence: float,
        confidence_source: ConfidenceSource = "deterministic",
    ) -> tuple[bool, bool, str]:
        """Return (allowed_to_execute, approval_required, reason).

        ``confidence_source`` says whether ``confidence`` was derived from the
        evidence or self-reported by a language model. A model-reported score
        never satisfies the policy-bounded autonomous gate, however high it is:
        a model asserting 0.99 is not evidence, and raising the threshold would
        only invite it to assert 0.999.
        """
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
            if self.autonomy_level < AutonomyLevel.APPROVAL_GATED_RESPONSE:
                return False, True, "High-risk action can only be proposed, not executed."
            if (
                self.autonomy_level >= AutonomyLevel.POLICY_BOUNDED_AUTONOMOUS_RESPONSE
                and confidence >= self.minimum_confidence_for_policy_bounded_response
            ):
                if confidence_source == "model":
                    return False, True, (
                        "High-risk action requires human approval: autonomous execution "
                        "cannot be authorized by model-reported confidence."
                    )
                return True, False, "High-risk action allowed by explicit policy-bounded autonomous mode."
            return False, True, "High-risk action requires human approval."
        return False, True, "Critical action always requires human approval."

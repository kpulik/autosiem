"""Suppression and exception framework.

Analysts define exceptions so noisy-but-benign detections stop flooding the
queue: findings can be fully ``suppress``-ed or ``downgrade``-d to a lower
severity. The engine also auto-suppresses repeated findings for the same
(rule, entity) within a short window, which is the classic "repeat alert"
grind for tier-1 analysts.

Every suppression decision is recorded so the deterministic detection core
stays the source of truth: nothing is hidden, only annotated.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Deque
from uuid import uuid4

from .schemas import Finding, Severity

VALID_ACTIONS = {"suppress", "downgrade"}
DEFAULT_REPEAT_WINDOW_MINUTES = 15
DEFAULT_REPEAT_THRESHOLD = 5

# Single source of truth for suppression defaults: callers, storage, and the
# web layer reference these constants instead of hardcoding the same values.
DEFAULT_SUPPRESSION_RULE_ID = "*"  # match any rule
DEFAULT_SUPPRESSION_ACTION = "suppress"
DEFAULT_SUPPRESSION_NAME = "manual suppression"
DEFAULT_SUPPRESSION_REASON = ""
DEFAULT_CREATED_BY = "analyst"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid4())


def validate_suppression_fields(action: str, downgrade_to: str | None) -> None:
    """Raise ValueError for invalid action / downgrade-target combinations."""
    if action not in VALID_ACTIONS:
        raise ValueError(f"action must be one of {sorted(VALID_ACTIONS)}")
    if action == "downgrade" and not downgrade_to:
        raise ValueError("downgrade_to is required when action == 'downgrade'")


@dataclass(slots=True)
class Suppression:
    """An analyst-defined (or auto-repeat) exception for a rule.

    Only ``rule_id`` is required; every other field has a reasonable default,
    including an auto-generated ``suppression_id``. ``action`` defaults to
    "suppress", so ``Suppression(rule_id="X", reason="noise")`` is valid.
    """

    rule_id: str  # specific rule id, or "*" to match any rule
    name: str = DEFAULT_SUPPRESSION_NAME
    action: str = DEFAULT_SUPPRESSION_ACTION  # "suppress" | "downgrade"
    reason: str = DEFAULT_SUPPRESSION_REASON
    suppression_id: str = field(default_factory=_new_id)
    entity: str | None = None  # e.g. "user:alice", "host:vpn-1", "ip:..."
    downgrade_to: str | None = None  # severity name, required when action == downgrade
    expires_at: datetime | None = None
    created_by: str = DEFAULT_CREATED_BY
    created_at: datetime = field(default_factory=_now)
    enabled: bool = True

    def matches(self, finding: Finding, now: datetime | None = None) -> bool:
        if not self.enabled:
            return False
        now = now or _now()
        if self.expires_at is not None and self.expires_at < now:
            return False
        if self.rule_id != "*" and self.rule_id != finding.rule_id:
            return False
        if self.entity is not None and self.entity not in finding.entities:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "suppression_id": self.suppression_id,
            "rule_id": self.rule_id,
            "name": self.name,
            "action": self.action,
            "reason": self.reason,
            "entity": self.entity,
            "downgrade_to": self.downgrade_to,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "enabled": self.enabled,
        }


def _entity_key(finding: Finding) -> str:
    return finding.entities[0] if finding.entities else "none"


class SuppressionEngine:
    """Applies analyst exceptions plus in-memory auto-repeat suppression.

    ``apply`` returns the findings that should still be considered (downgrades
    mutate the finding's severity) and a record of every suppression decision
    for auditability.
    """

    def __init__(
        self,
        suppressions: list[Suppression] | None = None,
        auto_repeat: bool = True,
        repeat_window_minutes: int = DEFAULT_REPEAT_WINDOW_MINUTES,
        repeat_threshold: int = DEFAULT_REPEAT_THRESHOLD,
    ) -> None:
        self.suppressions: list[Suppression] = list(suppressions or [])
        self.auto_repeat = auto_repeat
        self.repeat_window = timedelta(minutes=repeat_window_minutes)
        self.repeat_threshold = repeat_threshold
        self._seen: dict[tuple[str, str], Deque[datetime]] = defaultdict(deque)

    def add_suppression(self, suppression: Suppression | None = None, **fields: Any) -> Suppression:
        """Register a suppression given either a Suppression or raw fields.

        Raw fields fall back to the ``DEFAULT_*`` constants when omitted, so
        callers only supply what differs from the defaults. Returns the
        registered ``Suppression`` (with a generated id when none was given).
        """
        if suppression is None:
            action = fields.pop("action", DEFAULT_SUPPRESSION_ACTION)
            downgrade_to = fields.pop("downgrade_to", None)
            validate_suppression_fields(action, downgrade_to)
            suppression = Suppression(
                rule_id=fields.pop("rule_id", DEFAULT_SUPPRESSION_RULE_ID),
                name=fields.pop("name", DEFAULT_SUPPRESSION_NAME),
                action=action,
                reason=fields.pop("reason", DEFAULT_SUPPRESSION_REASON),
                suppression_id=fields.pop("suppression_id", None) or _new_id(),
                entity=fields.pop("entity", None),
                downgrade_to=downgrade_to,
                expires_at=fields.pop("expires_at", None),
                created_by=fields.pop("created_by", DEFAULT_CREATED_BY),
                enabled=bool(fields.pop("enabled", True)),
            )
        else:
            validate_suppression_fields(suppression.action, suppression.downgrade_to)
        self.suppressions.append(suppression)
        return suppression

    def matches(self, finding: Finding, now: datetime | None = None) -> Suppression | None:
        for suppression in self.suppressions:
            if suppression.matches(finding, now):
                return suppression
        return None

    def apply(self, findings: list[Finding]) -> tuple[list[Finding], list[dict[str, Any]]]:
        """Return (kept_findings, suppressed_records).

        Downgraded findings are kept (with ``severity`` lowered); suppressed
        findings are dropped. ``suppressed_records`` documents every decision.
        """
        kept: list[Finding] = []
        suppressed: list[dict[str, Any]] = []
        ordered = sorted(findings, key=lambda f: f.timestamp)
        for finding in ordered:
            match = self.matches(finding)
            if match is None and self.auto_repeat:
                match = self._auto_repeat_suppression(finding)
            if match is None:
                kept.append(finding)
                continue
            record: dict[str, Any] = {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "event_id": finding.event_id,
                "timestamp": finding.timestamp.isoformat(),
                "entity": _entity_key(finding),
                "action": match.action,
                "reason": match.reason,
                "suppression_id": match.suppression_id,
            }
            if match.action == "suppress":
                suppressed.append(record)
                continue
            # downgrade: lower the severity, keep the finding
            target = Severity.from_value(match.downgrade_to)
            if finding.severity > target:
                record["from"] = finding.severity.name.lower()
                finding.severity = target
            record["to"] = finding.severity.name.lower()
            record["severity"] = finding.severity.name.lower()
            suppressed.append(record)
            kept.append(finding)
        return kept, suppressed

    def _auto_repeat_suppression(self, finding: Finding) -> Suppression | None:
        """Suppress the Nth+ repeat of the same (rule, entity) in a window."""
        if self.repeat_threshold <= 1:
            return None
        key = (finding.rule_id, _entity_key(finding))
        bucket = self._seen[key]
        cutoff = finding.timestamp - self.repeat_window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(finding.timestamp)
        if len(bucket) <= self.repeat_threshold:
            return None
        return Suppression(
            suppression_id=f"auto-repeat:{key[0]}:{key[1]}",
            rule_id=finding.rule_id,
            name="auto-repeat suppression",
            action="suppress",
            reason=f"Auto-repeated {len(bucket)} times for {key[1]} within {self.repeat_window.total_seconds() / 60:.0f} minutes.",
        )

"""Analyst feedback learning.

Captures whether analysts approve, reject, or merely comment on findings, then
translates that signal into a per-rule trust weight. Rules an analyst keeps
rejecting become less trusted, which lowers their effective risk contribution
so downstream triage / SOAR can prioritise the content analysts actually care
about. Persisted as a flat JSON list.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

VALID_DECISIONS = ("approve", "reject", "comment")

# Weight tuning: how much each approved/rejected signal moves the rule weight.
APPROVE_STEP = 0.1
REJECT_STEP = 0.2
MAX_WEIGHT = 3.0
MIN_WEIGHT = 0.1


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid4())


@dataclass(slots=True)
class Feedback:
    """A lightweight (rule, entity) pair the analyst has rejected."""

    rule_id: str
    entity: str
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "entity": self.entity, "weight": self.weight}


@dataclass(slots=True)
class FeedbackRecord:
    """One analyst decision about a finding."""

    finding_id: str = field(default_factory=_new_id)
    rule_id: str = ""
    entity: str | None = None
    decision: str = ""  # "approve" | "reject" | "comment"
    actor: str = "analyst"
    created_at: datetime = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "entity": self.entity,
            "decision": self.decision,
            "actor": self.actor,
            "created_at": self.created_at.isoformat(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "FeedbackRecord":
        created_at = data.get("created_at")
        parsed = datetime.fromisoformat(created_at) if isinstance(created_at, str) else _now()
        return FeedbackRecord(
            decision=str(data.get("decision", "")),
            rule_id=str(data.get("rule_id", "")),
            finding_id=str(data.get("finding_id") or _new_id()),
            entity=data.get("entity"),
            actor=str(data.get("actor") or "analyst"),
            created_at=parsed,
        )


def _validate(record: FeedbackRecord) -> None:
    if record.decision not in VALID_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(VALID_DECISIONS)}, got '{record.decision}'")
    if not record.rule_id:
        raise ValueError("rule_id is required")


class FeedbackEngine:
    """Tracks analyst feedback and derives per-rule trust weights."""

    def __init__(self, records: list[FeedbackRecord] | None = None) -> None:
        self.records: list[FeedbackRecord] = list(records or [])

    def record(self, finding: FeedbackRecord | dict[str, Any]) -> FeedbackRecord:
        """Record one analyst decision (a FeedbackRecord or a dict)."""
        record = finding if isinstance(finding, FeedbackRecord) else FeedbackRecord.from_dict(finding)
        _validate(record)
        self.records.append(record)
        return record

    def list_records(self) -> list[FeedbackRecord]:
        return list(self.records)

    def to_dict(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self.records]

    def weight_for_rule(self, rule_id: str) -> float:
        """Trust weight for a rule, starting at 1.0.

        Each ``approve`` nudges it up, each ``reject`` pulls it down, bounded to
        ``[MIN_WEIGHT, MAX_WEIGHT]``.
        """
        weight = 1.0
        for record in self.records:
            if record.rule_id != rule_id:
                continue
            if record.decision == "approve":
                weight += APPROVE_STEP
            elif record.decision == "reject":
                weight -= REJECT_STEP
        return min(MAX_WEIGHT, max(MIN_WEIGHT, weight))

    def adjusted_risk(self, finding: Any) -> int:
        """Scale a finding's raw risk by its rule's weight when the rule is
        distrusted (weight < 1.0); otherwise return the raw risk unchanged."""
        rule_id = getattr(finding, "rule_id", None) or (finding.get("rule_id") if isinstance(finding, dict) else None)
        raw = getattr(finding, "risk_points", None)
        if raw is None and isinstance(finding, dict):
            raw = finding.get("risk_points")
        raw = int(raw or 0)

        weight = self.weight_for_rule(rule_id or "")
        if weight >= 1.0:
            return raw
        return round(raw * weight)

    def suppression_map(self) -> list[Feedback]:
        """(rule, entity) pairs the analyst has rejected, so triage can lower them."""
        pairs: dict[tuple[str, str], float] = {}
        for record in self.records:
            if record.decision != "reject" or not record.entity:
                continue
            weight = self.weight_for_rule(record.rule_id)
            pairs[(record.rule_id, record.entity)] = weight
        return [Feedback(rule_id=rule_id, entity=entity, weight=weight) for (rule_id, entity), weight in pairs.items()]

    def save(self, path: str | Path) -> None:
        """Persist the feedback records as a JSON list (atomic write)."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(p)

    def load(self, path: str | Path) -> None:
        """Load records from a JSON list written by ``save``."""
        p = Path(path)
        if not p.exists():
            self.records = []
            return
        data = json.loads(p.read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else data.get("records", [])
        self.records = [FeedbackRecord.from_dict(item) for item in items if isinstance(item, dict)]

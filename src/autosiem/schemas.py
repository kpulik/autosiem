from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal
from uuid import uuid4


class Severity(IntEnum):
    INFORMATIONAL = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100

    @classmethod
    def from_value(cls, value: str | int | float | None) -> "Severity":
        if value is None:
            return cls.INFORMATIONAL
        if isinstance(value, (int, float)):
            if value >= 90:
                return cls.CRITICAL
            if value >= 70:
                return cls.HIGH
            if value >= 40:
                return cls.MEDIUM
            if value > 0:
                return cls.LOW
            return cls.INFORMATIONAL
        normalized = str(value).strip().lower()
        return {
            "info": cls.INFORMATIONAL,
            "informational": cls.INFORMATIONAL,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
        }.get(normalized, cls.INFORMATIONAL)


EventCategory = Literal[
    "authentication",
    "process",
    "network",
    "dns",
    "cloud",
    "file",
    "endpoint",
    "application",
    "email",
    "unknown",
]


@dataclass(slots=True)
class NormalizedEvent:
    timestamp: datetime
    category: EventCategory
    action: str
    outcome: str = "unknown"
    event_id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "unknown"
    severity: Severity = Severity.INFORMATIONAL
    user: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    cloud_account: str | None = None
    resource: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def entity_keys(self) -> list[str]:
        entities: list[str] = []
        if self.user:
            entities.append(f"user:{self.user}")
        if self.host:
            entities.append(f"host:{self.host}")
        if self.src_ip:
            entities.append(f"ip:{self.src_ip}")
        if self.cloud_account:
            entities.append(f"cloud_account:{self.cloud_account}")
        return entities

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "category": self.category,
            "action": self.action,
            "outcome": self.outcome,
            "source": self.source,
            "severity": self.severity.name.lower(),
            "user": self.user,
            "host": self.host,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "cloud_account": self.cloud_account,
            "resource": self.resource,
            "labels": self.labels,
            "raw": self.raw,
        }


@dataclass(slots=True)
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: Severity
    risk_points: int
    selection: dict[str, Any]
    mitre_attack: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass(slots=True)
class Finding:
    finding_id: str
    rule_id: str
    rule_name: str
    event_id: str
    timestamp: datetime
    severity: Severity
    risk_points: int
    entities: list[str]
    mitre_attack: list[str]
    evidence: dict[str, Any]


@dataclass(slots=True)
class EntityRisk:
    entity: str
    score: int = 0
    finding_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Incident:
    incident_id: str
    title: str
    severity: Severity
    risk_score: int
    entities: list[str]
    finding_ids: list[str]
    mitre_attack: list[str]
    summary: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

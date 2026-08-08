"""STIX/TAXII threat-intel ingestion and matching (zero runtime dependencies).

Loads STIX 2.x indicator bundles (a subset of the pattern grammar), keeps the
indicators in a small JSON state file, and matches IP/domain/URL/hash indicators
against normalized events at pipeline time. Matches surface as a dedicated
finding (``AUTO-INTEL-001``) that flows into the same entity-risk and incident
machinery as rule detections.

Patterns supported: ``[type:field = 'value']`` clauses, including combined
patterns with ``AND``/``OR`` (each clause is unioned), ``ipv4-addr:value``,
``domain-name:value``, ``url:value``, and ``file:hashes.'SHA-256'``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from .schemas import Finding, NormalizedEvent, Severity

THREAT_INTEL_RULE_ID = "AUTO-INTEL-001"
THREAT_INTEL_RULE_NAME = "Threat Intelligence Indicator Match"

_CLAUSE_RE = re.compile(r"\[\s*([\w.-]+):([\w.'-]+)\s*=\s*'([^']*)'", re.IGNORECASE)


@dataclass(slots=True)
class StixIndicator:
    """One parsed STIX indicator with its clauses extracted from the pattern."""

    indicator_id: str
    name: str
    pattern: str
    clauses: list[dict[str, str]] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "name": self.name,
            "pattern": self.pattern,
            "clauses": self.clauses,
            "description": self.description,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "StixIndicator":
        return StixIndicator(
            indicator_id=str(data.get("indicator_id") or uuid4()),
            name=str(data.get("name") or "untitled"),
            pattern=str(data.get("pattern") or ""),
            clauses=list(data.get("clauses") or []),
            description=str(data.get("description") or ""),
        )


def _parse_pattern(pattern: str) -> list[dict[str, str]]:
    """Extract ``[type:field = 'value']`` clauses from a STIX pattern."""
    return [
        {"type": m.group(1).lower(), "field": m.group(2), "value": m.group(3)}
        for m in _CLAUSE_RE.finditer(pattern)
    ]


def _extract_clauses(obj: dict[str, Any]) -> list[dict[str, str]]:
    pattern = obj.get("pattern")
    if not isinstance(pattern, str):
        return []
    clauses = _parse_pattern(pattern)
    if not clauses and pattern:
        # Every indicator is required to have an observable, so fall back to
        # treating the whole bracketed text as a free-form marker.
        for m in re.finditer(r"'([^']*)'", pattern):
            clauses.append({"type": "any", "field": "", "value": m.group(1)})
    return clauses


def parse_stix_bundle(data: dict[str, Any]) -> list[StixIndicator]:
    """Parse a STIX 2.x bundle (or a single indicator object) into indicators."""
    indicators: list[StixIndicator] = []
    objects: Any = data.get("objects") if isinstance(data, dict) else []
    if not isinstance(objects, list):
        objects = [data] if isinstance(data, dict) else []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        otype = str(obj.get("type") or "")
        pattern = obj.get("pattern")
        if otype == "indicator" and isinstance(pattern, str):
            indicators.append(
                StixIndicator(
                    indicator_id=str(obj.get("id") or uuid4()),
                    name=str(obj.get("name") or "threat indicator"),
                    pattern=pattern,
                    clauses=_extract_clauses(obj),
                    description=str(obj.get("description") or ""),
                )
            )
    return indicators


def load_stix_bundle(path: str | Path) -> list[StixIndicator]:
    """Load and parse a STIX bundle from a file path."""
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    return parse_stix_bundle(data)


def load_intel_state(path: str | Path) -> list[StixIndicator]:
    """Load previously persisted indicators from the JSON state file."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    items = data if isinstance(data, list) else data.get("indicators", [])
    return [StixIndicator.from_dict(item) for item in items if isinstance(item, dict)]


def save_intel_state(path: str | Path, indicators: list[StixIndicator]) -> None:
    """Persist indicators to the JSON state file (atomic write)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"indicators": [ind.to_dict() for ind in indicators]}
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(p)


def default_intel_state(db_path: str | Path) -> Path:
    """Derive the intel state path from a SQLite db path (``<db>.intel.json``)."""
    p = Path(db_path)
    return p.with_name(p.stem + ".intel" + ".json")


def _flatten_strings(value: Any, acc: list[str]) -> None:
    if isinstance(value, dict):
        for v in value.values():
            _flatten_strings(v, acc)
    elif isinstance(value, list):
        for v in value:
            _flatten_strings(v, acc)
    elif isinstance(value, str):
        acc.append(value)
    elif value is not None:
        acc.append(str(value))


class ThreatIntelMatcher:
    """Match normalized events against a set of STIX indicators."""

    def __init__(self, indicators: list[StixIndicator] | None = None) -> None:
        self.indicators = list(indicators or [])

    def add_indicators(self, indicators: list[StixIndicator]) -> None:
        self.indicators.extend(indicators)

    def matches_for(self, event: NormalizedEvent) -> list[StixIndicator]:
        doc = event.to_dict()
        hay: list[str] = []
        _flatten_strings(doc, hay)
        haystack = " ".join(hay).lower()
        return [ind for ind in self.indicators if ind.clauses and self._match(ind, doc, haystack)]

    @staticmethod
    def _match(indicator: StixIndicator, doc: dict[str, Any], haystack: str) -> bool:
        src = doc.get("src_ip")
        dst = doc.get("dst_ip")
        for clause in indicator.clauses:
            ctype = clause.get("type")
            value = clause.get("value") or ""
            if ctype == "ipv4-addr":
                if value.lower() in (str(src or "").lower(), str(dst or "").lower()):
                    return True
            elif value and value.lower() in haystack:
                return True
        return False

    def findings_for(self, event: NormalizedEvent) -> list[Finding]:
        hits = self.matches_for(event)
        if not hits:
            return []
        doc = event.to_dict()
        return [
            Finding(
                finding_id=str(uuid4()),
                rule_id=THREAT_INTEL_RULE_ID,
                rule_name=THREAT_INTEL_RULE_NAME,
                event_id=event.event_id,
                timestamp=event.timestamp,
                severity=Severity.HIGH,
                risk_points=75,
                entities=event.entity_keys(),
                mitre_attack=[],
                evidence={
                    "event": doc,
                    "indicators": [
                        {"indicator_id": i.indicator_id, "name": i.name, "pattern": i.pattern}
                        for i in hits
                    ],
                },
            )
        ]
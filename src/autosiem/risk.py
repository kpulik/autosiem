"""Entity risk aggregation and incident correlation.

Findings are correlated into incidents with a time-windowed entity graph:
two findings join the same incident when they share an entity and occur within
:data:`CORRELATION_WINDOW_SECONDS` of each other. Because the relation is
transitive, an incident can span entity types — a user linked to a host, that
host linked to a source IP, that IP linked to a cloud account — which is what
turns a pile of findings into one attack story.

The time window is what stops everything collapsing into a single incident: a
long quiet gap starts a new incident for the same entity, the same way a SOC
analyst treats last month's activity as a separate case.
"""

from __future__ import annotations

from collections import defaultdict
from uuid import uuid4

from .coverage import tactic_for
from .schemas import EntityRisk, Finding, Incident, Severity

#: Maximum gap between two findings on a shared entity for them to correlate.
#: 24h matches the usual SOC shift/day boundary for "same episode of activity".
CORRELATION_WINDOW_SECONDS = 86_400

#: Placeholder entity for findings that carry no entity of their own.
UNKNOWN_ENTITY = "global:unknown"


def aggregate_entity_risk(findings: list[Finding]) -> dict[str, EntityRisk]:
    risk: dict[str, EntityRisk] = {}
    for finding in findings:
        entities = finding.entities or [UNKNOWN_ENTITY]
        for entity in entities:
            current = risk.setdefault(entity, EntityRisk(entity=entity))
            current.score = min(1000, current.score + finding.risk_points)
            current.finding_ids.append(finding.finding_id)
            current.reasons.append(f"{finding.rule_name} (+{finding.risk_points})")
    return risk


class _UnionFind:
    """Minimal union-find over finding indices."""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]  # path halving
            item = self._parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            # Bias toward the lower index so cluster order stays deterministic.
            if left_root < right_root:
                self._parent[right_root] = left_root
            else:
                self._parent[left_root] = right_root


def correlate_findings(
    findings: list[Finding], window_seconds: int = CORRELATION_WINDOW_SECONDS
) -> list[list[Finding]]:
    """Group findings into correlated clusters.

    Per entity, findings are ordered by time and consecutive ones are linked
    when their gap is within ``window_seconds``. Links are merged transitively,
    so a cluster can span several entities. Clusters and the findings inside
    them keep chronological order; the caller decides how to rank them.
    """
    if not findings:
        return []

    ordered = sorted(range(len(findings)), key=lambda i: (findings[i].timestamp, i))

    by_entity: dict[str, list[int]] = defaultdict(list)
    for index in ordered:
        for entity in findings[index].entities or [UNKNOWN_ENTITY]:
            by_entity[entity].append(index)

    union = _UnionFind(len(findings))
    for indices in by_entity.values():
        for previous, current in zip(indices, indices[1:]):
            gap = (findings[current].timestamp - findings[previous].timestamp).total_seconds()
            if abs(gap) <= window_seconds:
                union.union(previous, current)

    clusters: dict[int, list[Finding]] = defaultdict(list)
    for index in ordered:
        clusters[union.find(index)].append(findings[index])
    return list(clusters.values())


def _primary_entity(cluster: list[Finding]) -> str:
    """The entity carrying the most risk in this cluster (ties broken by name)."""
    totals: dict[str, int] = defaultdict(int)
    for finding in cluster:
        for entity in finding.entities or [UNKNOWN_ENTITY]:
            totals[entity] += finding.risk_points
    if not totals:
        return UNKNOWN_ENTITY
    return max(sorted(totals), key=lambda entity: totals[entity])


def _kill_chain(cluster: list[Finding]) -> list[str]:
    """Techniques in first-observed order — the incident's attack progression."""
    seen: list[str] = []
    for finding in cluster:
        for technique in finding.mitre_attack:
            if technique not in seen:
                seen.append(technique)
    return seen


def _summarize(cluster: list[Finding], primary: str, entities: list[str], risk_score: int) -> str:
    tactics: list[str] = []
    for technique in _kill_chain(cluster):
        tactic = tactic_for(technique)
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    parts = [
        f"{len(cluster)} correlated finding(s) across {len(entities)} entit"
        f"{'y' if len(entities) == 1 else 'ies'}, risk {risk_score}."
    ]
    if tactics:
        parts.append(f"Attack progression: {' → '.join(tactics)}.")
    span = cluster[-1].timestamp - cluster[0].timestamp
    if span.total_seconds() > 0:
        parts.append(f"Spanning {_humanize(span.total_seconds())} from first to last finding.")
    parts.append(f"Highest-risk entity: {primary}.")
    return " ".join(parts)


def _humanize(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def _title(primary: str, entities: list[str]) -> str:
    others = len(entities) - 1
    if others <= 0:
        return f"Suspicious activity involving {primary}"
    return f"Correlated activity involving {primary} and {others} related entit{'y' if others == 1 else 'ies'}"


def build_incidents(
    findings: list[Finding], window_seconds: int = CORRELATION_WINDOW_SECONDS
) -> list[Incident]:
    """Correlate findings into incidents, highest risk first."""
    incidents: list[Incident] = []
    for cluster in correlate_findings(findings, window_seconds=window_seconds):
        risk_score = min(1000, sum(finding.risk_points for finding in cluster))
        max_severity = max((finding.severity for finding in cluster), default=Severity.INFORMATIONAL)
        entities = sorted({entity for finding in cluster for entity in finding.entities})
        primary = _primary_entity(cluster)
        if not entities:
            entities = [primary]
        incidents.append(
            Incident(
                incident_id=str(uuid4()),
                title=_title(primary, entities),
                severity=max_severity,
                risk_score=risk_score,
                entities=entities,
                finding_ids=[finding.finding_id for finding in cluster],
                mitre_attack=_kill_chain(cluster),
                summary=_summarize(cluster, primary, entities, risk_score),
            )
        )
    return sorted(incidents, key=lambda incident: incident.risk_score, reverse=True)

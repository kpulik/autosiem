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

:func:`merge_into_stored` applies the same rule across pipeline runs, so an attack
that spans several batches stays one incident: new findings join a stored open
incident when they share an entity with it inside the window.
"""

from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .coverage import tactic_for
from .schemas import EntityRisk, Finding, Incident, Severity

#: Maximum gap between two findings on a shared entity for them to correlate.
#: 24h matches the usual SOC shift/day boundary for "same episode of activity".
CORRELATION_WINDOW_SECONDS = 86_400

#: Placeholder entity for findings that carry no entity of their own.
UNKNOWN_ENTITY = "global:unknown"

#: A stored incident at this size takes no more findings; the attack continues in
#: a new incident. Every merge reloads the incident's findings, so this bounds the
#: work per batch and the size of the incident document.
MAX_INCIDENT_FINDINGS = 2000

#: Risk scores at which the analyst runtime changes its decision or confidence
#: (``AIAnalystRuntime._make_decision`` and ``_estimate_confidence``).
DECISION_RISK_THRESHOLDS = (30, 100, 200)


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


def incident_from_findings(
    findings: list[Finding], incident_id: str | None = None, created_at: datetime | None = None
) -> Incident:
    """Build one incident from correlated findings; a merge passes the stored id."""
    cluster = sorted(findings, key=lambda finding: finding.timestamp)
    risk_score = min(1000, sum(finding.risk_points for finding in cluster))
    max_severity = max((finding.severity for finding in cluster), default=Severity.INFORMATIONAL)
    entities = sorted({entity for finding in cluster for entity in finding.entities})
    primary = _primary_entity(cluster)
    if not entities:
        entities = [primary]
    return Incident(
        incident_id=incident_id or str(uuid4()),
        title=_title(primary, entities),
        severity=max_severity,
        risk_score=risk_score,
        entities=entities,
        finding_ids=[finding.finding_id for finding in cluster],
        mitre_attack=_kill_chain(cluster),
        summary=_summarize(cluster, primary, entities, risk_score),
        created_at=created_at or datetime.now(timezone.utc),
    )


def build_incidents(
    findings: list[Finding], window_seconds: int = CORRELATION_WINDOW_SECONDS
) -> list[Incident]:
    """Correlate findings into incidents, highest risk first."""
    incidents = [
        incident_from_findings(cluster)
        for cluster in correlate_findings(findings, window_seconds=window_seconds)
    ]
    return sorted(incidents, key=lambda incident: incident.risk_score, reverse=True)


@dataclass(slots=True)
class StoredIncident:
    """An open incident loaded from storage, with its findings."""

    incident: Incident
    findings: list[Finding]


@dataclass(slots=True)
class IncidentMerge:
    """New findings folded into a stored incident."""

    incident: Incident
    previous: Incident
    findings: list[Finding]
    new_finding_ids: list[str]

    @property
    def material(self) -> bool:
        """Whether the analyst's picture changed enough to investigate again.

        More of the same only updates the incident, so a long brute force does
        not write a new investigation and AI case note for every batch.
        """
        before, after = self.previous, self.incident
        return (
            after.severity > before.severity
            or bool(set(after.entities) - set(before.entities))
            or bool(set(after.mitre_attack) - set(before.mitre_attack))
            or any(before.risk_score < line <= after.risk_score for line in DECISION_RISK_THRESHOLDS)
        )


def _entity_times(findings: list[Finding]) -> dict[str, list[datetime]]:
    times: dict[str, list[datetime]] = defaultdict(list)
    for finding in findings:
        for entity in finding.entities:
            times[entity].append(finding.timestamp)
    for stamps in times.values():
        stamps.sort()
    return times


def _linked(cluster: list[Finding], times: dict[str, list[datetime]], window: timedelta) -> bool:
    """True when a finding shares an entity with the stored ones inside the window."""
    for finding in cluster:
        for entity in finding.entities:
            # The placeholder says nothing about who did it, so it links nothing.
            stamps = times.get(entity) if entity != UNKNOWN_ENTITY else None
            if not stamps:
                continue
            nearest = bisect_left(stamps, finding.timestamp - window)
            if nearest < len(stamps) and stamps[nearest] <= finding.timestamp + window:
                return True
    return False


def merge_into_stored(
    findings: list[Finding],
    stored: list[StoredIncident],
    window_seconds: int = CORRELATION_WINDOW_SECONDS,
) -> tuple[list[Incident], list[IncidentMerge]]:
    """Correlate findings, folding each cluster into a stored incident it links to.

    Returns the new incidents and the merges. A cluster that links to several
    stored incidents joins the highest-risk one (oldest on a tie); stored
    incidents are never combined with each other, because each may already carry
    an analyst's triage. A finding for a rule and event the incident already holds
    is a redelivery, not new activity, so it adds no risk.
    """
    window = timedelta(seconds=window_seconds)
    candidates = sorted(
        (item for item in stored if len(item.incident.finding_ids) < MAX_INCIDENT_FINDINGS),
        key=lambda item: (-item.incident.risk_score, item.incident.created_at, item.incident.incident_id),
    )
    indexed = [(item, _entity_times(item.findings)) for item in candidates]

    fresh: list[Incident] = []
    joined: dict[str, tuple[StoredIncident, list[Finding]]] = {}
    for cluster in correlate_findings(findings, window_seconds=window_seconds):
        target = next((item for item, times in indexed if _linked(cluster, times, window)), None)
        if target is None:
            fresh.append(incident_from_findings(cluster))
        else:
            joined.setdefault(target.incident.incident_id, (target, []))[1].extend(cluster)

    merges: list[IncidentMerge] = []
    for target, new in joined.values():
        held = {(finding.rule_id, finding.event_id) for finding in target.findings}
        added = [finding for finding in new if (finding.rule_id, finding.event_id) not in held]
        if not added:
            continue
        combined = sorted([*target.findings, *added], key=lambda finding: finding.timestamp)
        merges.append(
            IncidentMerge(
                incident=incident_from_findings(
                    combined, target.incident.incident_id, target.incident.created_at
                ),
                previous=target.incident,
                findings=combined,
                new_finding_ids=[finding.finding_id for finding in added],
            )
        )
    return fresh, merges

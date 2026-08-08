from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from .policy import AutomationPolicy
from .schemas import Finding, Incident, Severity

#: Events pulled per entity when the runtime searches for related telemetry.
DEFAULT_RELATED_EVENT_LIMIT = 25

_CRITICALITY_ORDER = ("low", "medium", "high", "critical")


def _highest_label(levels: list[str]) -> str | None:
    """Most severe criticality label in ``levels``, or None."""
    best: str | None = None
    for level in levels:
        if level in _CRITICALITY_ORDER and (
            best is None or _CRITICALITY_ORDER.index(level) > _CRITICALITY_ORDER.index(best)
        ):
            best = level
    return best


@runtime_checkable
class EventSearcher(Protocol):
    """Anything that can look up stored events for an entity.

    ``AutoSIEMStorage`` satisfies this. Supplying one makes the runtime's
    ``search_related_events`` task perform a real query instead of describing
    what it would do.
    """

    def search_events(
        self,
        query: str | None = ...,
        entity: str | None = ...,
        limit: int = ...,
        tenant_id: str | None = ...,
    ) -> list[dict[str, Any]]: ...


class TaskStatus(str, Enum):
    PLANNED = "planned"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    NEEDS_APPROVAL = "needs_approval"


class DecisionType(str, Enum):
    LIKELY_BENIGN = "likely_benign"
    SUSPICIOUS_MONITOR = "suspicious_monitor"
    ESCALATE = "escalate"
    CONTAINMENT_PROPOSED = "containment_proposed"


@dataclass(slots=True)
class Evidence:
    evidence_id: str
    kind: str
    source: str
    summary: str
    data: dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class AnalystTask:
    task_id: str
    name: str
    action: str
    status: TaskStatus
    rationale: str
    result: str | None = None
    approval_required: bool = False
    policy_reason: str | None = None


@dataclass(slots=True)
class ActionProposal:
    proposal_id: str
    action: str
    target: str
    rationale: str
    confidence: float
    approval_required: bool
    executable_now: bool
    policy_reason: str


@dataclass(slots=True)
class AnalystDecision:
    decision_id: str
    decision_type: DecisionType
    confidence: float
    rationale: str
    recommended_owner: str


@dataclass(slots=True)
class Investigation:
    investigation_id: str
    incident_id: str
    status: str
    created_at: datetime
    tasks: list[AnalystTask]
    evidence: list[Evidence]
    decision: AnalystDecision
    action_proposals: list[ActionProposal]
    audit_log: list[str]
    #: Triage note the runtime drafted. ``AutoSIEMStorage.save_pipeline_result``
    #: writes it to the incident's comment thread once the incident row exists.
    case_note: str | None = None


class AIAnalystRuntime:
    """Policy-bound AI SOC analyst runtime.

    This first implementation is deterministic and auditable. Future LLM-backed
    agents should produce the same object model after tool-policy checks.
    """

    def __init__(
        self,
        policy: AutomationPolicy | None = None,
        event_search: EventSearcher | None = None,
        tenant_id: str | None = None,
        related_event_limit: int = DEFAULT_RELATED_EVENT_LIMIT,
        enrichment: Any | None = None,
    ) -> None:
        self.policy = policy or AutomationPolicy()
        self.event_search = event_search
        self.tenant_id = tenant_id
        self.related_event_limit = related_event_limit
        # EnrichmentRegistry: asset/identity/network/threat-intel context.
        self.enrichment = enrichment

    def investigate(self, incident: Incident, findings: list[Finding], decision_override: dict[str, Any] | None = None) -> Investigation:
        related = [finding for finding in findings if finding.finding_id in incident.finding_ids]
        audit: list[str] = [f"investigation_started incident={incident.incident_id}"]
        evidence = self._collect_evidence(incident, related, audit)
        # Tasks publish structured output here; the case note is written to the
        # incident comment thread later, once the incident row exists.
        outputs: dict[str, Any] = {}
        tasks = self._build_and_execute_tasks(incident, related, evidence, audit, outputs)
        confidence = self._estimate_confidence(incident, related)
        if decision_override:
            decision = self._make_decision(incident, related, confidence, override=decision_override)
            audit.append(f"decision_from_llm value={decision.decision_type.value} confidence={decision.confidence:.2f}")
        else:
            decision = self._make_decision(incident, related, confidence)
        proposals = self._propose_actions(incident, related, decision, decision.confidence, audit)
        status = "needs_approval" if any(item.approval_required for item in proposals) else "completed"
        audit.append(f"investigation_completed status={status} decision={decision.decision_type.value} confidence={confidence:.2f}")
        return Investigation(
            investigation_id=str(uuid4()),
            incident_id=incident.incident_id,
            status=status,
            created_at=datetime.now(timezone.utc),
            tasks=tasks,
            evidence=evidence,
            decision=decision,
            action_proposals=proposals,
            audit_log=audit,
            case_note=outputs.get("case_note"),
        )

    def _collect_evidence(self, incident: Incident, findings: list[Finding], audit: list[str]) -> list[Evidence]:
        evidence: list[Evidence] = []
        evidence.append(
            Evidence(
                evidence_id=str(uuid4()),
                kind="incident_summary",
                source="autosiem.incident_builder",
                summary=incident.summary,
                data={
                    "severity": incident.severity.name.lower(),
                    "risk_score": incident.risk_score,
                    "entities": incident.entities,
                    "mitre_attack": incident.mitre_attack,
                },
            )
        )
        audit.append("evidence_collected kind=incident_summary")
        for finding in findings:
            event = finding.evidence.get("event", {})
            evidence.append(
                Evidence(
                    evidence_id=str(uuid4()),
                    kind="finding",
                    source=f"rule:{finding.rule_id}",
                    summary=f"{finding.rule_name} on event {finding.event_id}",
                    data={
                        "rule_id": finding.rule_id,
                        "rule_name": finding.rule_name,
                        "severity": finding.severity.name.lower(),
                        "risk_points": finding.risk_points,
                        "mitre_attack": finding.mitre_attack,
                        "event": event,
                    },
                )
            )
        audit.append(f"evidence_collected kind=finding count={len(findings)}")
        return evidence

    def _build_and_execute_tasks(
        self,
        incident: Incident,
        findings: list[Finding],
        evidence: list[Evidence],
        audit: list[str],
        outputs: dict[str, Any],
    ) -> list[AnalystTask]:
        # Order matters: the case note summarizes the evidence the earlier tasks
        # produce, so it runs last.
        planned = [
            ("Gather related events", "search_related_events", "Find telemetry around the same entities."),
            ("Enrich entities", "enrich_entities", "Collect context for users, hosts, IPs, cloud accounts."),
            ("Link duplicate alerts", "link_duplicate_alerts", "Group repeated findings into the incident."),
            ("Write case note", "create_case_note", "Persist AI triage notes for analyst review."),
        ]
        tasks: list[AnalystTask] = []
        for name, action, rationale in planned:
            allowed, approval_required, reason = self.policy.decision_for_action(action, confidence=1.0)
            if allowed:
                status = TaskStatus.COMPLETED
                result = self._execute_task(action, incident, findings, evidence, audit, outputs)
                audit.append(f"task_executed action={action} status=completed")
            elif approval_required:
                status = TaskStatus.NEEDS_APPROVAL
                result = None
                audit.append(f"task_blocked action={action} status=needs_approval reason={reason}")
            else:
                status = TaskStatus.BLOCKED
                result = None
                audit.append(f"task_blocked action={action} status=blocked reason={reason}")
            tasks.append(
                AnalystTask(
                    task_id=str(uuid4()),
                    name=name,
                    action=action,
                    status=status,
                    rationale=rationale,
                    result=result,
                    approval_required=approval_required,
                    policy_reason=reason,
                )
            )
        return tasks

    def _execute_task(
        self,
        action: str,
        incident: Incident,
        findings: list[Finding],
        evidence: list[Evidence],
        audit: list[str],
        outputs: dict[str, Any],
    ) -> str:
        if action == "search_related_events":
            return self._search_related_events(incident, findings, evidence, audit)
        if action == "enrich_entities":
            return self._enrich_entities(incident, evidence, audit)
        if action == "create_case_note":
            return self._create_case_note(incident, findings, evidence, audit, outputs)
        if action == "link_duplicate_alerts":
            return self._link_duplicate_alerts(incident, findings, evidence, audit)
        return "Action completed."

    def _enrich_entities(self, incident: Incident, evidence: list[Evidence], audit: list[str]) -> str:
        """Build context for each entity from local telemetry.

        No external reputation services are involved. What the event store
        already knows about an entity - how long it has been active, how much
        it does, and how varied that activity is - is genuine triage context:
        a brand-new account doing many distinct things reads very differently
        from a long-established one.
        """
        external = self._external_context(incident, evidence, audit)
        if self.event_search is None:
            if external:
                return external
            return "No event store configured, so entities could not be enriched from local telemetry."

        profiles: list[dict[str, Any]] = []
        for entity in incident.entities:
            try:
                rows = self.event_search.search_events(
                    entity=entity, limit=self.related_event_limit, tenant_id=self.tenant_id
                )
            except Exception as exc:
                audit.append(f"task_error action=enrich_entities entity={entity} error={type(exc).__name__}")
                continue
            if not rows:
                profiles.append({"entity": entity, "known": False, "event_count": 0})
                continue
            timestamps = sorted(str(row.get("timestamp", "")) for row in rows if row.get("timestamp"))
            actions = sorted({str(row.get("action", "")) for row in rows if row.get("action")})
            categories = sorted({str(row.get("category", "")) for row in rows if row.get("category")})
            profiles.append(
                {
                    "entity": entity,
                    "known": True,
                    "event_count": len(rows),
                    "first_seen": timestamps[0] if timestamps else None,
                    "last_seen": timestamps[-1] if timestamps else None,
                    "distinct_actions": len(actions),
                    "actions": actions[:10],
                    "categories": categories,
                }
            )

        if not profiles:
            return "Entity enrichment found no local context for this incident's entities."

        known = [profile for profile in profiles if profile["known"]]
        unknown = [profile for profile in profiles if not profile["known"]]
        evidence.append(
            Evidence(
                evidence_id=str(uuid4()),
                kind="entity_context",
                source="autosiem.storage",
                summary=f"Local context for {len(profiles)} entit{'y' if len(profiles) == 1 else 'ies'}",
                data={"profiles": profiles},
            )
        )
        audit.append(f"task_executed action=enrich_entities entities={len(profiles)} known={len(known)}")

        parts = [f"Enriched {len(profiles)} entit{'y' if len(profiles) == 1 else 'ies'} from local telemetry."]
        if known:
            busiest = max(known, key=lambda profile: int(profile["event_count"]))
            parts.append(
                f"Busiest: {busiest['entity']} with {busiest['event_count']} event(s) "
                f"across {busiest['distinct_actions']} distinct action(s)."
            )
        if unknown:
            names = ", ".join(str(profile["entity"]) for profile in unknown[:5])
            parts.append(f"No prior history for {len(unknown)} entit{'y' if len(unknown) == 1 else 'ies'} ({names}) - first observation.")
        if external:
            parts.append(external)
        else:
            parts.append("No asset, identity or threat-intel enrichment sources are configured.")
        return " ".join(parts)

    def _external_context(
        self, incident: Incident, evidence: list[Evidence], audit: list[str]
    ) -> str:
        """Asset, identity, network and threat-intel context for the entities.

        Returns a one-line summary and attaches the full context as evidence.
        Empty string when no enricher knows anything about this incident.
        """
        if self.enrichment is None:
            return ""
        try:
            context = self.enrichment.context_for(incident.entities)
        except Exception as exc:
            audit.append(f"task_error action=enrich_entities stage=external error={type(exc).__name__}")
            return ""
        if not context:
            return ""

        sources: list[str] = []
        criticalities: list[str] = []
        tags: list[str] = []
        for contexts in context.values():
            for item in contexts:
                if item["source"] not in sources:
                    sources.append(item["source"])
                if item.get("criticality"):
                    criticalities.append(str(item["criticality"]))
                for tag in item.get("tags") or []:
                    if tag not in tags:
                        tags.append(str(tag))

        evidence.append(
            Evidence(
                evidence_id=str(uuid4()),
                kind="entity_enrichment",
                source="autosiem.enrichment",
                summary=f"{len(context)} entit{'y' if len(context) == 1 else 'ies'} enriched from {', '.join(sources)}",
                data={"context": context, "sources": sources, "tags": tags},
            )
        )
        audit.append(
            f"task_executed action=enrich_entities stage=external entities={len(context)} sources={len(sources)}"
        )

        summary = (
            f"Enrichment matched {len(context)} entit{'y' if len(context) == 1 else 'ies'} "
            f"from {', '.join(sources)}."
        )
        highest = _highest_label(criticalities)
        if highest:
            summary += f" Highest asset/identity criticality: {highest}."
        if tags:
            summary += f" Tags: {', '.join(tags[:8])}."
        return summary

    def _link_duplicate_alerts(
        self,
        incident: Incident,
        findings: list[Finding],
        evidence: list[Evidence],
        audit: list[str],
    ) -> str:
        """Group repeated findings so an analyst reads N clusters, not N alerts.

        A duplicate here means the same rule firing on the same entity more than
        once inside the incident - the classic noisy-detection shape.
        """
        clusters: dict[tuple[str, str], list[Finding]] = {}
        for finding in findings:
            entity = finding.entities[0] if finding.entities else "global:unknown"
            clusters.setdefault((finding.rule_id, entity), []).append(finding)

        duplicates = {key: group for key, group in clusters.items() if len(group) > 1}
        audit.append(
            f"task_executed action=link_duplicate_alerts findings={len(findings)} "
            f"clusters={len(clusters)} duplicate_clusters={len(duplicates)}"
        )
        if not duplicates:
            return f"{len(findings)} finding(s) resolved to {len(clusters)} distinct rule/entity pair(s); no duplicates to link."

        linked = sorted(
            (
                {
                    "rule_id": rule_id,
                    "rule_name": group[0].rule_name,
                    "entity": entity,
                    "count": len(group),
                    "finding_ids": [item.finding_id for item in group],
                    "first_seen": min(item.timestamp for item in group).isoformat(),
                    "last_seen": max(item.timestamp for item in group).isoformat(),
                }
                for (rule_id, entity), group in duplicates.items()
            ),
            key=lambda item: (-int(item["count"]), str(item["rule_id"])),
        )
        collapsed = sum(int(item["count"]) for item in linked) - len(linked)
        evidence.append(
            Evidence(
                evidence_id=str(uuid4()),
                kind="duplicate_alerts",
                source="autosiem.incident_builder",
                summary=f"{len(linked)} repeated rule/entity pair(s) collapsing {collapsed} finding(s)",
                data={"clusters": linked, "collapsed": collapsed},
            )
        )
        top = ", ".join(f"{item['rule_id']} on {item['entity']} x{item['count']}" for item in linked[:3])
        return (
            f"{len(findings)} finding(s) resolved to {len(clusters)} distinct rule/entity pair(s). "
            f"Linked {len(linked)} repeated pair(s), collapsing {collapsed} duplicate finding(s): {top}."
        )

    def _create_case_note(
        self,
        incident: Incident,
        findings: list[Finding],
        evidence: list[Evidence],
        audit: list[str],
        outputs: dict[str, Any],
    ) -> str:
        """Draft the triage note that gets written to the incident comment thread.

        The note is stored on the Investigation rather than written here: at this
        point in the pipeline the incident row does not exist yet, so the write
        happens in ``AutoSIEMStorage.save_pipeline_result`` once it does.
        """
        top_rules = sorted(
            {finding.rule_name for finding in findings if not finding.rule_id.startswith("builtin-anomaly")}
        )[:5]
        anomalies = [finding for finding in findings if finding.rule_id.startswith("builtin-anomaly")]
        lines = [
            f"AI triage note for {incident.title}",
            "",
            f"Risk {incident.risk_score} / severity {incident.severity.name.lower()} "
            f"from {len(findings)} finding(s) across {len(incident.entities)} entit"
            f"{'y' if len(incident.entities) == 1 else 'ies'}.",
        ]
        if incident.mitre_attack:
            lines.append(f"ATT&CK progression: {' -> '.join(incident.mitre_attack)}.")
        if top_rules:
            lines.append("Detections: " + "; ".join(top_rules) + ".")
        if anomalies:
            signal_names = sorted(
                {
                    str(signal.get("signal"))
                    for finding in anomalies
                    for signal in finding.evidence.get("signals", [])
                    if signal.get("signal")
                }
            )
            if signal_names:
                lines.append(f"Behavioral signals: {', '.join(signal_names)}.")
        context = [item for item in evidence if item.kind in {"related_events", "entity_context", "duplicate_alerts"}]
        for item in context:
            lines.append(f"Context: {item.summary}.")
        lines.append(f"Entities: {', '.join(incident.entities)}.")
        note = "\n".join(lines)
        audit.append(f"task_executed action=create_case_note length={len(note)}")
        outputs["case_note"] = note
        return f"Case note drafted ({len(note)} chars) for {incident.title}; queued for the incident comment thread."

    def _search_related_events(
        self,
        incident: Incident,
        findings: list[Finding],
        evidence: list[Evidence],
        audit: list[str],
    ) -> str:
        """Pivot from the incident to everything else known about its entities.

        Without a configured event store this reports what the incident already
        holds. With one, it queries stored telemetry per entity and attaches the
        events that are *not* already part of this incident, which is the
        "what else did this user do?" question an analyst asks first.
        """
        base = f"{len(findings)} directly related finding(s) across {len(incident.entities)} entit{'y' if len(incident.entities) == 1 else 'ies'}."
        if self.event_search is None:
            return f"{base} No event store configured, so no historical lookup was performed."

        known_event_ids = {finding.event_id for finding in findings}
        seen: set[str] = set()
        related: list[dict[str, Any]] = []
        counts: list[tuple[str, int]] = []
        searched = 0

        for entity in incident.entities:
            try:
                rows = self.event_search.search_events(
                    entity=entity, limit=self.related_event_limit, tenant_id=self.tenant_id
                )
            except Exception as exc:  # a broken store must not abort the investigation
                audit.append(f"task_error action=search_related_events entity={entity} error={type(exc).__name__}")
                continue
            searched += 1
            # Count per entity independently: one event usually involves several
            # entities, so deduping here would credit it to whichever entity was
            # queried first and report 0 for the others.
            entity_total = 0
            for row in rows:
                event_id = str(row.get("event_id", ""))
                if not event_id or event_id in known_event_ids:
                    continue
                entity_total += 1
                if event_id not in seen:
                    seen.add(event_id)
                    related.append(row)
            if entity_total:
                counts.append((entity, entity_total))

        # Busiest entity first: that is where an analyst pivots next.
        counts.sort(key=lambda item: (-item[1], item[0]))
        per_entity = [f"{entity} {total}" for entity, total in counts]

        audit.append(f"task_executed action=search_related_events entities={searched} related_events={len(related)}")
        if not related:
            return f"{base} Queried {searched} entit{'y' if searched == 1 else 'ies'} against the event store; no prior events outside this incident."

        capped = related[: self.related_event_limit]
        evidence.append(
            Evidence(
                evidence_id=str(uuid4()),
                kind="related_events",
                source="autosiem.storage",
                summary=f"{len(related)} prior event(s) involving this incident's entities",
                data={
                    "total": len(related),
                    "returned": len(capped),
                    "per_entity": per_entity,
                    "events": capped,
                },
            )
        )
        return (
            f"{base} Queried {searched} entit{'y' if searched == 1 else 'ies'} against the event store and found "
            f"{len(related)} distinct prior event(s) outside this incident. "
            f"Per entity (events can involve several, so these overlap): {', '.join(per_entity)}."
        )

    def _estimate_confidence(self, incident: Incident, findings: list[Finding]) -> float:
        score = 0.20
        if incident.risk_score >= 200:
            score += 0.25
        elif incident.risk_score >= 100:
            score += 0.15
        if incident.severity >= Severity.HIGH:
            score += 0.20
        if incident.mitre_attack:
            score += 0.15
        if len(findings) >= 3:
            score += 0.10
        if any(finding.rule_id.startswith("builtin-anomaly") for finding in findings):
            score += 0.10
        return min(score, 0.99)

    def _make_decision(self, incident: Incident, _findings: list[Finding], confidence: float, override: dict[str, Any] | None = None) -> AnalystDecision:
        if override:
            return self._decision_from_override(override, confidence)
        if incident.severity >= Severity.HIGH and incident.risk_score >= 200:
            decision_type = DecisionType.CONTAINMENT_PROPOSED
            owner = "tier-2-incident-responder"
            rationale = "High severity plus high aggregate risk suggests active investigation and containment review."
        elif incident.risk_score >= 100 or incident.severity >= Severity.MEDIUM:
            decision_type = DecisionType.ESCALATE
            owner = "tier-2-analyst"
            rationale = "Moderate or higher risk requires analyst validation and broader scoping."
        elif incident.risk_score >= 30:
            decision_type = DecisionType.SUSPICIOUS_MONITOR
            owner = "tier-1-queue"
            rationale = "Low-to-moderate risk should remain monitored with context preserved."
        else:
            decision_type = DecisionType.LIKELY_BENIGN
            owner = "tier-1-queue"
            rationale = "Low risk and limited evidence indicates likely benign activity."
        return AnalystDecision(
            decision_id=str(uuid4()),
            decision_type=decision_type,
            confidence=confidence,
            rationale=rationale,
            recommended_owner=owner,
        )

    def _decision_from_override(self, override: dict[str, Any], fallback_confidence: float) -> AnalystDecision:
        raw_type = str(override.get("decision_type", DecisionType.SUSPICIOUS_MONITOR.value)).strip().lower()
        try:
            decision_type = DecisionType(raw_type)
        except ValueError:
            decision_type = DecisionType.SUSPICIOUS_MONITOR
        try:
            confidence = float(override.get("confidence", fallback_confidence))
        except (TypeError, ValueError):
            confidence = fallback_confidence
        confidence = max(min(confidence, 1.0), 0.0)
        return AnalystDecision(
            decision_id=str(uuid4()),
            decision_type=decision_type,
            confidence=confidence,
            rationale=str(override.get("rationale", "LLM-provided decision.")),
            recommended_owner=str(override.get("recommended_owner", "tier-2-analyst")),
        )

    def _propose_actions(
        self,
        incident: Incident,
        _findings: list[Finding],
        decision: AnalystDecision,
        confidence: float,
        audit: list[str],
    ) -> list[ActionProposal]:
        proposed: list[tuple[str, str, str]] = []
        if decision.decision_type == DecisionType.CONTAINMENT_PROPOSED:
            for entity in incident.entities:
                if entity.startswith("user:"):
                    proposed.append(("disable_user", entity, "Potential compromised identity; disable or force reset after approval."))
                if entity.startswith("host:") and "vpn" not in entity.lower():
                    proposed.append(("isolate_host", entity, "Endpoint is associated with high-risk execution activity."))
                if entity.startswith("ip:"):
                    proposed.append(("block_indicator", entity, "Source IP appears in suspicious incident context."))
        elif decision.decision_type == DecisionType.ESCALATE:
            proposed.append(("notify_channel", "soc-escalations", "Notify escalation channel with investigation summary."))

        proposals: list[ActionProposal] = []
        for action, target, rationale in proposed:
            executable, approval_required, reason = self.policy.decision_for_action(action, confidence)
            proposals.append(
                ActionProposal(
                    proposal_id=str(uuid4()),
                    action=action,
                    target=target,
                    rationale=rationale,
                    confidence=confidence,
                    approval_required=approval_required,
                    executable_now=executable,
                    policy_reason=reason,
                )
            )
            audit.append(f"action_proposed action={action} target={target} executable={executable} approval_required={approval_required} confidence={confidence:.2f}")
        return proposals

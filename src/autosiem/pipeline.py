from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from .ai import Investigator
from .anomaly import AnomalyDetector, BaselineState, BaselineStore
from .detection import evaluate_rules
from .enrichment import EnrichmentRegistry
from .feedback import FeedbackEngine
from .llm import LLMService
from .normalization import normalize, parse_raw_line
from .policy import base_technique, classify_target
from .rag import RagEngine
from .risk import build_incidents
from .rules import load_rules
from .schemas import DetectionRule, Finding, Incident, NormalizedEvent
from .soar import SoarPlanner
from .soc_runtime import AIAnalystRuntime, ActionProposal, EventSearcher, Investigation
from .suppression import SuppressionEngine
from .threat_intel import ThreatIntelMatcher


def _dedup_key(target: str) -> str:
    """Dedup identity for a proposal target.

    Sub-techniques collapse onto their parent (T1059.001 -> T1059) so one
    runbook is not applied twice. Everything else is compared verbatim: an IP
    contains dots too, and 198.51.100.25 must stay distinct from .55.
    """
    if classify_target(target) == "technique":
        return base_technique(target)
    return target


@dataclass(slots=True)
class PipelineResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    reports: dict[str, str] = field(default_factory=dict)
    investigations: dict[str, Investigation] = field(default_factory=dict)
    suppressed: list[dict[str, Any]] = field(default_factory=list)
    #: Incident IDs whose report actually came from a language model. Recorded
    #: from the call itself rather than inferred from the audit log, so a
    #: configured-but-failing backend is never reported as "used an LLM".
    llm_reports: set[str] = field(default_factory=set)


class AutoSIEMPipeline:
    def __init__(
        self,
        rules: list[DetectionRule],
        anomaly_detector: AnomalyDetector | None = None,
        llm: LLMService | None = None,
        suppression_engine: SuppressionEngine | None = None,
        threat_intel: ThreatIntelMatcher | None = None,
        rag: RagEngine | None = None,
        soar: SoarPlanner | None = None,
        feedback: FeedbackEngine | None = None,
        event_search: EventSearcher | None = None,
        tenant_id: str | None = None,
        baseline_store: BaselineStore | None = None,
        enrichment: EnrichmentRegistry | None = None,
    ) -> None:
        self.rules = rules
        self.baseline_store = baseline_store
        self.tenant_id = tenant_id
        self.enrichment = enrichment
        self.anomaly_detector = anomaly_detector or self._load_detector()
        self.investigator = Investigator()
        # Passing an event store lets the analyst runtime's search_related_events
        # task run a real historical query instead of describing one.
        self.analyst_runtime = AIAnalystRuntime(
            event_search=event_search, tenant_id=tenant_id, enrichment=enrichment
        )
        self.llm = llm
        self.suppression_engine = suppression_engine
        self.threat_intel = threat_intel
        self.rag = rag
        self.soar = soar
        self.feedback = feedback

    def _load_detector(self) -> AnomalyDetector:
        """Resume the stored behavioral baseline, or start a fresh one."""
        if self.baseline_store is None:
            return AnomalyDetector()
        try:
            state = self.baseline_store.load_baseline(tenant_id=self.tenant_id)
        except Exception:  # a broken baseline must not stop detection
            return AnomalyDetector()
        if not state:
            return AnomalyDetector()
        try:
            return AnomalyDetector(BaselineState.from_dict(state))
        except Exception:
            return AnomalyDetector()

    def _persist_baseline(self) -> None:
        """Write the updated baseline back so the next run starts warm."""
        if self.baseline_store is None:
            return
        try:
            self.baseline_store.save_baseline(
                self.anomaly_detector.state.to_dict(), tenant_id=self.tenant_id
            )
        except Exception as exc:
            # Losing a baseline update is recoverable; failing the run is not.
            logging.getLogger(__name__).warning("Behavioral baseline update not saved (%s)", type(exc).__name__)

    def process_lines(self, lines: list[str]) -> PipelineResult:
        result = PipelineResult()
        for line in lines:
            if not line.strip():
                continue
            event = normalize(parse_raw_line(line))
            result.events.append(event)
            result.findings.extend(evaluate_rules(event, self.rules))
            if self.threat_intel:
                result.findings.extend(self.threat_intel.findings_for(event))
            anomaly_finding = self.anomaly_detector.finding_for_event(event)
            if anomaly_finding:
                result.findings.append(anomaly_finding)
        if self.suppression_engine:
            result.findings, result.suppressed = self.suppression_engine.apply(result.findings)
        if self.feedback:
            # Analyst feedback lowers the effective risk of distrusted rules
            # before incidents are built, so noisy rules contribute less.
            for finding in result.findings:
                adjusted = self.feedback.adjusted_risk(finding)
                if adjusted != finding.risk_points:
                    finding.risk_points = adjusted
        if self.enrichment:
            # Asset and identity criticality scale risk before incidents are
            # built, so the same detection on a crown-jewel host outranks it on
            # a spare laptop. Unenriched entities score exactly as before.
            for finding in result.findings:
                adjusted = self.enrichment.adjusted_risk(finding.risk_points, finding.entities)
                if adjusted != finding.risk_points:
                    finding.risk_points = adjusted
        result.incidents = build_incidents(result.findings)
        for incident in result.incidents:
            related = [finding for finding in result.findings if finding.finding_id in incident.finding_ids]
            rag_context = self.rag.build_prompt(incident) if self.rag else ""
            if self.llm and self.llm.enabled:
                annotation = self.llm.annotate(incident, related, extra_context=rag_context)
                report = annotation.report
                decision_override = annotation.decision
                # A backend being configured is not evidence one was used: the
                # call can fail and fall back to the local investigator.
                if annotation.used_llm:
                    result.llm_reports.add(incident.incident_id)
            else:
                report = self.investigator.explain(incident, result.findings)
                if rag_context:
                    report = f"{report}\n\n{rag_context}"
                decision_override = None
            result.reports[incident.incident_id] = report
            investigation = self.analyst_runtime.investigate(
                incident, result.findings, decision_override=decision_override
            )
            if self.soar:
                investigation = self._apply_soar_plan(investigation, incident, related)
            result.investigations[incident.incident_id] = investigation
        self._persist_baseline()
        return result

    def _apply_soar_plan(
        self, investigation: Investigation, incident: Incident, findings: list[Finding]
    ) -> Investigation:
        """Merge approval-gated SOAR runbook steps into the investigation.

        Steps are appended as ``ActionProposal`` objects (deduped against what
        the runtime already proposed) so they flow through the same persistence
        and UI approval workflow. Each step carries the target the planner
        resolved; it is re-checked against the action's declared target kinds
        here so nothing reaches the approval queue pointed at the wrong kind of
        thing, whatever produced the plan.
        """
        if self.soar is None:
            return investigation
        plan = self.soar.recommend(incident, findings)
        policy = self.soar.policy
        for drop in self.soar.dropped:
            investigation.audit_log.append(
                f"soar_step_dropped action={drop['action']} technique={drop['technique']} "
                f"reason={drop['reason']}"
            )
        if not plan:
            return investigation

        existing = {
            (proposal.action, _dedup_key(proposal.target))
            for proposal in investigation.action_proposals
        }
        added: list[ActionProposal] = []
        for step in plan:
            action = str(step.get("action", ""))
            target = str(step.get("target", "")).strip()
            valid, reason = policy.validate_target(action, target)
            if not valid:
                investigation.audit_log.append(
                    f"soar_step_rejected action={action} target={target or '<none>'} reason={reason}"
                )
                continue
            key = (action, _dedup_key(target))
            if key in existing:
                continue
            proposal = ActionProposal(
                proposal_id=str(uuid4()),
                action=action,
                target=target,
                rationale=str(step.get("description", "Recommended by SOAR runbook plan.")),
                confidence=round(float(step.get("confidence", 0.8)), 2),
                approval_required=bool(step.get("approval_required", True)),
                executable_now=bool(step.get("allowed", False)),
                policy_reason=str(step.get("description", "SOAR runbook step.")),
            )
            investigation.action_proposals.append(proposal)
            existing.add(key)
            added.append(proposal)
        if added:
            investigation.audit_log.append(f"soar_plan_applied proposals={len(added)}")
            if any(proposal.approval_required for proposal in added):
                investigation.status = "needs_approval"
        return investigation

    @classmethod
    def from_rule_path(cls, path: str | Path, llm: LLMService | None = None, suppression_engine: SuppressionEngine | None = None, threat_intel: ThreatIntelMatcher | None = None) -> "AutoSIEMPipeline":
        return cls(load_rules(path), llm=llm, suppression_engine=suppression_engine, threat_intel=threat_intel)


def process_jsonl_file(event_path: str | Path, rule_path: str | Path, llm: LLMService | None = None, suppression_engine: SuppressionEngine | None = None, threat_intel: ThreatIntelMatcher | None = None) -> PipelineResult:
    lines = Path(event_path).read_text(encoding="utf-8").splitlines()
    return AutoSIEMPipeline.from_rule_path(rule_path, llm=llm, suppression_engine=suppression_engine, threat_intel=threat_intel).process_lines(lines)

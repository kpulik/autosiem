"""The security questions AutoSIEM asks a System One model, and the state it sends.

Both live here rather than being spread across call sites: the wording of a
detection question is security content, it is reviewed like a rule, and two
providers must be asked exactly the same thing or the evaluation harness is
comparing prompts instead of models.

Privacy: :func:`build_state` is a whitelist, not a filter. Only named,
security-relevant fields are copied out of an event, and every string that
reaches a provider goes through the existing :mod:`autosiem.redaction`
redactor. Jev is a remote service; Laya can run entirely on the host.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ..redaction import Redactor, default_redactor
from ..schemas import Finding, Incident
from .types import CHOICE, NOUL, DecisionQuestion, DecisionState

SEVERITY_LEVELS = ("informational", "low", "medium", "high", "critical")
ACTIONS = ("suppress", "monitor", "enrich", "investigate", "escalate")

#: The questions. Keep them short, concrete and about observable evidence: a
#: System One model reads the state, it does not reason at length about it.
SECURITY_QUESTIONS: dict[str, DecisionQuestion] = {
    "malicious": DecisionQuestion(
        type=NOUL,
        instructions=(
            "Is this correlated security incident likely malicious or genuinely "
            "security-relevant, rather than benign or expected activity?"
        ),
        criteria={
            "true": "Evidence of attacker behaviour, misuse, or activity a SOC analyst should act on.",
            "false": "Expected administration, automation, or routine user behaviour.",
        },
    ),
    "severity": DecisionQuestion(
        type=CHOICE,
        instructions="How severe is this incident for the affected organisation?",
        criteria={
            "informational": "No impact; recorded for context only.",
            "low": "Minor or isolated; no privileged access or sensitive data involved.",
            "medium": "Real but contained; a single account or host, no confirmed impact.",
            "high": "Privileged access, credential theft, lateral movement, or a crown-jewel asset.",
            "critical": "Active damage or organisation-wide impact: ransomware, destruction, mass exfiltration.",
        },
    ),
    "action": DecisionQuestion(
        type=CHOICE,
        instructions="What should a SOC analyst do with this incident next?",
        criteria={
            "suppress": "Known-benign pattern; close without work.",
            "monitor": "Keep under observation; no action yet.",
            "enrich": "Needs more context (asset, identity, intel) before judging.",
            "investigate": "A human analyst should work this case now.",
            "escalate": "Needs immediate response or incident-response handoff.",
        },
    ),
    "needs_llm_analysis": DecisionQuestion(
        type=NOUL,
        instructions=(
            "Is this incident ambiguous or complex enough that a slower generative "
            "model should write a full narrative analysis of it?"
        ),
        criteria={
            "true": "Mixed or conflicting signals, an unusual chain of behaviour, or a judgement call.",
            "false": "A clear-cut case the deterministic detection output already explains.",
        },
    ),
}

#: Raw event fields worth sending. Everything else in ``raw`` stays local: a raw
#: log line can carry session tokens, Authorization headers or request bodies.
RAW_FIELD_WHITELIST = (
    "process_name",
    "command_line",
    "parent_process",
    "url",
    "file_path",
    "event_name",
    "error_code",
    "user_agent",
    "rule_name",
)

#: Never copy a field whose name looks like a secret, even from the whitelist.
_SECRET_HINTS = ("token", "secret", "password", "passwd", "credential", "api_key", "apikey", "authorization", "cookie", "session")


def _looks_secret(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SECRET_HINTS)


def _clean(value: Any, redactor: Redactor) -> Any:
    """Redact strings; pass numbers and bools through; drop anything else."""
    if isinstance(value, str):
        return redactor.redact(value)
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    return None


def _ueba_signals(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    """The named UEBA signals behind this incident, with their points."""
    signals: list[dict[str, Any]] = []
    for finding in findings:
        evidence = finding.evidence if isinstance(finding.evidence, Mapping) else {}
        for signal in evidence.get("signals", []) or []:
            if not isinstance(signal, Mapping):
                continue
            signals.append(
                {
                    "signal": signal.get("signal"),
                    "entity": signal.get("entity"),
                    "points": signal.get("points"),
                    "detail": signal.get("detail"),
                }
            )
    return signals


def build_state(
    incident: Incident,
    findings: Iterable[Finding],
    *,
    events: Iterable[Any] = (),
    redactor: Redactor | None = None,
    max_findings: int = 20,
    max_events: int = 10,
    prior_activity: Mapping[str, Any] | None = None,
) -> DecisionState:
    """Build the evidence bundle for one incident.

    Summarised, not dumped: counts and named signals instead of whole log lines,
    capped lists, and only whitelisted raw fields. ``prior_activity`` is an
    optional caller-supplied summary of earlier behaviour for these entities.
    """
    redactor = redactor or default_redactor()
    related = list(findings)[:max_findings]
    signals = _ueba_signals(related)
    signal_names = {signal["signal"] for signal in signals if signal.get("signal")}

    state: DecisionState = {
        "incident": {
            "title": redactor.redact(incident.title),
            "summary": redactor.redact(incident.summary),
            # The deterministic engine's own verdict. The model is being asked to
            # comment on this, so it has to see it.
            "deterministic_severity": incident.severity.name.lower(),
            "deterministic_risk_score": incident.risk_score,
            "created_at": incident.created_at.isoformat(),
            "entities": [redactor.redact(entity) for entity in incident.entities],
            "mitre_attack": list(incident.mitre_attack),
            "finding_count": len(incident.finding_ids),
        },
        "correlation": {
            # build_incidents links findings through a shared entity inside a
            # 24h window, so the entity spread is the graph context that matters.
            "entity_count": len(incident.entities),
            "entity_kinds": sorted({entity.split(":", 1)[0] for entity in incident.entities if ":" in entity}),
            "distinct_rules": sorted({finding.rule_id for finding in related}),
            "tactics": list(incident.mitre_attack),
        },
        "ueba": {
            "signals": signals,
            "signal_names": sorted(signal_names),
            "novelty": sorted(name for name in signal_names if str(name).startswith("novel_")),
            "off_hours": "off_hours" in signal_names,
            "rare_action": "rare_action" in signal_names,
            "peer_rare": "peer_rare" in signal_names,
            "burst": "burst" in signal_names,
            "total_points": sum(int(signal.get("points") or 0) for signal in signals),
        },
        "findings": [
            {
                "rule_id": finding.rule_id,
                "rule_name": redactor.redact(finding.rule_name),
                "severity": finding.severity.name.lower(),
                "risk_points": finding.risk_points,
                "mitre_attack": list(finding.mitre_attack),
                "timestamp": finding.timestamp.isoformat(),
                "entities": [redactor.redact(entity) for entity in finding.entities],
            }
            for finding in related
        ],
    }

    observed: list[dict[str, Any]] = []
    for event in list(events)[:max_events]:
        summary: dict[str, Any] = {
            "category": getattr(event, "category", None),
            "action": getattr(event, "action", None),
            "outcome": getattr(getattr(event, "outcome", None), "value", getattr(event, "outcome", None)),
            "timestamp": getattr(getattr(event, "timestamp", None), "isoformat", lambda: None)(),
        }
        raw = getattr(event, "raw", None)
        if isinstance(raw, Mapping):
            for field_name in RAW_FIELD_WHITELIST:
                if _looks_secret(field_name) or field_name not in raw:
                    continue
                cleaned = _clean(raw[field_name], redactor)
                if cleaned is not None:
                    summary[field_name] = cleaned
        observed.append({key: value for key, value in summary.items() if value is not None})
    if observed:
        state["events"] = observed
    if prior_activity:
        state["prior_activity"] = {
            key: _clean(value, redactor) for key, value in prior_activity.items() if _clean(value, redactor) is not None
        }
    return state

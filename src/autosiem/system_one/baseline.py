"""The existing AutoSIEM decision path, expressed as a comparable provider.

So the evaluation harness can score the deterministic engine on the same cases,
with the same question set, instead of treating it as ground truth. It reads only
what the deterministic stages already produced (severity, risk score, UEBA
signals) and applies the mapping the CLI and UI already imply.

Honest about what it is: a **rule**, not a calibrated model. The confidences it
reports are a documented monotone function of risk score, not probabilities
learned from outcomes, so a poor calibration error here is the expected result
and not a bug. It is reported anyway, because a model that cannot beat a rule's
calibration is not earning its place in the path.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from ..schemas import Severity
from .types import CHOICE, NOUL, DecisionAnswer, DecisionResult, DecisionState

PROVIDER_NAME = "autosiem"
MODEL_NAME = "deterministic"

#: Risk score above which the deterministic path treats an incident as malicious.
MALICIOUS_RISK_FLOOR = 100

#: Severity to recommended action, matching how the incident queue is triaged.
_ACTION_BY_SEVERITY = {
    "critical": "escalate",
    "high": "investigate",
    "medium": "investigate",
    "low": "monitor",
    "informational": "suppress",
}


def _section(state: DecisionState, name: str) -> Mapping[str, Any]:
    """One top-level section of the state, or an empty mapping."""
    value = state.get(name)
    return value if isinstance(value, Mapping) else {}


def _risk_to_probability(risk_score: int) -> float:
    """Map risk score to a 0..1 number, saturating at 1000 (the demo maximum).

    Deliberately crude and deliberately documented: the deterministic engine
    produces an unbounded additive score, not a probability, and pretending
    otherwise is how a rule starts looking like a model.
    """
    if risk_score <= 0:
        return 0.02
    return max(0.02, min(0.98, risk_score / 500.0))


def decide(state: DecisionState) -> DecisionResult:
    """Answer the standard question set from deterministic fields alone."""
    started = time.perf_counter()
    incident = _section(state, "incident")
    ueba = _section(state, "ueba")

    severity = str(incident.get("deterministic_severity") or "informational").lower()
    if severity not in _ACTION_BY_SEVERITY:
        severity = "informational"
    try:
        risk_score = int(incident.get("deterministic_risk_score") or 0)
    except (TypeError, ValueError):
        risk_score = 0

    malicious_probability = _risk_to_probability(risk_score)
    if severity in ("high", "critical"):
        malicious_probability = max(malicious_probability, 0.9)
    elif risk_score >= MALICIOUS_RISK_FLOOR:
        malicious_probability = max(malicious_probability, 0.6)

    severity_confidence = _risk_to_probability(risk_score)
    action = _ACTION_BY_SEVERITY[severity]

    # The deterministic path has no notion of its own ambiguity, so it asks for
    # narrative analysis exactly where the existing pipeline would benefit: a
    # real incident that is not already unambiguous at the top of the scale.
    signal_count = len(ueba.get("signals") or [])
    needs_llm = 0.7 if severity in ("medium", "high") and signal_count > 1 else 0.2

    answers = {
        "malicious": DecisionAnswer(
            type=NOUL,
            selected=malicious_probability >= 0.5,
            probabilities={"true": malicious_probability, "false": round(1 - malicious_probability, 10)},
            confidence=None,
            value=malicious_probability,
        ),
        "severity": DecisionAnswer(
            type=CHOICE,
            selected=severity,
            probabilities={severity: severity_confidence},
            confidence=severity_confidence,
        ),
        "action": DecisionAnswer(
            type=CHOICE,
            selected=action,
            probabilities={action: severity_confidence},
            confidence=severity_confidence,
        ),
        "needs_llm_analysis": DecisionAnswer(
            type=NOUL,
            selected=needs_llm >= 0.5,
            probabilities={"true": needs_llm, "false": round(1 - needs_llm, 10)},
            confidence=None,
            value=needs_llm,
        ),
    }
    return DecisionResult(
        provider=PROVIDER_NAME,
        model=MODEL_NAME,
        answers=answers,
        latency_ms=(time.perf_counter() - started) * 1000,
        # Local arithmetic: no tokens, so the harness reports no cost rather
        # than a guessed one.
        usage={},
    )


def severity_from_name(name: str) -> Severity:
    """The Severity enum for a label, for callers comparing to engine output."""
    return Severity[name.upper()] if name.upper() in Severity.__members__ else Severity.INFORMATIONAL

"""The decision engine: choose a provider, fall back, threshold, record.

What this layer is allowed to do
--------------------------------
Produce an **advisory signal** next to the deterministic result, and record it.

What it is not allowed to do
----------------------------
Change a severity, approve an action, or shorten an approval path. The
deterministic detection engine and :mod:`autosiem.policy` stay authoritative,
so a compromised, hallucinating or simply wrong model cannot lower AutoSIEM's
guard. That is also why a failure here degrades to exactly the behaviour of a
deployment with no provider configured.

Three states are kept distinct, because collapsing them is how a decision layer
becomes a liability:

* **provider failed** - unreachable, timed out, malformed answer. Try the
  fallback, then give up quietly.
* **answered, but not confidently** - a real answer that is not worth acting on.
  This is *not* a failure, so it does not trigger fallback unless the operator
  explicitly enables that.
* **answered confidently** - accept it as one signal among several.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from ..metrics import MetricsRegistry
from ..redaction import Redactor
from ..schemas import Finding, Incident
from .config import PROVIDER_NONE, DecisionConfig, config_from_env
from .providers import DecisionProvider, Transport, build_provider
from .questions import SECURITY_QUESTIONS, build_state
from .types import (
    DecisionAnswer,
    DecisionConfigError,
    DecisionError,
    DecisionInvalid,
    DecisionQuestion,
    DecisionResult,
    DecisionState,
    DecisionUnavailable,
)

logger = logging.getLogger(__name__)

#: How much weight the engine puts on an answer.
DISPOSITION_ACCEPTED = "accepted"
DISPOSITION_REVIEW = "review"
DISPOSITION_IGNORED = "ignored"
DISPOSITION_UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class DecisionOutcome:
    """What the engine concluded for one incident.

    ``result`` is ``None`` when no provider answered. ``disposition`` says how
    much weight the answer carries; ``notes`` explains why, in words meant for
    an analyst reading the incident.
    """

    disposition: str
    result: DecisionResult | None = None
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    llm_escalated: bool = False

    @property
    def available(self) -> bool:
        return self.result is not None

    def answer(self, name: str) -> DecisionAnswer | None:
        return self.result.answer(name) if self.result else None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "disposition": self.disposition,
            "notes": list(self.notes),
            "errors": list(self.errors),
            "llm_escalated": self.llm_escalated,
        }
        if self.result is not None:
            payload.update(self.result.to_dict())
        return payload


class DecisionEngine:
    """Runs the System One step and keeps it inside its lane."""

    def __init__(
        self,
        config: DecisionConfig | None = None,
        *,
        providers: Mapping[str, DecisionProvider] | None = None,
        questions: Mapping[str, DecisionQuestion] | None = None,
        metrics: MetricsRegistry | None = None,
        redactor: Redactor | None = None,
        transport: Transport | None = None,
        laya_loader: Callable[[], Any] | None = None,
    ) -> None:
        self.config = config or config_from_env()
        self.questions = dict(questions or SECURITY_QUESTIONS)
        self.metrics = metrics or MetricsRegistry()
        self.redactor = redactor
        self._transport = transport
        self._laya_loader = laya_loader
        self._provided = dict(providers or {})
        self._cache: dict[str, DecisionProvider | None] = {}

    # -- provider plumbing -------------------------------------------------
    def _provider(self, name: str) -> DecisionProvider | None:
        """Build (and remember) a provider, or ``None`` if unconfigurable.

        A missing API key is a configuration problem, not a per-incident error:
        it is logged once and then the provider simply is not available.
        """
        if name == PROVIDER_NONE:
            return None
        if name in self._provided:
            return self._provided[name]
        if name in self._cache:
            return self._cache[name]
        try:
            provider = build_provider(
                name, self.config, transport=self._transport, laya_loader=self._laya_loader
            )
        except DecisionConfigError as exc:
            logger.warning("System One provider %s is not usable: %s", name, exc)
            provider = None
        self._cache[name] = provider
        return provider

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def _record(self, provider: str, outcome: str, latency_ms: float | None = None) -> None:
        self.metrics.counter("autosiem_system_one_requests_total", provider=provider, outcome=outcome).inc()
        if latency_ms is not None:
            self.metrics.histogram("autosiem_system_one_latency_ms", provider=provider).observe(latency_ms)

    def _ask(self, name: str, state: DecisionState) -> tuple[DecisionResult | None, str | None]:
        """One attempt. Returns ``(result, error)``; never raises."""
        provider = self._provider(name)
        if provider is None:
            return None, f"{name}: not configured"
        try:
            result = provider.decide(state, self.questions)
        except DecisionInvalid as exc:
            # Recorded separately from an outage: a malformed answer usually
            # means a schema or model change, and it must never be coerced into
            # a usable classification.
            self._record(name, "invalid")
            logger.warning("System One provider %s returned an unusable answer: %s", name, exc)
            return None, f"{name}: invalid response ({exc})"
        except DecisionUnavailable as exc:
            self._record(name, "error")
            logger.warning("System One provider %s unavailable: %s", name, exc)
            return None, f"{name}: unavailable ({exc})"
        except DecisionError as exc:
            self._record(name, "error")
            return None, f"{name}: {exc}"
        except Exception as exc:  # a provider bug must not stop the pipeline
            self._record(name, "error")
            logger.exception("System One provider %s raised unexpectedly", name)
            return None, f"{name}: unexpected {type(exc).__name__} ({exc})"
        self._record(name, "success", result.latency_ms)
        return result, None

    # -- thresholds --------------------------------------------------------
    def _certainty(self, result: DecisionResult) -> float:
        """The certainty the disposition is based on: the driving classification.

        ``malicious`` and ``severity`` are what a reader acts on, so the weakest
        of those two governs. A confident severity behind a coin-flip
        maliciousness call is not a confident assessment.
        """
        considered = [result.answer(name) for name in ("malicious", "severity")]
        certainties = [answer.certainty for answer in considered if answer is not None]
        if not certainties:
            certainties = [answer.certainty for answer in result.answers.values()]
        return min(certainties) if certainties else 0.0

    def _disposition(self, certainty: float) -> str:
        if certainty >= self.config.accept_threshold:
            return DISPOSITION_ACCEPTED
        if certainty >= self.config.review_threshold:
            return DISPOSITION_REVIEW
        return DISPOSITION_IGNORED

    # -- the step itself ---------------------------------------------------
    def assess(
        self,
        incident: Incident,
        findings: Iterable[Finding],
        *,
        events: Iterable[Any] = (),
        prior_activity: Mapping[str, Any] | None = None,
    ) -> DecisionOutcome:
        """Assess one incident. Never raises; never changes the incident."""
        if not self.enabled:
            return DecisionOutcome(disposition=DISPOSITION_UNAVAILABLE, notes=["System One is disabled"])

        state = build_state(
            incident,
            findings,
            events=events,
            redactor=self.redactor,
            max_findings=self.config.max_findings,
            max_events=self.config.max_events,
            prior_activity=prior_activity,
        )

        errors: list[str] = []
        result, error = self._ask(self.config.provider, state)
        if error:
            errors.append(error)

        fallback_reason = ""
        if result is None and self.config.fallback != PROVIDER_NONE:
            fallback_reason = "primary provider failed"
        elif (
            result is not None
            and self.config.fallback_on_low_confidence
            and self.config.fallback != PROVIDER_NONE
            and self._certainty(result) < self.config.review_threshold
        ):
            fallback_reason = "primary answer was below the review threshold"

        if fallback_reason:
            fallback_result, fallback_error = self._ask(self.config.fallback, state)
            if fallback_error:
                errors.append(fallback_error)
            if fallback_result is not None:
                self.metrics.counter("autosiem_system_one_fallbacks_total", provider=self.config.fallback).inc()
                result = DecisionResult(
                    provider=fallback_result.provider,
                    model=fallback_result.model,
                    answers=fallback_result.answers,
                    latency_ms=fallback_result.latency_ms,
                    fallback_used=True,
                    usage=fallback_result.usage,
                )

        if result is None:
            # Both paths exhausted: behave exactly like a deployment with no
            # provider at all. The deterministic result already stands.
            return DecisionOutcome(
                disposition=DISPOSITION_UNAVAILABLE,
                notes=["no System One provider answered; deterministic result stands"],
                errors=errors,
            )

        certainty = self._certainty(result)
        disposition = self._disposition(certainty)
        notes = [f"{result.provider} answered with certainty {certainty:.2f} ({disposition})"]
        if result.fallback_used:
            notes.append(f"fallback used: {fallback_reason}")
        if disposition == DISPOSITION_IGNORED:
            notes.append("below the review threshold, treated as no signal")

        deterministic = incident.severity.name.lower()
        severity_answer = result.answer("severity")
        if severity_answer is not None and severity_answer.selected != deterministic:
            # Recorded as a disagreement, never applied. Changing the severity
            # here would put a model in charge of the risk score.
            notes.append(
                f"disagrees with the deterministic severity: model {severity_answer.selected!r} "
                f"vs engine {deterministic!r} (engine wins)"
            )
            self.metrics.counter("autosiem_system_one_severity_disagreements_total", provider=result.provider).inc()

        self.metrics.counter(
            "autosiem_system_one_dispositions_total", provider=result.provider, disposition=disposition
        ).inc()
        return DecisionOutcome(disposition=disposition, result=result, notes=notes, errors=errors)

    # -- advisory outputs --------------------------------------------------
    def should_run_llm(self, outcome: DecisionOutcome, *, llm_available: bool) -> bool:
        """Whether the generative LLM step should run for this incident.

        Default behaviour is unchanged: the LLM runs whenever it is configured.
        Only with ``AUTOSIEM_DECISION_GATE_LLM=1`` may a confident
        ``needs_llm_analysis=false`` skip it, and only when the whole assessment
        was confident enough to accept.
        """
        if not llm_available:
            return False
        if not self.config.gate_llm or not outcome.available:
            return True
        if outcome.disposition != DISPOSITION_ACCEPTED:
            return True
        answer = outcome.answer("needs_llm_analysis")
        if answer is None:
            return True
        probability = answer.value if answer.value is not None else answer.certainty
        if answer.selected is True:
            return True
        # Only a decisively negative answer suppresses the call.
        return not (probability is not None and probability <= (1.0 - self.config.accept_threshold))

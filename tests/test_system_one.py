"""System One primitives, providers, fallback and thresholds.

No test here needs an API key, the network, a GPU or a downloaded model: the Jev
transport and the Laya loader are both injected, the same way the API connectors
are tested. Tests that talk to a real provider live in
``test_system_one_integration.py`` behind an explicit marker.
"""

from __future__ import annotations

import json

import pytest

from autosiem.metrics import MetricsRegistry
from autosiem.system_one import (
    DecisionConfig,
    DecisionEngine,
    DecisionInvalid,
    DecisionQuestion,
    DecisionUnavailable,
    DisabledDecisionProvider,
    JevDecisionProvider,
    LayaDecisionProvider,
    normalize_answer,
    normalize_answers,
)
from autosiem.system_one.config import JevConfig, LayaConfig, config_from_env
from autosiem.system_one.engine import (
    DISPOSITION_ACCEPTED,
    DISPOSITION_IGNORED,
    DISPOSITION_REVIEW,
    DISPOSITION_UNAVAILABLE,
)
from autosiem.system_one.types import CHOICE, NOUL, SCORE

def _answer(result, name):
    """The answer for ``name``, asserted present (also narrows the type)."""
    answer = result.answer(name)
    assert answer is not None, f"no answer for {name!r}"
    return answer


# --- question primitives ---------------------------------------------------


def test_noul_question_payload_and_answer() -> None:
    question = DecisionQuestion(type=NOUL, instructions="Malicious?")
    assert question.to_payload() == {"type": "noul", "instructions": "Malicious?"}
    answer = normalize_answer("malicious", question, {"type": "noul", "noul": 0.94})
    assert answer.selected is True
    assert answer.value == pytest.approx(0.94)
    assert answer.probabilities == {"true": pytest.approx(0.94), "false": pytest.approx(0.06)}
    # A noul carries no confidence of its own; certainty is the decisive side.
    assert answer.confidence is None
    assert answer.certainty == pytest.approx(0.94)


def test_a_low_noul_is_a_confident_no_not_an_uncertain_yes() -> None:
    question = DecisionQuestion(type=NOUL, instructions="Malicious?")
    answer = normalize_answer("malicious", question, {"type": "noul", "noul": 0.03})
    assert answer.selected is False
    assert answer.certainty == pytest.approx(0.97)


def test_choice_question_and_answer() -> None:
    question = DecisionQuestion(
        type=CHOICE,
        instructions="Which team?",
        criteria={"billing": "payments", "technical": "bugs", "sales": "pricing"},
    )
    answer = normalize_answer(
        "department",
        question,
        {
            "type": "choice",
            "choice": "billing",
            "probabilities": {"billing": 0.88, "technical": 0.12, "sales": 0.0},
            "confidence": 0.81,
        },
    )
    assert answer.selected == "billing"
    assert answer.confidence == pytest.approx(0.81)
    assert answer.certainty == pytest.approx(0.81)


def test_score_answer_maps_levels_onto_labels() -> None:
    question = DecisionQuestion(
        type=SCORE, instructions="Rate frustration", criteria=["Calm", "Frustrated", "Very angry"]
    )
    answer = normalize_answer(
        "frustration",
        question,
        {
            "type": "score",
            "score": 1.05,
            "legend": {"0": "Calm", "1": "Frustrated", "2": "Very angry"},
            "probabilities": {"0": 0.0, "1": 0.95, "2": 0.05},
            "confidence": 0.92,
        },
    )
    # Positional keys never reach the rest of AutoSIEM.
    assert answer.selected == "Frustrated"
    assert answer.probabilities == {"Calm": 0.0, "Frustrated": 0.95, "Very angry": 0.05}
    assert answer.value == pytest.approx(1.05)


@pytest.mark.parametrize(
    "criteria,kind",
    [(None, CHOICE), ({"only": "one"}, CHOICE), (["one"], SCORE), ({"a": "b"}, SCORE)],
)
def test_malformed_questions_are_refused(criteria, kind) -> None:
    with pytest.raises(ValueError):
        DecisionQuestion(type=kind, instructions="x", criteria=criteria)


def test_unknown_question_type_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown question type"):
        DecisionQuestion(type="vibes", instructions="x")


# --- malformed answers must never become classifications -------------------

NOUL_Q = {"malicious": DecisionQuestion(type=NOUL, instructions="Malicious?")}
CHOICE_Q = {
    "severity": DecisionQuestion(
        type=CHOICE, instructions="Severity?", criteria={"low": "l", "high": "h"}
    )
}


@pytest.mark.parametrize(
    "raw",
    [
        {"malicious": {"type": "noul"}},  # no probability
        {"malicious": {"type": "noul", "noul": 1.4}},  # out of range
        {"malicious": {"type": "noul", "noul": "0.9"}},  # not a number
        {"malicious": {"type": "choice", "choice": "low"}},  # wrong type back
        {"malicious": "yes"},  # not an object
    ],
)
def test_bad_noul_answers_raise_rather_than_default(raw) -> None:
    with pytest.raises(DecisionInvalid):
        normalize_answers(NOUL_Q, raw)


@pytest.mark.parametrize(
    "raw",
    [
        {"severity": {"type": "choice", "choice": "catastrophic"}},  # not an option
        {"severity": {"type": "choice"}},  # no choice
        {"severity": {"type": "choice", "choice": "low", "confidence": 1.5}},
        {"severity": {"type": "choice", "choice": "low", "probabilities": {"nope": 0.5}}},
    ],
)
def test_bad_choice_answers_raise(raw) -> None:
    with pytest.raises(DecisionInvalid):
        normalize_answers(CHOICE_Q, raw)


def test_missing_and_extra_answers_are_both_refused() -> None:
    questions = {**NOUL_Q, **CHOICE_Q}
    with pytest.raises(DecisionInvalid, match="did not answer"):
        normalize_answers(questions, {"malicious": {"type": "noul", "noul": 0.5}})
    with pytest.raises(DecisionInvalid, match="not asked"):
        normalize_answers(
            NOUL_Q,
            {"malicious": {"type": "noul", "noul": 0.5}, "surprise": {"type": "noul", "noul": 0.1}},
        )


# --- Jev provider ----------------------------------------------------------


def _jev_body(answers: dict, model: str = "jev-1.13.0", usage: dict | None = None) -> str:
    payload = {"model": model, "answers": answers}
    payload["usage"] = usage if usage is not None else {"input_tokens": 304, "output_tokens": 18}
    return json.dumps(payload)


def _transport(responses):
    """A scripted transport. Records the requests it was given."""
    calls: list[dict] = []
    queue = list(responses)

    def transport(url, body, headers, timeout):
        calls.append({"url": url, "body": json.loads(body), "headers": headers, "timeout": timeout})
        return queue.pop(0) if queue else (500, "")

    transport.calls = calls  # type: ignore[attr-defined]
    return transport


def test_jev_request_shape_and_auth() -> None:
    transport = _transport([(200, _jev_body({"malicious": {"type": "noul", "noul": 0.9}}))])
    provider = JevDecisionProvider(JevConfig(api_key="k-123", model="jev-latest"), transport=transport)
    result = provider.decide({"incident": {"title": "t"}}, NOUL_Q)

    call = transport.calls[0]  # type: ignore[attr-defined]
    assert call["url"] == "https://api.typesafe.ai/v1/systemone"
    assert call["headers"]["Authorization"] == "Bearer k-123"
    assert call["body"]["model"] == "jev-latest"
    assert call["body"]["state"] == {"incident": {"title": "t"}}
    assert call["body"]["questions"]["malicious"]["type"] == "noul"
    # The concrete version that answered is recorded, not the alias requested.
    assert result.model == "jev-1.13.0"
    assert result.provider == "jev"
    assert result.usage == {"input_tokens": 304, "output_tokens": 18}
    assert result.fallback_used is False


def test_jev_requires_a_key_and_https() -> None:
    from autosiem.system_one.types import DecisionConfigError

    with pytest.raises(DecisionConfigError, match="TYPESAFE_API_KEY"):
        JevDecisionProvider(JevConfig(api_key=""))
    with pytest.raises(ValueError, match="non-HTTPS"):
        JevDecisionProvider(JevConfig(api_key="k", url="http://api.example.com/v1/systemone"))


def test_jev_retries_throttling_then_succeeds() -> None:
    transport = _transport(
        [(429, "slow down"), (529, "overloaded"), (200, _jev_body({"malicious": {"type": "noul", "noul": 0.7}}))]
    )
    slept: list[float] = []
    provider = JevDecisionProvider(
        JevConfig(api_key="k", retries=2, backoff_seconds=0.01), transport=transport, sleep=slept.append
    )
    result = provider.decide({}, NOUL_Q)
    assert _answer(result, "malicious").value == pytest.approx(0.7)
    # Exponential, not a tight loop.
    assert slept == [pytest.approx(0.01), pytest.approx(0.02)]


def test_jev_gives_up_after_its_retries() -> None:
    transport = _transport([(429, ""), (429, ""), (429, "")])
    provider = JevDecisionProvider(
        JevConfig(api_key="k", retries=2, backoff_seconds=0.0), transport=transport, sleep=lambda _s: None
    )
    with pytest.raises(DecisionUnavailable, match="3 attempt"):
        provider.decide({}, NOUL_Q)


def test_jev_does_not_retry_an_auth_or_schema_error() -> None:
    transport = _transport([(401, "nope"), (200, _jev_body({"malicious": {"type": "noul", "noul": 0.5}}))])
    provider = JevDecisionProvider(JevConfig(api_key="bad", retries=3), transport=transport)
    with pytest.raises(DecisionUnavailable, match="401"):
        provider.decide({}, NOUL_Q)
    assert len(transport.calls) == 1  # type: ignore[attr-defined]

    transport = _transport([(422, "bad question")])
    provider = JevDecisionProvider(JevConfig(api_key="k", retries=3), transport=transport)
    # A 422 is our bug, not an outage, so it is invalid rather than unavailable.
    with pytest.raises(DecisionInvalid, match="422"):
        provider.decide({}, NOUL_Q)


def test_jev_timeout_is_unavailable() -> None:
    def transport(url, body, headers, timeout):
        raise DecisionUnavailable("jev request failed: timed out")

    provider = JevDecisionProvider(JevConfig(api_key="k", retries=0), transport=transport)
    with pytest.raises(DecisionUnavailable, match="timed out"):
        provider.decide({}, NOUL_Q)


def test_jev_timeout_value_is_passed_to_the_transport() -> None:
    transport = _transport([(200, _jev_body({"malicious": {"type": "noul", "noul": 0.5}}))])
    provider = JevDecisionProvider(JevConfig(api_key="k", timeout=3.5), transport=transport)
    provider.decide({}, NOUL_Q)
    assert transport.calls[0]["timeout"] == 3.5  # type: ignore[attr-defined]


def test_jev_invalid_json_and_wrong_shape_are_invalid() -> None:
    provider = JevDecisionProvider(JevConfig(api_key="k"), transport=_transport([(200, "not json")]))
    with pytest.raises(DecisionInvalid, match="invalid JSON"):
        provider.decide({}, NOUL_Q)
    provider = JevDecisionProvider(JevConfig(api_key="k"), transport=_transport([(200, "[]")]))
    with pytest.raises(DecisionInvalid, match="expected an object"):
        provider.decide({}, NOUL_Q)


# --- Laya provider ---------------------------------------------------------


class FakeLaya:
    """Stands in for a loaded laya agent."""

    def __init__(self, answers=None, error: Exception | None = None) -> None:
        self.answers = answers or {"malicious": {"type": "noul", "noul": 0.42}}
        self.error = error
        self.calls: list[tuple] = []

    def predict(self, state, questions):
        self.calls.append((state, questions))
        if self.error:
            raise self.error
        return {"routing": {"model": "laya-typed-decisions"}, "answers": self.answers}


def test_laya_parses_a_local_result() -> None:
    agent = FakeLaya()
    provider = LayaDecisionProvider(LayaConfig(), loader=lambda: agent)
    result = provider.decide({"incident": {"title": "t"}}, NOUL_Q)
    assert result.provider == "laya"
    assert result.model == "laya-typed-decisions"
    assert _answer(result, "malicious").value == pytest.approx(0.42)
    # Local inference reports no tokens, so no cost can be claimed for it.
    assert result.usage == {}
    assert agent.calls[0][1]["malicious"]["type"] == "noul"


def test_laya_loads_lazily_and_only_once() -> None:
    loads: list[int] = []
    agent = FakeLaya()

    def loader():
        loads.append(1)
        return agent

    provider = LayaDecisionProvider(LayaConfig(), loader=loader)
    assert loads == []  # constructing it must not load the model
    provider.decide({}, NOUL_Q)
    provider.decide({}, NOUL_Q)
    assert loads == [1]


def test_laya_inference_failure_is_unavailable() -> None:
    provider = LayaDecisionProvider(LayaConfig(), loader=lambda: FakeLaya(error=RuntimeError("cuda oom")))
    with pytest.raises(DecisionUnavailable, match="cuda oom"):
        provider.decide({}, NOUL_Q)


def test_laya_malformed_output_is_invalid() -> None:
    provider = LayaDecisionProvider(
        LayaConfig(), loader=lambda: FakeLaya(answers={"malicious": {"type": "noul", "noul": 7}})
    )
    with pytest.raises(DecisionInvalid):
        provider.decide({}, NOUL_Q)


def test_laya_missing_extra_names_the_install_command(monkeypatch) -> None:
    from autosiem.system_one.types import DecisionConfigError

    provider = LayaDecisionProvider(LayaConfig())
    monkeypatch.setitem(__import__("sys").modules, "laya", None)
    monkeypatch.delitem(__import__("sys").modules, "laya")
    # No laya installed in the test environment, so the real import path runs.
    with pytest.raises((DecisionConfigError, DecisionUnavailable)) as exc:
        provider.decide({}, NOUL_Q)
    assert "laya" in str(exc.value)


def test_disabled_provider_refuses_clearly() -> None:
    with pytest.raises(DecisionUnavailable, match="disabled"):
        DisabledDecisionProvider().decide({}, NOUL_Q)


# --- configuration ---------------------------------------------------------


def test_config_defaults_to_disabled() -> None:
    config = config_from_env({})
    assert config.provider == "none"
    assert config.enabled is False
    assert config.fallback == "none"
    # Documented defaults, in one place.
    assert config.accept_threshold == 0.75
    assert config.review_threshold == 0.5
    assert config.fallback_on_low_confidence is False
    assert config.gate_llm is False


def test_config_reads_the_environment() -> None:
    config = config_from_env(
        {
            "AUTOSIEM_DECISION_PROVIDER": "jev",
            "AUTOSIEM_DECISION_FALLBACK": "laya",
            "TYPESAFE_API_KEY": "secret",
            "AUTOSIEM_JEV_MODEL": "jev-1.13.0",
            "AUTOSIEM_LAYA_DEVICE": "MPS",
            "AUTOSIEM_DECISION_ACCEPT_CONFIDENCE": "0.9",
            "AUTOSIEM_DECISION_GATE_LLM": "1",
        }
    )
    assert (config.provider, config.fallback) == ("jev", "laya")
    assert config.jev.configured and config.jev.model == "jev-1.13.0"
    assert config.laya.device == "mps"
    assert config.accept_threshold == 0.9
    assert config.gate_llm is True
    # describe() is what gets logged and printed: it must not carry the key.
    assert "secret" not in json.dumps(config.describe())
    assert config.describe()["jev_key_configured"] is True


def test_an_unknown_provider_is_rejected_loudly() -> None:
    with pytest.raises(ValueError, match="unknown decision provider"):
        config_from_env({"AUTOSIEM_DECISION_PROVIDER": "gpt"})


def test_a_fallback_equal_to_the_primary_is_dropped() -> None:
    # Retrying the same provider is what `retries` is for.
    config = config_from_env({"AUTOSIEM_DECISION_PROVIDER": "jev", "AUTOSIEM_DECISION_FALLBACK": "jev"})
    assert config.fallback == "none"


# --- engine: fallback, thresholds, disabled --------------------------------


class StubProvider:
    def __init__(self, name: str, result=None, error: Exception | None = None) -> None:
        self.name = name
        self._result = result
        self._error = error
        self.calls = 0

    def decide(self, state, questions):
        self.calls += 1
        if self._error:
            raise self._error
        return self._result


def _result(provider: str, *, malicious: float = 0.9, severity_confidence: float = 0.9, severity: str = "high"):
    from autosiem.system_one.types import DecisionAnswer, DecisionResult

    return DecisionResult(
        provider=provider,
        model=f"{provider}-model",
        answers={
            "malicious": DecisionAnswer(
                type=NOUL, selected=malicious >= 0.5,
                probabilities={"true": malicious, "false": 1 - malicious}, value=malicious,
            ),
            "severity": DecisionAnswer(type=CHOICE, selected=severity, confidence=severity_confidence),
            "action": DecisionAnswer(type=CHOICE, selected="investigate", confidence=0.9),
            "needs_llm_analysis": DecisionAnswer(
                type=NOUL, selected=False, probabilities={"true": 0.1, "false": 0.9}, value=0.1
            ),
        },
        latency_ms=12.0,
    )


def _engine(config: DecisionConfig, **providers):
    return DecisionEngine(config, providers=providers, metrics=MetricsRegistry())


def _incident(severity_name: str = "high", risk: int = 300):
    from datetime import datetime, timezone

    from autosiem.schemas import Incident, Severity

    return Incident(
        incident_id="inc-1",
        title="Suspicious chain",
        severity=Severity[severity_name.upper()],
        risk_score=risk,
        entities=["user:alice", "host:vpn-1"],
        finding_ids=["f-1"],
        mitre_attack=["T1110"],
        summary="credential access then discovery",
        created_at=datetime(2026, 9, 17, 3, 0, tzinfo=timezone.utc),
    )


def test_disabled_engine_returns_unavailable_and_asks_nobody() -> None:
    jev = StubProvider("jev", result=_result("jev"))
    engine = _engine(DecisionConfig(provider="none"), jev=jev)
    outcome = engine.assess(_incident(), [])
    assert outcome.disposition == DISPOSITION_UNAVAILABLE
    assert outcome.available is False
    assert jev.calls == 0


def test_a_confident_answer_is_accepted() -> None:
    engine = _engine(DecisionConfig(provider="jev"), jev=StubProvider("jev", result=_result("jev")))
    outcome = engine.assess(_incident(), [])
    assert outcome.disposition == DISPOSITION_ACCEPTED
    assert outcome.result is not None and outcome.result.fallback_used is False


def test_middling_confidence_lands_in_review_and_low_is_ignored() -> None:
    review = _engine(
        DecisionConfig(provider="jev"),
        jev=StubProvider("jev", result=_result("jev", malicious=0.62, severity_confidence=0.6)),
    ).assess(_incident(), [])
    assert review.disposition == DISPOSITION_REVIEW

    ignored = _engine(
        DecisionConfig(provider="jev"),
        jev=StubProvider("jev", result=_result("jev", malicious=0.52, severity_confidence=0.3)),
    ).assess(_incident(), [])
    assert ignored.disposition == DISPOSITION_IGNORED
    # The answer is still recorded; it just carries no weight.
    assert ignored.available is True


def test_the_weakest_driving_answer_governs_the_disposition() -> None:
    # A near-certain severity behind a coin-flip maliciousness call is not a
    # confident assessment, so it must not be accepted.
    #
    # Note the floor this exposes: a noul's certainty is P(selected side), which
    # is never below 0.5, so a noul alone can never fall under the review
    # threshold. Only a choice/score confidence can push an assessment to
    # "ignored" - which is why the severity answer is part of this minimum.
    outcome = _engine(
        DecisionConfig(provider="jev"),
        jev=StubProvider("jev", result=_result("jev", malicious=0.5, severity_confidence=0.99)),
    ).assess(_incident(), [])
    assert outcome.disposition == DISPOSITION_REVIEW


def test_fallback_runs_when_the_primary_fails() -> None:
    jev = StubProvider("jev", error=DecisionUnavailable("down"))
    laya = StubProvider("laya", result=_result("laya"))
    engine = _engine(DecisionConfig(provider="jev", fallback="laya"), jev=jev, laya=laya)
    outcome = engine.assess(_incident(), [])
    assert outcome.result is not None
    assert outcome.result.provider == "laya"
    assert outcome.result.fallback_used is True
    assert "unavailable" in " ".join(outcome.errors)
    assert laya.calls == 1


def test_fallback_also_runs_for_a_malformed_primary_response() -> None:
    jev = StubProvider("jev", error=DecisionInvalid("garbage"))
    laya = StubProvider("laya", result=_result("laya"))
    outcome = _engine(DecisionConfig(provider="jev", fallback="laya"), jev=jev, laya=laya).assess(_incident(), [])
    assert outcome.result is not None and outcome.result.fallback_used is True


def test_low_confidence_does_not_trigger_fallback_by_default() -> None:
    # A low-confidence answer and a failed provider are different states.
    jev = StubProvider("jev", result=_result("jev", malicious=0.5, severity_confidence=0.2))
    laya = StubProvider("laya", result=_result("laya"))
    outcome = _engine(DecisionConfig(provider="jev", fallback="laya"), jev=jev, laya=laya).assess(_incident(), [])
    assert laya.calls == 0
    assert outcome.result is not None and outcome.result.provider == "jev"
    assert outcome.disposition == DISPOSITION_IGNORED


def test_low_confidence_fallback_is_opt_in() -> None:
    jev = StubProvider("jev", result=_result("jev", malicious=0.5, severity_confidence=0.2))
    laya = StubProvider("laya", result=_result("laya"))
    config = DecisionConfig(provider="jev", fallback="laya", fallback_on_low_confidence=True)
    outcome = _engine(config, jev=jev, laya=laya).assess(_incident(), [])
    assert laya.calls == 1
    assert outcome.result is not None and outcome.result.provider == "laya"


def test_both_providers_failing_degrades_to_the_deterministic_path() -> None:
    engine = _engine(
        DecisionConfig(provider="jev", fallback="laya"),
        jev=StubProvider("jev", error=DecisionUnavailable("down")),
        laya=StubProvider("laya", error=DecisionUnavailable("no model")),
    )
    outcome = engine.assess(_incident(), [])
    assert outcome.disposition == DISPOSITION_UNAVAILABLE
    assert outcome.available is False
    assert len(outcome.errors) == 2


def test_a_provider_raising_something_unexpected_does_not_escape() -> None:
    class Exploding:
        name = "jev"

        def decide(self, state, questions):
            raise KeyError("bug in the provider")

    outcome = _engine(DecisionConfig(provider="jev"), jev=Exploding()).assess(_incident(), [])
    assert outcome.disposition == DISPOSITION_UNAVAILABLE
    assert "KeyError" in " ".join(outcome.errors)


def test_a_severity_disagreement_is_recorded_not_applied() -> None:
    incident = _incident("medium")
    engine = _engine(
        DecisionConfig(provider="jev"), jev=StubProvider("jev", result=_result("jev", severity="critical"))
    )
    outcome = engine.assess(incident, [])
    # The engine's severity is untouched: a model does not get to rewrite risk.
    assert incident.severity.name.lower() == "medium"
    assert any("engine wins" in note for note in outcome.notes)


def test_metrics_record_requests_fallbacks_and_dispositions() -> None:
    metrics = MetricsRegistry()
    providers: dict = {
        "jev": StubProvider("jev", error=DecisionUnavailable("down")),
        "laya": StubProvider("laya", result=_result("laya")),
    }
    engine = DecisionEngine(
        DecisionConfig(provider="jev", fallback="laya"),
        providers=providers,
        metrics=metrics,
    )
    engine.assess(_incident(), [])
    assert metrics.counter("autosiem_system_one_requests_total", provider="jev", outcome="error").value == 1
    assert metrics.counter("autosiem_system_one_requests_total", provider="laya", outcome="success").value == 1
    assert metrics.counter("autosiem_system_one_fallbacks_total", provider="laya").value == 1
    assert (
        metrics.counter(
            "autosiem_system_one_dispositions_total", provider="laya", disposition=DISPOSITION_ACCEPTED
        ).value
        == 1
    )


# --- LLM escalation --------------------------------------------------------


def test_llm_runs_as_before_unless_gating_is_enabled() -> None:
    engine = _engine(DecisionConfig(provider="jev"), jev=StubProvider("jev", result=_result("jev")))
    outcome = engine.assess(_incident(), [])
    # needs_llm_analysis is 0.1 here, but gating is off by default, so the
    # existing LLM behaviour is unchanged.
    assert engine.should_run_llm(outcome, llm_available=True) is True
    assert engine.should_run_llm(outcome, llm_available=False) is False


def test_gating_suppresses_the_llm_only_on_a_confident_no() -> None:
    config = DecisionConfig(provider="jev", gate_llm=True)
    engine = _engine(config, jev=StubProvider("jev", result=_result("jev")))
    assert engine.should_run_llm(engine.assess(_incident(), []), llm_available=True) is False


def test_gating_still_runs_the_llm_when_the_model_asks_for_it() -> None:
    from autosiem.system_one.types import DecisionAnswer

    result = _result("jev")
    result.answers["needs_llm_analysis"] = DecisionAnswer(
        type=NOUL, selected=True, probabilities={"true": 0.8, "false": 0.2}, value=0.8
    )
    engine = _engine(DecisionConfig(provider="jev", gate_llm=True), jev=StubProvider("jev", result=result))
    assert engine.should_run_llm(engine.assess(_incident(), []), llm_available=True) is True


def test_gating_never_suppresses_the_llm_on_an_unconfident_assessment() -> None:
    engine = _engine(
        DecisionConfig(provider="jev", gate_llm=True),
        jev=StubProvider("jev", result=_result("jev", malicious=0.55, severity_confidence=0.55)),
    )
    outcome = engine.assess(_incident(), [])
    assert outcome.disposition == DISPOSITION_REVIEW
    assert engine.should_run_llm(outcome, llm_available=True) is True


def test_gating_with_no_provider_answer_leaves_the_llm_alone() -> None:
    engine = _engine(
        DecisionConfig(provider="jev", gate_llm=True), jev=StubProvider("jev", error=DecisionUnavailable("down"))
    )
    outcome = engine.assess(_incident(), [])
    assert engine.should_run_llm(outcome, llm_available=True) is True

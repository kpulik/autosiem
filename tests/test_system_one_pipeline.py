"""System One inside the pipeline: state privacy, persistence, and the gates.

The load-bearing test in this file is
``test_a_confident_model_cannot_lower_a_policy_gate``. Everything else can be
re-litigated; that one is the reason the layer is allowed to exist at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules
from autosiem.schemas import Severity
from autosiem.storage import AutoSIEMStorage
from autosiem.system_one import DecisionConfig, DecisionEngine, SECURITY_QUESTIONS, build_state
from autosiem.system_one.types import CHOICE, NOUL, DecisionAnswer, DecisionResult

ROOT = Path(__file__).resolve().parents[1]


def _rules():
    return load_rules(ROOT / "rules")


def _demo_lines() -> list[str]:
    return (ROOT / "examples/events.jsonl").read_text(encoding="utf-8").splitlines()


class ScriptedProvider:
    """A provider that answers however a test needs, and counts its calls."""

    name = "jev"

    def __init__(self, *, severity: str = "critical", malicious: float = 0.97, needs_llm: float = 0.02, error: Exception | None = None) -> None:
        self.severity = severity
        self.malicious = malicious
        self.needs_llm = needs_llm
        self.error = error
        self.states: list[dict] = []

    def decide(self, state, questions):
        self.states.append(state)
        if self.error:
            raise self.error
        return DecisionResult(
            provider="jev",
            model="jev-1.13.0",
            answers={
                "malicious": DecisionAnswer(
                    type=NOUL, selected=self.malicious >= 0.5,
                    probabilities={"true": self.malicious, "false": 1 - self.malicious},
                    value=self.malicious,
                ),
                "severity": DecisionAnswer(type=CHOICE, selected=self.severity, confidence=0.96),
                "action": DecisionAnswer(type=CHOICE, selected="escalate", confidence=0.95),
                "needs_llm_analysis": DecisionAnswer(
                    type=NOUL, selected=self.needs_llm >= 0.5,
                    probabilities={"true": self.needs_llm, "false": 1 - self.needs_llm},
                    value=self.needs_llm,
                ),
            },
            latency_ms=84.0,
            usage={"input_tokens": 512, "output_tokens": 12},
        )


def _as_llm(fake: "FakeLLM") -> Any:
    """FakeLLM is duck-typed: the pipeline only touches .enabled and .annotate."""
    return fake


def _engine(provider, **overrides):
    config = DecisionConfig(provider="jev", **overrides)
    return DecisionEngine(config, providers={"jev": provider})


# --- default behaviour is unchanged ----------------------------------------


def test_without_an_engine_the_pipeline_behaves_exactly_as_before() -> None:
    result = AutoSIEMPipeline(_rules()).process_lines(_demo_lines())
    assert result.incidents
    assert result.decisions == {}


def test_a_disabled_engine_asks_nothing_and_records_nothing() -> None:
    provider = ScriptedProvider()
    engine = DecisionEngine(DecisionConfig(provider="none"), providers={"jev": provider})
    result = AutoSIEMPipeline(_rules(), decision_engine=engine).process_lines(_demo_lines())
    assert result.incidents
    assert result.decisions == {}
    assert provider.states == []


def test_an_enabled_engine_annotates_every_incident() -> None:
    provider = ScriptedProvider()
    result = AutoSIEMPipeline(_rules(), decision_engine=_engine(provider)).process_lines(_demo_lines())
    assert set(result.decisions) == {incident.incident_id for incident in result.incidents}
    outcome = result.decisions[result.incidents[0].incident_id]
    assert outcome.result is not None
    assert outcome.result.provider == "jev"
    assert outcome.disposition == "accepted"


# --- the gates stay authoritative ------------------------------------------


def test_a_confident_model_cannot_change_severity_or_risk() -> None:
    lines = _demo_lines()
    baseline = AutoSIEMPipeline(_rules()).process_lines(lines)
    # The model insists everything is informational, with high confidence.
    provider = ScriptedProvider(severity="informational", malicious=0.99)
    annotated = AutoSIEMPipeline(_rules(), decision_engine=_engine(provider)).process_lines(lines)

    assert len(annotated.incidents) == len(baseline.incidents)
    for before, after in zip(baseline.incidents, annotated.incidents):
        assert after.severity == before.severity
        assert after.risk_score == before.risk_score
    # The disagreement is recorded instead.
    notes = " ".join(annotated.decisions[annotated.incidents[0].incident_id].notes)
    assert "engine wins" in notes


def test_a_confident_model_cannot_lower_a_policy_gate() -> None:
    """The invariant: approval requirements are identical with and without it."""
    lines = _demo_lines()
    baseline = AutoSIEMPipeline(_rules()).process_lines(lines)
    provider = ScriptedProvider(severity="informational", malicious=0.01)
    annotated = AutoSIEMPipeline(_rules(), decision_engine=_engine(provider)).process_lines(lines)

    def gates(result) -> list[tuple]:
        # Keyed by proposal content, not incident id: ids are fresh uuid4 on
        # every run, so only the gate decisions are comparable across runs.
        rows = []
        for investigation in result.investigations.values():
            for proposal in investigation.action_proposals:
                rows.append(
                    (
                        proposal.action,
                        proposal.target,
                        proposal.approval_required,
                        proposal.executable_now,
                        proposal.policy_reason,
                    )
                )
        return sorted(rows)

    assert gates(annotated) == gates(baseline)
    # And the high/critical proposals really do still require approval.
    required = [row for row in gates(annotated) if row[2]]
    assert required, "the demo kill chain must still produce approval-gated actions"


def test_the_investigation_decision_is_not_overridden_by_system_one() -> None:
    lines = _demo_lines()
    baseline = AutoSIEMPipeline(_rules()).process_lines(lines)
    provider = ScriptedProvider(severity="informational", malicious=0.02)
    annotated = AutoSIEMPipeline(_rules(), decision_engine=_engine(provider)).process_lines(lines)
    def decisions(result) -> list[tuple]:
        return sorted(
            (inv.decision.decision_type.value, inv.decision.confidence)
            for inv in result.investigations.values()
        )

    assert decisions(annotated) == decisions(baseline)


def test_a_failing_provider_leaves_the_run_intact() -> None:
    from autosiem.system_one.types import DecisionUnavailable

    lines = _demo_lines()
    baseline = AutoSIEMPipeline(_rules()).process_lines(lines)
    provider = ScriptedProvider(error=DecisionUnavailable("connection refused"))
    annotated = AutoSIEMPipeline(_rules(), decision_engine=_engine(provider)).process_lines(lines)

    assert len(annotated.incidents) == len(baseline.incidents)
    assert len(annotated.reports) == len(baseline.reports)
    outcome = annotated.decisions[annotated.incidents[0].incident_id]
    assert outcome.disposition == "unavailable"
    assert "connection refused" in " ".join(outcome.errors)


# --- LLM escalation --------------------------------------------------------


class FakeLLM:
    """Minimal stand-in for LLMService."""

    def __init__(self) -> None:
        self.enabled = True
        self.calls = 0

    def annotate(self, incident, findings, extra_context=""):
        from autosiem.llm import AnnotationResult

        self.calls += 1
        return AnnotationResult(report="llm report", decision=None, used_llm=True)


def test_the_llm_still_runs_by_default_when_system_one_is_enabled() -> None:
    llm = FakeLLM()
    provider = ScriptedProvider(needs_llm=0.01)
    result = AutoSIEMPipeline(_rules(), llm=_as_llm(llm), decision_engine=_engine(provider)).process_lines(_demo_lines())
    # Gating is opt-in, so enabling System One must not change LLM behaviour.
    assert llm.calls == len(result.incidents)
    assert result.decisions[result.incidents[0].incident_id].llm_escalated is True


def test_gating_can_skip_the_llm_for_a_clear_cut_incident() -> None:
    llm = FakeLLM()
    provider = ScriptedProvider(needs_llm=0.01)
    result = AutoSIEMPipeline(
        _rules(), llm=_as_llm(llm), decision_engine=_engine(provider, gate_llm=True)
    ).process_lines(_demo_lines())
    assert llm.calls == 0
    assert result.llm_reports == set()
    # The local deterministic explainer still produced a report.
    assert result.reports[result.incidents[0].incident_id]
    assert result.decisions[result.incidents[0].incident_id].llm_escalated is False


def test_gating_keeps_the_llm_for_an_ambiguous_incident() -> None:
    llm = FakeLLM()
    provider = ScriptedProvider(needs_llm=0.9)
    result = AutoSIEMPipeline(
        _rules(), llm=_as_llm(llm), decision_engine=_engine(provider, gate_llm=True)
    ).process_lines(_demo_lines())
    assert llm.calls == len(result.incidents)


# --- privacy ---------------------------------------------------------------


def test_the_state_carries_signals_not_raw_log_dumps() -> None:
    result = AutoSIEMPipeline(_rules()).process_lines(_demo_lines())
    incident = result.incidents[0]
    related = [f for f in result.findings if f.finding_id in incident.finding_ids]
    events = [e for e in result.events if e.event_id in {f.event_id for f in related}]
    state = build_state(incident, related, events=events)

    assert state["incident"]["deterministic_severity"] == incident.severity.name.lower()
    assert "ueba" in state and "signals" in state["ueba"]
    assert isinstance(state["findings"], list)
    # No whole-event dump: each event summary is a small, named set of fields.
    for event in state.get("events", []):
        assert "raw" not in event
        assert set(event) <= {"category", "action", "outcome", "timestamp", *[
            "process_name", "command_line", "parent_process", "url", "file_path",
            "event_name", "error_code", "user_agent", "rule_name",
        ]}


def test_secrets_in_a_raw_event_never_reach_the_state() -> None:
    from autosiem.normalization import normalize, parse_raw_line

    line = json.dumps(
        {
            "timestamp": "2026-09-17T02:00:00Z",
            "category": "process",
            "action": "process_started",
            "user": "alice",
            "host": "vpn-1",
            "process_name": "curl",
            "command_line": "curl -H 'Authorization: Bearer sk-live-ABCDEF1234567890abcdef' https://x.test",
            "api_key": "AKIAIOSFODNN7EXAMPLE",
            "session_token": "eyJhbGciOiJIUzI1NiJ9.super.secret",
            "password": "hunter2",
        }
    )
    event = normalize(parse_raw_line(line))
    result = AutoSIEMPipeline(_rules()).process_lines([line])
    incident_findings = result.findings
    from autosiem.schemas import Incident

    incident = Incident(
        incident_id="inc-secret",
        title="curl with a bearer token",
        severity=Severity.MEDIUM,
        risk_score=50,
        entities=["user:alice"],
        finding_ids=[f.finding_id for f in incident_findings],
        mitre_attack=[],
        summary="test",
    )
    blob = json.dumps(build_state(incident, incident_findings, events=[event]))

    # Fields that are not whitelisted never appear at all.
    for name in ("api_key", "session_token", "password"):
        assert name not in blob
    for secret in ("AKIAIOSFODNN7EXAMPLE", "hunter2", "eyJhbGciOiJIUzI1NiJ9.super.secret"):
        assert secret not in blob
    # command_line IS whitelisted (it is detection-relevant), so the embedded
    # token must have been redacted rather than the field dropped.
    assert "sk-live-ABCDEF1234567890abcdef" not in blob
    assert "curl" in blob


def test_caps_bound_what_is_sent() -> None:
    result = AutoSIEMPipeline(_rules()).process_lines(_demo_lines())
    incident = result.incidents[0]
    state = build_state(incident, result.findings, events=result.events, max_findings=2, max_events=1)
    assert len(state["findings"]) == 2
    assert len(state.get("events", [])) == 1


# --- persistence -----------------------------------------------------------


def test_the_assessment_is_persisted_and_surfaces_in_the_bundle(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "decisions.db")
    provider = ScriptedProvider(severity="high", malicious=0.94)
    result = AutoSIEMPipeline(_rules(), decision_engine=_engine(provider)).process_lines(_demo_lines())
    store.save_pipeline_result(result)

    incident_id = result.incidents[0].incident_id
    row = store.get_decision(incident_id)
    assert row is not None
    assert row["provider"] == "jev"
    assert row["model"] == "jev-1.13.0"
    assert row["severity"] == "high"
    assert row["action"] == "escalate"
    assert row["malicious"] == pytest.approx(0.94)
    assert row["latency_ms"] == pytest.approx(84.0)
    assert row["fallback_used"] == 0
    assert row["disposition"] == "accepted"

    bundle = store.get_incident_bundle(incident_id)
    assert bundle is not None and bundle["system_one"]["provider"] == "jev"
    # The state that was sent is deliberately not duplicated into the row.
    stored = row["data"] if isinstance(row["data"], dict) else json.loads(row["data"])
    assert "state" not in stored
    assert set(stored["answers"]) == set(SECURITY_QUESTIONS)


def test_an_unavailable_assessment_is_still_recorded(tmp_path) -> None:
    from autosiem.system_one.types import DecisionUnavailable

    store = AutoSIEMStorage(tmp_path / "unavailable.db")
    provider = ScriptedProvider(error=DecisionUnavailable("down"))
    result = AutoSIEMPipeline(_rules(), decision_engine=_engine(provider)).process_lines(_demo_lines())
    store.save_pipeline_result(result)
    row = store.get_decision(result.incidents[0].incident_id)
    assert row is not None and row["disposition"] == "unavailable"
    assert row["provider"] == "none"


def test_decision_stats_report_providers_and_escalations(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "stats.db")
    result = AutoSIEMPipeline(_rules(), decision_engine=_engine(ScriptedProvider())).process_lines(_demo_lines())
    store.save_pipeline_result(result)
    stats = store.decision_stats()
    assert stats["total"] == len(result.incidents)
    assert stats["by_provider"][0]["provider"] == "jev"


def test_an_existing_database_gains_the_decisions_table(tmp_path) -> None:
    db = tmp_path / "legacy.db"
    AutoSIEMStorage(db)  # first open creates the schema
    import sqlite3

    conn = sqlite3.connect(db)
    conn.execute("drop table system_one_decisions")
    conn.commit()
    conn.close()
    # Re-opening an older database must add the table back, not fail.
    store = AutoSIEMStorage(db)
    assert store.get_decision("nope") is None


def test_saving_without_any_decisions_still_works(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "plain.db")
    result = AutoSIEMPipeline(_rules()).process_lines(_demo_lines())
    store.save_pipeline_result(result)
    bundle = store.get_incident_bundle(result.incidents[0].incident_id)
    assert bundle is not None and bundle["system_one"] is None
    assert store.decision_stats()["total"] == 0


def test_the_question_set_is_the_documented_one() -> None:
    assert set(SECURITY_QUESTIONS) == {"malicious", "severity", "action", "needs_llm_analysis"}
    assert SECURITY_QUESTIONS["malicious"].type == NOUL
    assert SECURITY_QUESTIONS["severity"].options == (
        "informational", "low", "medium", "high", "critical",
    )
    assert SECURITY_QUESTIONS["action"].options == (
        "suppress", "monitor", "enrich", "investigate", "escalate",
    )

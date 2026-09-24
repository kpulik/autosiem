"""The evaluation harness: scoring maths and the CLI around it.

The metrics are checked against hand-computed values, because a benchmark whose
arithmetic is only verified by itself is not evidence of anything.
"""

from __future__ import annotations

import json
import sys

import pytest

from autosiem.cli import main
from autosiem.system_one import SECURITY_QUESTIONS
from autosiem.system_one import baseline as decision_baseline
from autosiem.system_one import evaluation as ev
from autosiem.system_one.types import CHOICE, NOUL, DecisionAnswer, DecisionResult


def _answer(result, name):
    """The answer for ``name``, asserted present (also narrows the type)."""
    answer = result.answer(name)
    assert answer is not None, f"no answer for {name!r}"
    return answer


# --- scoring maths ---------------------------------------------------------


def test_brier_score_matches_hand_computation() -> None:
    # (0.9 - 1)^2 = 0.01, (0.2 - 0)^2 = 0.04 -> mean 0.025
    assert ev.brier_score([(0.9, True), (0.2, False)]) == pytest.approx(0.025)
    # Always saying 0.5 scores 0.25, the documented baseline.
    assert ev.brier_score([(0.5, True), (0.5, False)]) == pytest.approx(0.25)
    assert ev.brier_score([]) is None


def test_a_confident_wrong_answer_is_punished_more_than_a_hedged_one() -> None:
    confident_wrong = ev.brier_score([(0.99, False)])
    hedged_wrong = ev.brier_score([(0.6, False)])
    assert confident_wrong is not None and hedged_wrong is not None
    assert confident_wrong > hedged_wrong


def test_expected_calibration_error_is_zero_for_a_calibrated_set() -> None:
    # Ten cases at 0.9 confidence, nine correct: |0.9 - 0.9| = 0.
    pairs = [(0.9, True)] * 9 + [(0.9, False)]
    assert ev.expected_calibration_error(pairs, bins=10) == pytest.approx(0.0)


def test_expected_calibration_error_catches_overconfidence() -> None:
    # Claims 1.0, right half the time.
    pairs = [(1.0, True), (1.0, False)]
    assert ev.expected_calibration_error(pairs, bins=10) == pytest.approx(0.5)
    assert ev.expected_calibration_error([]) is None


def test_question_score_tracks_accuracy_and_confusion() -> None:
    score = ev.QuestionScore(question="severity")
    score.record("high", "high", probability=None, confidence=0.9)
    score.record("high", "critical", probability=None, confidence=0.8)
    score.record("low", "low", probability=None, confidence=0.7)
    assert score.total == 3 and score.correct == 2
    assert score.accuracy == pytest.approx(2 / 3)
    # The confusion matrix shows where the error actually is.
    assert score.confusion["high"] == {"high": 1, "critical": 1}
    assert score.confusion["low"] == {"low": 1}


def test_boolean_labels_compare_across_representations() -> None:
    score = ev.QuestionScore(question="malicious")
    score.record(True, True, probability=0.9, confidence=0.9)
    score.record(False, False, probability=0.1, confidence=0.9)
    assert score.correct == 2
    assert score.to_dict()["brier_score"] == pytest.approx(0.01)


# --- end-to-end evaluation -------------------------------------------------


def _answer_set(malicious: float, severity: str, action: str = "investigate"):
    return {
        "malicious": DecisionAnswer(
            type=NOUL, selected=malicious >= 0.5,
            probabilities={"true": malicious, "false": 1 - malicious}, value=malicious,
        ),
        "severity": DecisionAnswer(type=CHOICE, selected=severity, confidence=0.9),
        "action": DecisionAnswer(type=CHOICE, selected=action, confidence=0.8),
        "needs_llm_analysis": DecisionAnswer(
            type=NOUL, selected=False, probabilities={"true": 0.1, "false": 0.9}, value=0.1
        ),
    }


def _runner(malicious: float, severity: str, *, usage=None, fallback=False):
    def run(state):
        return DecisionResult(
            provider="stub", model="stub-1", answers=_answer_set(malicious, severity),
            latency_ms=10.0, fallback_used=fallback, usage=usage or {},
        )

    return run


def _cases():
    return [
        ev.LabelledCase(case_id="c1", state={"incident": {"deterministic_severity": "high", "deterministic_risk_score": 400}}, labels={"malicious": True, "severity": "high"}),
        ev.LabelledCase(case_id="c2", state={"incident": {"deterministic_severity": "low", "deterministic_risk_score": 10}}, labels={"malicious": False, "severity": "low"}),
    ]


def test_evaluate_scores_every_path_on_the_same_cases() -> None:
    results = ev.evaluate(
        _cases(),
        {
            "always_high": _runner(0.95, "high"),
            "autosiem": decision_baseline.decide,
        },
        SECURITY_QUESTIONS,
    )
    assert results["cases"] == 2
    assert sorted(results["paths"]) == ["always_high", "autosiem"]
    # The stub is right on c1 and wrong on c2.
    always_high = results["paths"]["always_high"]["questions"]
    assert always_high["severity"]["accuracy"] == pytest.approx(0.5)
    assert always_high["malicious"]["accuracy"] == pytest.approx(0.5)
    # The deterministic path reads severity straight from the state, so it is
    # right on both by construction. Stated so nobody mistakes it for skill.
    assert results["paths"]["autosiem"]["questions"]["severity"]["accuracy"] == pytest.approx(1.0)
    assert len(results["per_case"]) == 2


def test_errors_and_fallbacks_are_counted_not_hidden() -> None:
    def broken(state):
        raise RuntimeError("provider exploded")

    results = ev.evaluate(
        _cases(),
        {"broken": broken, "flaky": _runner(0.9, "high", fallback=True)},
        SECURITY_QUESTIONS,
    )
    broken_report = results["paths"]["broken"]
    assert broken_report["errors"] == 2
    assert broken_report["error_rate"] == pytest.approx(1.0)
    assert results["paths"]["flaky"]["fallback_rate"] == pytest.approx(1.0)
    assert "provider exploded" in results["per_case"][0]["paths"]["broken"]["error"]


def test_cost_is_computed_only_from_reported_usage() -> None:
    results = ev.evaluate(
        _cases(),
        {
            "hosted": _runner(0.9, "high", usage={"input_tokens": 500_000, "output_tokens": 1_000}),
            "local": _runner(0.9, "high"),
        },
        SECURITY_QUESTIONS,
    )
    hosted = results["paths"]["hosted"]
    # 1,000,000 input tokens over two cases at $0.042/Mtok, output free.
    assert hosted["tokens"] == {"input": 1_000_000, "output": 2_000}
    assert hosted["estimated_cost_usd"] == pytest.approx(0.042)
    # A local model reports no usage, so no cost is invented for it.
    assert results["paths"]["local"]["estimated_cost_usd"] is None
    assert "no token usage" in results["paths"]["local"]["cost_basis"]


def test_unlabelled_questions_are_not_scored() -> None:
    results = ev.evaluate(_cases(), {"stub": _runner(0.9, "high")}, SECURITY_QUESTIONS)
    questions = results["paths"]["stub"]["questions"]
    # Only malicious and severity carry labels in these cases.
    assert set(questions) == {"malicious", "severity"}
    assert results["labelled_questions"] == ["malicious", "severity"]


def test_render_report_is_readable_and_honest_about_gaps() -> None:
    results = ev.evaluate(_cases(), {"stub": _runner(0.9, "high")}, SECURITY_QUESTIONS)
    results["paths"]["jev"] = {"path": "jev", "skipped_reason": "TYPESAFE_API_KEY is not set"}
    text = ev.render_report(results)
    assert "System One evaluation" in text
    assert "skipped: TYPESAFE_API_KEY is not set" in text
    assert "accuracy=" in text and "brier=" in text


# --- case loading ----------------------------------------------------------


def test_cases_load_from_json_array_and_jsonl(tmp_path) -> None:
    rows = [
        {"id": "a", "state": {"incident": {}}, "labels": {"malicious": True}},
        {"id": "b", "state": {"incident": {}}, "labels": {"malicious": False}},
    ]
    array = tmp_path / "cases.json"
    array.write_text(json.dumps(rows), encoding="utf-8")
    lines = tmp_path / "cases.jsonl"
    lines.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    assert [case.case_id for case in ev.load_cases(str(array))] == ["a", "b"]
    assert [case.case_id for case in ev.load_cases(str(lines))] == ["a", "b"]


def test_a_case_without_a_state_is_rejected(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([{"labels": {"malicious": True}}]), encoding="utf-8")
    with pytest.raises(ValueError, match="no 'state'"):
        ev.load_cases(str(path))


# --- CLI -------------------------------------------------------------------


def _run_cli(capsys, monkeypatch, *argv: str) -> str:
    monkeypatch.setattr(sys, "argv", ["autosiem", *argv])
    main()
    return capsys.readouterr().out


def _write_cases(tmp_path) -> str:
    rows = [
        {
            "id": "c1",
            "state": {"incident": {"deterministic_severity": "critical", "deterministic_risk_score": 1000}},
            "labels": {"malicious": True, "severity": "critical", "action": "escalate"},
        },
        {
            "id": "c2",
            "state": {"incident": {"deterministic_severity": "informational", "deterministic_risk_score": 0}},
            "labels": {"malicious": False, "severity": "informational", "action": "suppress"},
        },
    ]
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return str(path)


def test_cli_evaluates_the_deterministic_path_without_any_credentials(capsys, monkeypatch, tmp_path) -> None:
    # The whole point: the harness works with no API key and no local model.
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out = _run_cli(capsys, monkeypatch, "evaluate-decisions", "--cases", _write_cases(tmp_path))
    assert "System One evaluation" in out
    assert "[autosiem]" in out
    # Jev is reported as skipped with the reason, never silently omitted.
    assert "TYPESAFE_API_KEY is not set" in out


def test_cli_writes_machine_readable_results(capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out_path = tmp_path / "results.json"
    _run_cli(
        capsys, monkeypatch, "evaluate-decisions", "--cases", _write_cases(tmp_path),
        "--json-out", str(out_path), "--provider", "autosiem",
    )
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["cases"] == 2
    assert payload["paths"]["autosiem"]["questions"]["severity"]["accuracy"] == pytest.approx(1.0)
    assert payload["config"]["provider"] == "none"
    assert "TYPESAFE_API_KEY" not in json.dumps(payload)


def test_cli_json_format_parses(capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out = _run_cli(
        capsys, monkeypatch, "evaluate-decisions", "--cases", _write_cases(tmp_path),
        "--provider", "autosiem", "--format", "json",
    )
    assert json.loads(out)["cases"] == 2


def test_cli_refuses_an_unknown_path_and_a_missing_file(capsys, monkeypatch, tmp_path) -> None:
    with pytest.raises(SystemExit) as exc:
        _run_cli(capsys, monkeypatch, "evaluate-decisions", "--cases", _write_cases(tmp_path), "--provider", "gpt5")
    assert "unknown decision path" in str(exc.value)

    with pytest.raises(SystemExit) as exc:
        _run_cli(capsys, monkeypatch, "evaluate-decisions", "--cases", str(tmp_path / "absent.json"))
    # A missing file is an operator error, reported as one line, not a traceback.
    assert "could not read labelled cases" in str(exc.value)
    assert "Traceback" not in str(exc.value)


def test_cli_requesting_only_an_unavailable_path_explains_why(capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        _run_cli(capsys, monkeypatch, "evaluate-decisions", "--cases", _write_cases(tmp_path), "--provider", "jev")
    assert "TYPESAFE_API_KEY is not set" in str(exc.value)


def test_cli_decisions_command_shows_config_and_stored_stats(capsys, monkeypatch, tmp_path) -> None:
    out = _run_cli(capsys, monkeypatch, "decisions", "--db", str(tmp_path / "d.db"))
    payload = json.loads(out)
    assert payload["config"]["provider"] == "none"
    assert payload["stored"]["total"] == 0


# --- the deterministic baseline it is compared against ---------------------


def test_the_deterministic_baseline_reads_the_engine_verdict() -> None:
    result = decision_baseline.decide(
        {"incident": {"deterministic_severity": "critical", "deterministic_risk_score": 1000}}
    )
    assert result.provider == "autosiem"
    assert _answer(result, "severity").selected == "critical"
    assert _answer(result, "action").selected == "escalate"
    assert _answer(result, "malicious").value == pytest.approx(0.98)
    # Local arithmetic reports no tokens.
    assert result.usage == {}


def test_the_deterministic_baseline_is_conservative_on_quiet_incidents() -> None:
    result = decision_baseline.decide(
        {"incident": {"deterministic_severity": "informational", "deterministic_risk_score": 0}}
    )
    assert _answer(result, "malicious").selected is False
    assert _answer(result, "action").selected == "suppress"


def test_the_deterministic_baseline_survives_a_junk_state() -> None:
    # The harness must not crash on a malformed case file.
    result = decision_baseline.decide({"incident": {"deterministic_severity": "nonsense", "deterministic_risk_score": "abc"}})
    assert _answer(result, "severity").selected == "informational"

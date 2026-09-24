"""Compare decision paths on identical incidents.

The point is to make claims falsifiable. Every provider sees the same state and
the same questions, and the deterministic AutoSIEM path is scored as a
competitor rather than assumed correct, because "the SIEM already does this" is
the claim being tested.

Metrics, and what each is for:

accuracy
    Fraction correct, per question. Blunt, but the number people ask for.
confusion
    Where the errors actually are. A severity model that only ever confuses
    ``high`` with ``critical`` is a different animal from one that calls
    ``critical`` incidents ``low``.
Brier score
    Mean squared error of the probability on the binary ``malicious`` call.
    Lower is better; 0.25 is what you get by always saying 0.5. This is the
    honest measure for a probabilistic answer, since accuracy throws the
    probability away.
ECE (expected calibration error)
    Binned |confidence - accuracy|. A model that says 0.9 should be right about
    90% of the time; ECE says how far off that is. Reported with its bin count
    because ECE is sensitive to binning and a single number without it is not
    comparable across runs.
latency, error rate, fallback rate
    Operational cost of putting the thing in the path.
tokens / cost
    Only for providers that report usage. Jev reports input and output tokens,
    so cost is computed from a configured price; Laya runs locally and reports
    nothing, and is shown as no cost rather than a guessed one.

A labelled case is a JSON object with a ``state`` (or an ``incident``/``findings``
pair to build one from) and a ``labels`` mapping, for example::

    {"id": "case-1", "labels": {"malicious": true, "severity": "high", "action": "investigate"}}

Nothing here fabricates data: if a provider is not configured it is skipped and
the report says so.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .types import DecisionQuestion, DecisionResult, DecisionState

#: Jev's published price: $0.042 per million input tokens, output free.
JEV_INPUT_COST_PER_MTOK = 0.042
JEV_OUTPUT_COST_PER_MTOK = 0.0


@dataclass(slots=True)
class LabelledCase:
    """One incident with ground truth attached."""

    case_id: str
    state: DecisionState
    labels: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], index: int) -> "LabelledCase":
        state = raw.get("state")
        if state is None:
            raise ValueError(f"case {index}: no 'state' (or build one first with build_state)")
        labels = raw.get("labels") or {}
        if not isinstance(labels, Mapping):
            raise ValueError(f"case {index}: 'labels' must be a mapping")
        return cls(case_id=str(raw.get("id") or f"case-{index}"), state=dict(state) if isinstance(state, Mapping) else state, labels=dict(labels))


def load_cases(path: str) -> list[LabelledCase]:
    """Read a JSON array or a JSONL file of labelled cases."""
    text = open(path, encoding="utf-8").read().strip()
    if not text:
        return []
    if text.startswith("["):
        raw_cases = json.loads(text)
    else:
        raw_cases = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [LabelledCase.from_dict(raw, index) for index, raw in enumerate(raw_cases, start=1)]


def brier_score(pairs: Sequence[tuple[float, bool]]) -> float | None:
    """Mean squared error between predicted probability and outcome."""
    if not pairs:
        return None
    return sum((probability - (1.0 if actual else 0.0)) ** 2 for probability, actual in pairs) / len(pairs)


def expected_calibration_error(
    pairs: Sequence[tuple[float, bool]], bins: int = 10
) -> float | None:
    """Binned |confidence - accuracy|, weighted by bin population.

    ``pairs`` is (confidence in the predicted side, whether it was right).
    """
    if not pairs:
        return None
    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for confidence, correct in pairs:
        index = min(bins - 1, max(0, int(confidence * bins)))
        buckets[index].append((confidence, correct))
    total = len(pairs)
    error = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        mean_confidence = sum(confidence for confidence, _ in bucket) / len(bucket)
        accuracy = sum(1 for _, correct in bucket if correct) / len(bucket)
        error += (len(bucket) / total) * abs(mean_confidence - accuracy)
    return error


@dataclass(slots=True)
class QuestionScore:
    """Per-question tally."""

    question: str
    correct: int = 0
    total: int = 0
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    probability_pairs: list[tuple[float, bool]] = field(default_factory=list)
    confidence_pairs: list[tuple[float, bool]] = field(default_factory=list)

    @property
    def accuracy(self) -> float | None:
        return self.correct / self.total if self.total else None

    def record(self, expected: Any, predicted: Any, *, probability: float | None, confidence: float | None) -> None:
        self.total += 1
        correct = _labels_match(expected, predicted)
        if correct:
            self.correct += 1
        row = self.confusion.setdefault(_label_key(expected), {})
        row[_label_key(predicted)] = row.get(_label_key(predicted), 0) + 1
        if probability is not None and isinstance(expected, bool):
            self.probability_pairs.append((probability, expected))
        if confidence is not None:
            self.confidence_pairs.append((confidence, correct))

    def to_dict(self, *, ece_bins: int = 10) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "question": self.question,
            "scored": self.total,
            "correct": self.correct,
            "accuracy": self.accuracy,
            "confusion": {expected: dict(row) for expected, row in sorted(self.confusion.items())},
        }
        brier = brier_score(self.probability_pairs)
        if brier is not None:
            payload["brier_score"] = brier
            payload["brier_baseline_always_half"] = 0.25
        ece = expected_calibration_error(self.confidence_pairs, bins=ece_bins)
        if ece is not None:
            payload["ece"] = ece
            payload["ece_bins"] = ece_bins
            payload["ece_samples"] = len(self.confidence_pairs)
        return payload


def _label_key(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _labels_match(expected: Any, predicted: Any) -> bool:
    if isinstance(expected, bool) or isinstance(predicted, bool):
        return _label_key(expected) == _label_key(predicted)
    return str(expected).lower() == str(predicted).lower()


@dataclass(slots=True)
class PathReport:
    """One decision path's results over the whole case set."""

    path: str
    model: str = ""
    cases: int = 0
    errors: int = 0
    fallbacks: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    scores: dict[str, QuestionScore] = field(default_factory=dict)
    skipped_reason: str = ""

    def score_for(self, question: str) -> QuestionScore:
        return self.scores.setdefault(question, QuestionScore(question=question))

    @property
    def error_rate(self) -> float | None:
        return self.errors / self.cases if self.cases else None

    @property
    def fallback_rate(self) -> float | None:
        return self.fallbacks / self.cases if self.cases else None

    def latency_percentile(self, fraction: float) -> float | None:
        if not self.latencies_ms:
            return None
        ordered = sorted(self.latencies_ms)
        index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
        return ordered[index]

    def estimated_cost_usd(self) -> float | None:
        """Only for providers that report token usage. None means unknown."""
        if not (self.input_tokens or self.output_tokens):
            return None
        return (self.input_tokens / 1_000_000) * JEV_INPUT_COST_PER_MTOK + (
            self.output_tokens / 1_000_000
        ) * JEV_OUTPUT_COST_PER_MTOK

    def to_dict(self, *, ece_bins: int = 10) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "model": self.model,
            "cases": self.cases,
            "errors": self.errors,
            "error_rate": self.error_rate,
            "fallbacks": self.fallbacks,
            "fallback_rate": self.fallback_rate,
            "latency_ms": {
                "mean": sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else None,
                "p50": self.latency_percentile(0.5),
                "p95": self.latency_percentile(0.95),
                "samples": len(self.latencies_ms),
            },
            "questions": {name: score.to_dict(ece_bins=ece_bins) for name, score in sorted(self.scores.items())},
        }
        if self.skipped_reason:
            payload["skipped_reason"] = self.skipped_reason
        if self.input_tokens or self.output_tokens:
            payload["tokens"] = {"input": self.input_tokens, "output": self.output_tokens}
            payload["estimated_cost_usd"] = self.estimated_cost_usd()
            payload["cost_basis"] = (
                f"${JEV_INPUT_COST_PER_MTOK}/Mtok input, ${JEV_OUTPUT_COST_PER_MTOK}/Mtok output"
            )
        else:
            payload["estimated_cost_usd"] = None
            payload["cost_basis"] = "no token usage reported by this path"
        return payload


#: A decision path under test: a name plus a callable taking the state and
#: returning a DecisionResult. The deterministic AutoSIEM path is wrapped the
#: same way so it is scored on equal terms.
PathRunner = Any


def evaluate(
    cases: Iterable[LabelledCase],
    paths: Mapping[str, PathRunner],
    questions: Mapping[str, DecisionQuestion],
    *,
    ece_bins: int = 10,
) -> dict[str, Any]:
    """Run every case through every path and score the answers."""
    case_list = list(cases)
    reports: dict[str, PathReport] = {name: PathReport(path=name) for name in paths}
    per_case: list[dict[str, Any]] = []

    for case in case_list:
        case_row: dict[str, Any] = {"id": case.case_id, "labels": dict(case.labels), "paths": {}}
        for name, runner in paths.items():
            report = reports[name]
            report.cases += 1
            started = time.perf_counter()
            try:
                result: DecisionResult = runner(case.state)
            except Exception as exc:
                report.errors += 1
                case_row["paths"][name] = {"error": f"{type(exc).__name__}: {exc}"}
                continue
            elapsed = result.latency_ms if result.latency_ms else (time.perf_counter() - started) * 1000
            report.latencies_ms.append(elapsed)
            report.model = report.model or result.model
            if result.fallback_used:
                report.fallbacks += 1
            report.input_tokens += int(result.usage.get("input_tokens", 0) or 0)
            report.output_tokens += int(result.usage.get("output_tokens", 0) or 0)

            answers_row: dict[str, Any] = {}
            for question_name in questions:
                answer = result.answer(question_name)
                if answer is None:
                    continue
                answers_row[question_name] = {
                    "selected": answer.selected,
                    "confidence": answer.confidence,
                    "value": answer.value,
                }
                if question_name in case.labels:
                    reports[name].score_for(question_name).record(
                        case.labels[question_name],
                        answer.selected,
                        probability=answer.value,
                        confidence=answer.certainty,
                    )
            case_row["paths"][name] = {
                "model": result.model,
                "latency_ms": elapsed,
                "fallback_used": result.fallback_used,
                "answers": answers_row,
            }
        per_case.append(case_row)

    return {
        "cases": len(case_list),
        "labelled_questions": sorted({key for case in case_list for key in case.labels}),
        "paths": {name: report.to_dict(ece_bins=ece_bins) for name, report in reports.items()},
        "per_case": per_case,
    }


def render_report(results: Mapping[str, Any]) -> str:
    """A short human-readable summary of :func:`evaluate` output."""
    lines = [
        "System One evaluation",
        f"Cases: {results.get('cases', 0)}",
        f"Labelled questions: {', '.join(results.get('labelled_questions') or []) or 'none'}",
        "",
    ]
    for name, report in sorted((results.get("paths") or {}).items()):
        lines.append(f"[{name}] model={report.get('model') or 'n/a'}")
        if report.get("skipped_reason"):
            lines.append(f"  skipped: {report['skipped_reason']}")
            lines.append("")
            continue
        latency = report.get("latency_ms") or {}
        mean = latency.get("mean")
        p95 = latency.get("p95")
        lines.append(
            "  cases={cases} errors={errors} ({rate}) fallbacks={fallbacks}".format(
                cases=report.get("cases"),
                errors=report.get("errors"),
                rate=_percent(report.get("error_rate")),
                fallbacks=report.get("fallbacks"),
            )
        )
        lines.append(
            f"  latency mean={_ms(mean)} p95={_ms(p95)}  cost={_cost(report.get('estimated_cost_usd'))}"
        )
        for question, score in sorted((report.get("questions") or {}).items()):
            parts = [f"  {question}: accuracy={_percent(score.get('accuracy'))} (n={score.get('scored')})"]
            if score.get("brier_score") is not None:
                parts.append(f"brier={score['brier_score']:.4f}")
            if score.get("ece") is not None:
                parts.append(f"ece={score['ece']:.4f}@{score.get('ece_bins')}bins")
            lines.append("  ".join(parts))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _percent(value: Any) -> str:
    return "n/a" if value is None else f"{float(value) * 100:.1f}%"


def _ms(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.0f}ms"


def _cost(value: Any) -> str:
    return "n/a" if value is None else f"${float(value):.6f}"

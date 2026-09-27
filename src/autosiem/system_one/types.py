"""Typed decision primitives, provider-agnostic.

A "System One" model answers typed *questions* about a *state* and returns a
value plus a probability distribution, rather than prose. Three question types
cover what AutoSIEM needs:

``noul``
    A yes/no question answered with P(true). Carries **no** confidence of its
    own: the distribution is the answer.
``choice``
    Pick one of several named options. Carries confidence.
``score``
    An ordered scale (level 0, 1, 2 ...). Carries confidence.

Everything here is stdlib dataclasses, matching the rest of ``src/autosiem``.
Provider payloads are normalized into :class:`DecisionAnswer` so nothing
downstream can tell which model answered.

**Validation fails closed.** A malformed provider response raises
:class:`DecisionInvalid` and is never coerced into a usable classification: a
silently-defaulted "benign" would be a detection gap wearing a valid shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

#: The evidence bundle handed to a provider. A plain JSON-able mapping so it can
#: be logged, diffed and (for remote providers) inspected before it is sent.
DecisionState = dict[str, Any]

NOUL = "noul"
CHOICE = "choice"
SCORE = "score"
QUESTION_TYPES = frozenset({NOUL, CHOICE, SCORE})


class DecisionError(Exception):
    """Base class for every System One failure."""


class DecisionUnavailable(DecisionError):
    """The provider could not be reached, timed out, or refused the request.

    Distinct from :class:`DecisionInvalid` on purpose, and distinct again from a
    low-confidence answer: those are three different states and the engine
    treats them differently.
    """


class DecisionInvalid(DecisionError):
    """The provider answered, but the answer did not survive validation."""


class DecisionConfigError(DecisionError):
    """The provider is configured incompletely (for example, no API key)."""


@dataclass(frozen=True, slots=True)
class DecisionQuestion:
    """One typed question.

    ``criteria`` is a mapping of option name to description for ``choice``, an
    ordered list of level descriptions for ``score``, and optionally a
    ``{"true": ..., "false": ...}`` mapping for ``noul``.
    """

    type: str
    instructions: str
    criteria: Mapping[str, str] | list[str] | None = None

    def __post_init__(self) -> None:
        if self.type not in QUESTION_TYPES:
            raise ValueError(f"unknown question type {self.type!r} (expected one of {sorted(QUESTION_TYPES)})")
        if not self.instructions.strip():
            raise ValueError("a question needs instructions")
        if self.type == CHOICE:
            if not isinstance(self.criteria, Mapping) or len(self.criteria) < 2:
                raise ValueError("a choice question needs a criteria mapping with at least two options")
        elif self.type == SCORE:
            if not isinstance(self.criteria, list) or len(self.criteria) < 2:
                raise ValueError("a score question needs an ordered list of at least two levels")
        elif self.criteria is not None and not isinstance(self.criteria, Mapping):
            raise ValueError("noul criteria, when given, is a {'true': ..., 'false': ...} mapping")

    @property
    def options(self) -> tuple[str, ...]:
        """The valid answers: option names for choice, level labels for score."""
        if self.type == CHOICE and isinstance(self.criteria, Mapping):
            return tuple(self.criteria)
        if self.type == SCORE and isinstance(self.criteria, list):
            return tuple(str(level) for level in self.criteria)
        return ("true", "false")

    def to_payload(self) -> dict[str, Any]:
        """The wire form. Jev and Laya accept the same question shape."""
        payload: dict[str, Any] = {"type": self.type, "instructions": self.instructions}
        if self.criteria is not None:
            payload["criteria"] = dict(self.criteria) if isinstance(self.criteria, Mapping) else list(self.criteria)
        return payload


@dataclass(frozen=True, slots=True)
class DecisionAnswer:
    """One normalized answer.

    ``selected`` is a bool for ``noul``, an option name for ``choice``, and a
    level label for ``score``. ``value`` keeps the provider's raw numeric where
    there is one (P(true) for noul, the fractional level for score), because
    rounding a 1.49 score to a label throws away information a reviewer wants.
    """

    type: str
    selected: str | bool | None
    probabilities: dict[str, float] = field(default_factory=dict)
    confidence: float | None = None
    value: float | None = None

    @property
    def certainty(self) -> float:
        """A single 0..1 number to threshold on, whatever the question type.

        ``confidence`` when the provider reports one (choice, score). For a
        noul it is the distance from a coin flip expressed as P(selected side),
        since a noul carries no confidence field: P(true)=0.94 is as decisive as
        P(true)=0.06, and both are more decisive than 0.5.
        """
        if self.confidence is not None:
            return self.confidence
        if self.probabilities:
            return max(self.probabilities.values())
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "selected": self.selected,
            "probabilities": dict(self.probabilities),
            "confidence": self.confidence,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class DecisionResult:
    """A provider's full answer set for one decision request."""

    provider: str
    model: str
    answers: dict[str, DecisionAnswer]
    latency_ms: float
    fallback_used: bool = False
    usage: dict[str, int] = field(default_factory=dict)

    def answer(self, name: str) -> DecisionAnswer | None:
        return self.answers.get(name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "answers": {name: answer.to_dict() for name, answer in self.answers.items()},
            "latency_ms": round(self.latency_ms, 3),
            "fallback_used": self.fallback_used,
            "usage": dict(self.usage),
        }


def _probability(value: Any, *, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DecisionInvalid(f"{where}: expected a number, got {value!r}")
    number = float(value)
    if not 0.0 <= number <= 1.0:
        raise DecisionInvalid(f"{where}: probability {number} is outside 0..1")
    return number


def _probability_map(raw: Any, *, allowed: Iterable[str], where: str) -> dict[str, float]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise DecisionInvalid(f"{where}: probabilities must be a mapping, got {type(raw).__name__}")
    allowed_set = set(allowed)
    out: dict[str, float] = {}
    for key, value in raw.items():
        name = str(key)
        if name not in allowed_set:
            raise DecisionInvalid(f"{where}: probability for unknown option {name!r}")
        out[name] = _probability(value, where=f"{where}[{name}]")
    return out


def _confidence(raw: Any, *, where: str) -> float | None:
    if raw is None:
        return None
    return _probability(raw, where=f"{where}.confidence")


def normalize_answer(name: str, question: DecisionQuestion, raw: Any) -> DecisionAnswer:
    """Validate one provider answer and normalize it. Raises on anything odd.

    Jev and Laya report the same shapes, so one normalizer serves both:
    ``{"type": "noul", "noul": 0.95}``,
    ``{"type": "choice", "choice": "billing", "probabilities": {...}, "confidence": 0.81}``,
    ``{"type": "score", "score": 1.05, "legend": {"0": "Calm", ...}, "probabilities": {...}, "confidence": 0.92}``.
    """
    where = f"answer {name!r}"
    if not isinstance(raw, Mapping):
        raise DecisionInvalid(f"{where}: expected an object, got {type(raw).__name__}")
    reported = raw.get("type", question.type)
    if reported != question.type:
        raise DecisionInvalid(f"{where}: asked a {question.type} question, got a {reported!r} answer")

    if question.type == NOUL:
        if "noul" not in raw:
            raise DecisionInvalid(f"{where}: noul answer has no 'noul' probability")
        probability = _probability(raw["noul"], where=f"{where}.noul")
        selected = probability >= 0.5
        return DecisionAnswer(
            type=NOUL,
            selected=selected,
            probabilities={"true": probability, "false": round(1.0 - probability, 10)},
            # A noul carries no confidence field; see DecisionAnswer.certainty.
            confidence=None,
            value=probability,
        )

    if question.type == CHOICE:
        chosen = raw.get("choice")
        if not isinstance(chosen, str):
            raise DecisionInvalid(f"{where}: choice answer has no 'choice' string")
        if chosen not in question.options:
            raise DecisionInvalid(f"{where}: chose {chosen!r}, which was not one of {list(question.options)}")
        return DecisionAnswer(
            type=CHOICE,
            selected=chosen,
            probabilities=_probability_map(raw.get("probabilities"), allowed=question.options, where=where),
            confidence=_confidence(raw.get("confidence"), where=where),
        )

    levels = question.options
    if "score" not in raw:
        raise DecisionInvalid(f"{where}: score answer has no 'score' value")
    numeric = raw["score"]
    if isinstance(numeric, bool) or not isinstance(numeric, (int, float)):
        raise DecisionInvalid(f"{where}.score: expected a number, got {numeric!r}")
    numeric = float(numeric)
    if not -0.5 <= numeric <= len(levels) - 0.5:
        raise DecisionInvalid(f"{where}.score: {numeric} is outside the 0..{len(levels) - 1} scale")
    index = max(0, min(len(levels) - 1, int(round(numeric))))
    # The provider keys score probabilities by level index; map them onto the
    # caller's labels so downstream code never sees positional keys.
    raw_probabilities = raw.get("probabilities")
    by_label: dict[str, float] = {}
    if raw_probabilities is not None:
        if not isinstance(raw_probabilities, Mapping):
            raise DecisionInvalid(f"{where}: probabilities must be a mapping")
        for key, value in raw_probabilities.items():
            try:
                position = int(str(key))
            except ValueError as exc:
                raise DecisionInvalid(f"{where}: score probability key {key!r} is not a level index") from exc
            if not 0 <= position < len(levels):
                raise DecisionInvalid(f"{where}: score probability for level {position} outside the scale")
            by_label[levels[position]] = _probability(value, where=f"{where}[{position}]")
    return DecisionAnswer(
        type=SCORE,
        selected=levels[index],
        probabilities=by_label,
        confidence=_confidence(raw.get("confidence"), where=where),
        value=numeric,
    )


def normalize_answers(
    questions: Mapping[str, DecisionQuestion], raw: Any
) -> dict[str, DecisionAnswer]:
    """Validate a whole answer set: every question answered, nothing extra."""
    if not isinstance(raw, Mapping):
        raise DecisionInvalid(f"answers must be a mapping, got {type(raw).__name__}")
    missing = [name for name in questions if name not in raw]
    if missing:
        raise DecisionInvalid(f"provider did not answer: {', '.join(sorted(missing))}")
    unexpected = [str(name) for name in raw if name not in questions]
    if unexpected:
        raise DecisionInvalid(f"provider answered questions that were not asked: {', '.join(sorted(unexpected))}")
    return {name: normalize_answer(name, question, raw[name]) for name, question in questions.items()}

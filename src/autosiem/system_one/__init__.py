"""System One decision layer: fast typed classification beside the detectors.

A System One model answers typed questions with a value and a probability
distribution instead of prose. AutoSIEM uses one as an **extra signal** on a
correlated incident: is this malicious, how severe, what next, and is it murky
enough to be worth a full generative write-up.

It is optional, off by default, and deliberately not authoritative. The
deterministic rules, UEBA scoring, risk model and :mod:`autosiem.policy` gates
decide what actually happens; this layer only annotates. Providers:

* :class:`~autosiem.system_one.providers.JevDecisionProvider` - TypeSafe Jev,
  hosted and proprietary.
* :class:`~autosiem.system_one.providers.LayaDecisionProvider` -
  ``laya-typed-decisions``, open weights (Apache 2.0), runs on the host.

See ``README.md`` for configuration and ``docs/system-one.md`` for the design.
"""

from __future__ import annotations

from .config import (
    JEV_MODEL,
    LAYA_MODEL,
    PROVIDER_JEV,
    PROVIDER_LAYA,
    PROVIDER_NONE,
    DecisionConfig,
    config_from_env,
)
from .engine import (
    DISPOSITION_ACCEPTED,
    DISPOSITION_IGNORED,
    DISPOSITION_REVIEW,
    DISPOSITION_UNAVAILABLE,
    DecisionEngine,
    DecisionOutcome,
)
from .providers import (
    DecisionProvider,
    DisabledDecisionProvider,
    JevDecisionProvider,
    LayaDecisionProvider,
    build_provider,
)
from .questions import ACTIONS, SECURITY_QUESTIONS, SEVERITY_LEVELS, build_state
from .types import (
    CHOICE,
    NOUL,
    SCORE,
    DecisionAnswer,
    DecisionError,
    DecisionInvalid,
    DecisionQuestion,
    DecisionResult,
    DecisionState,
    DecisionUnavailable,
    normalize_answer,
    normalize_answers,
)

__all__ = [
    "ACTIONS",
    "CHOICE",
    "DISPOSITION_ACCEPTED",
    "DISPOSITION_IGNORED",
    "DISPOSITION_REVIEW",
    "DISPOSITION_UNAVAILABLE",
    "JEV_MODEL",
    "LAYA_MODEL",
    "NOUL",
    "PROVIDER_JEV",
    "PROVIDER_LAYA",
    "PROVIDER_NONE",
    "SCORE",
    "SECURITY_QUESTIONS",
    "SEVERITY_LEVELS",
    "DecisionAnswer",
    "DecisionConfig",
    "DecisionEngine",
    "DecisionError",
    "DecisionInvalid",
    "DecisionOutcome",
    "DecisionProvider",
    "DecisionQuestion",
    "DecisionResult",
    "DecisionState",
    "DecisionUnavailable",
    "DisabledDecisionProvider",
    "JevDecisionProvider",
    "LayaDecisionProvider",
    "build_provider",
    "build_state",
    "config_from_env",
    "normalize_answer",
    "normalize_answers",
]

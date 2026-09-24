"""System One configuration, read from the environment in one place.

Thresholds are configuration, not literals scattered through the engine, so an
operator can retune them without reading the code and a reviewer can see every
tunable at once. Defaults are deliberately conservative: the subsystem is
**off** unless a provider is named, and even when on it never gates the existing
generative LLM step unless asked to.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping

PROVIDER_NONE = "none"
PROVIDER_JEV = "jev"
PROVIDER_LAYA = "laya"
PROVIDERS = (PROVIDER_NONE, PROVIDER_JEV, PROVIDER_LAYA)

#: TypeSafe's documented endpoint and default model alias.
JEV_URL = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-latest"
#: The open-weight checkpoint trained for typed decisions (Apache 2.0).
LAYA_MODEL = "convaiinnovations/laya-typed-decisions"


def _env(values: Mapping[str, str], name: str, default: str = "") -> str:
    return (values.get(name) or default).strip()


def _float(values: Mapping[str, str], name: str, default: float) -> float:
    raw = _env(values, name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _int(values: Mapping[str, str], name: str, default: int) -> int:
    raw = _env(values, name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _bool(values: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = _env(values, name).lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class JevConfig:
    """TypeSafe Jev: hosted, so this is the remote path."""

    api_key: str = ""
    model: str = JEV_MODEL
    url: str = JEV_URL
    timeout: float = 10.0
    #: Retries for throttling and overload only (429/529 and transport errors).
    #: A 401 or a validation failure is not retried; it will not become valid.
    retries: int = 2
    backoff_seconds: float = 0.5

    @property
    def configured(self) -> bool:
        return bool(self.api_key)


@dataclass(frozen=True, slots=True)
class LayaConfig:
    """Laya: open weights, runs on the host, so no key and no network."""

    model: str = LAYA_MODEL
    #: "auto" picks CUDA, then Apple MPS, then CPU.
    device: str = "auto"


@dataclass(frozen=True, slots=True)
class DecisionConfig:
    """The whole subsystem's configuration."""

    provider: str = PROVIDER_NONE
    fallback: str = PROVIDER_NONE
    #: Accept the classification as a signal at or above this certainty.
    accept_threshold: float = 0.75
    #: Below ``accept`` but at or above this: treat as ambiguous (enrich, or let
    #: the generative LLM look at it). Below it: ignore the answer entirely and
    #: use the deterministic result, which is what happens with no provider.
    review_threshold: float = 0.5
    #: A low-confidence answer is NOT a provider failure. Falling back to a
    #: second model to shop for a more confident answer is opt-in.
    fallback_on_low_confidence: bool = False
    #: When true, ``needs_llm_analysis`` may suppress the generative LLM call for
    #: clear-cut incidents. Off by default so enabling System One does not change
    #: what the existing LLM layer does.
    gate_llm: bool = False
    #: Caps on what is sent to a provider.
    max_findings: int = 20
    max_events: int = 10
    jev: JevConfig = field(default_factory=JevConfig)
    laya: LayaConfig = field(default_factory=LayaConfig)

    @property
    def enabled(self) -> bool:
        return self.provider != PROVIDER_NONE

    def describe(self) -> dict[str, object]:
        """Config without secrets, for `cli` output and audit details."""
        return {
            "provider": self.provider,
            "fallback": self.fallback,
            "accept_threshold": self.accept_threshold,
            "review_threshold": self.review_threshold,
            "fallback_on_low_confidence": self.fallback_on_low_confidence,
            "gate_llm": self.gate_llm,
            "jev_model": self.jev.model,
            "jev_key_configured": self.jev.configured,
            "laya_model": self.laya.model,
            "laya_device": self.laya.device,
        }


def _provider_name(raw: str, *, what: str) -> str:
    value = (raw or PROVIDER_NONE).lower()
    if value not in PROVIDERS:
        raise ValueError(f"unknown {what} {raw!r}; expected one of {', '.join(PROVIDERS)}")
    return value


def config_from_env(env: Mapping[str, str] | None = None) -> DecisionConfig:
    """Build the config. Unset ``AUTOSIEM_DECISION_PROVIDER`` means disabled."""
    values = dict(os.environ) if env is None else dict(env)
    provider = _provider_name(_env(values, "AUTOSIEM_DECISION_PROVIDER", PROVIDER_NONE), what="decision provider")
    fallback = _provider_name(_env(values, "AUTOSIEM_DECISION_FALLBACK", PROVIDER_NONE), what="decision fallback")
    if fallback != PROVIDER_NONE and fallback == provider:
        # Retrying the same provider is what `retries` is for.
        fallback = PROVIDER_NONE
    return DecisionConfig(
        provider=provider,
        fallback=fallback,
        accept_threshold=_float(values, "AUTOSIEM_DECISION_ACCEPT_CONFIDENCE", 0.75),
        review_threshold=_float(values, "AUTOSIEM_DECISION_REVIEW_CONFIDENCE", 0.5),
        fallback_on_low_confidence=_bool(values, "AUTOSIEM_DECISION_FALLBACK_ON_LOW_CONFIDENCE"),
        gate_llm=_bool(values, "AUTOSIEM_DECISION_GATE_LLM"),
        max_findings=_int(values, "AUTOSIEM_DECISION_MAX_FINDINGS", 20),
        max_events=_int(values, "AUTOSIEM_DECISION_MAX_EVENTS", 10),
        jev=JevConfig(
            api_key=_env(values, "TYPESAFE_API_KEY"),
            model=_env(values, "AUTOSIEM_JEV_MODEL", JEV_MODEL),
            url=_env(values, "AUTOSIEM_JEV_URL", JEV_URL),
            timeout=_float(values, "AUTOSIEM_JEV_TIMEOUT", 10.0),
            retries=_int(values, "AUTOSIEM_JEV_RETRIES", 2),
            backoff_seconds=_float(values, "AUTOSIEM_JEV_BACKOFF", 0.5),
        ),
        laya=LayaConfig(
            model=_env(values, "AUTOSIEM_LAYA_MODEL", LAYA_MODEL),
            device=_env(values, "AUTOSIEM_LAYA_DEVICE", "auto").lower() or "auto",
        ),
    )

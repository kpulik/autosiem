"""Decision providers: hosted Jev, local Laya, and disabled.

``decide`` is **synchronous**. The reference design for this subsystem used
``async def``, but ``AutoSIEMPipeline.process_lines`` is synchronous top to
bottom and so is every storage call under it; an async provider would mean
spinning an event loop inside a sync pipeline for one HTTP request. Following
the repository's shape is worth more here than matching the sketch. Providers
are small enough that an async variant could be added later without touching
callers.

Jev is reached with stdlib ``urllib`` rather than the TypeSafe SDK: ``src/autosiem``
carries no runtime dependencies, which is why the Sigma parser and the SigV4
signer are hand-rolled too. Laya is a genuine optional extra (``pip install
'.[laya]'``) and is imported lazily, so a Jev-only or disabled install never pays
for torch.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from ..net import InsecureURLError, open_url, require_https
from .config import DecisionConfig, JevConfig, LayaConfig
from .types import (
    DecisionConfigError,
    DecisionInvalid,
    DecisionResult,
    DecisionQuestion,
    DecisionState,
    DecisionUnavailable,
    normalize_answers,
)

logger = logging.getLogger(__name__)

#: A transport takes (url, body, headers, timeout) and returns (status, text).
#: Injected in tests so no unit test needs the network, mirroring how the API
#: connectors are tested.
Transport = Callable[[str, bytes, dict[str, str], float], "tuple[int, str]"]


@runtime_checkable
class DecisionProvider(Protocol):
    """One System One model."""

    name: str

    def decide(
        self, state: DecisionState, questions: Mapping[str, DecisionQuestion]
    ) -> DecisionResult:
        """Answer every question about ``state``.

        Raises :class:`DecisionUnavailable` when the provider could not answer
        and :class:`DecisionInvalid` when it answered badly. It must never
        invent an answer.
        """
        ...


class DisabledDecisionProvider:
    """The no-op provider. Present so "disabled" is a provider, not a branch."""

    name = "none"

    def decide(
        self, state: DecisionState, questions: Mapping[str, DecisionQuestion]
    ) -> DecisionResult:
        raise DecisionUnavailable("System One is disabled (AUTOSIEM_DECISION_PROVIDER=none)")


def _urllib_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> tuple[int, str]:
    request = urllib.request.Request(url, data=body, method="POST")
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with open_url(request, timeout=timeout, allow_loopback=True) as response:
            return int(getattr(response, "status", 200) or 200), response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # a status, not a transport failure
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")
        except Exception:  # pragma: no cover - body already consumed
            detail = ""
        return int(exc.code), detail
    except (urllib.error.URLError, TimeoutError, OSError, InsecureURLError) as exc:
        raise DecisionUnavailable(f"jev request failed: {exc}") from exc


class JevDecisionProvider:
    """TypeSafe Jev over its documented ``POST /v1/systemone`` endpoint.

    Remote by definition, so the state it is handed has already been built by
    :func:`autosiem.system_one.questions.build_state`, which whitelists and
    redacts. Transport is HTTPS-only via :func:`autosiem.net.require_https`,
    loopback excepted so a local mock can be pointed at during testing.
    """

    name = "jev"

    #: Retry these: throttling and overload. 401/422 are configuration and
    #: schema errors; retrying them only wastes the operator's rate limit.
    RETRY_STATUSES = frozenset({429, 500, 502, 503, 504, 529})

    def __init__(self, config: JevConfig, transport: Transport | None = None, sleep: Callable[[float], None] = time.sleep) -> None:
        if not config.configured:
            raise DecisionConfigError("Jev needs TYPESAFE_API_KEY (never commit it; put it in the environment)")
        self.config = config
        self.url = require_https(config.url, allow_loopback=True, what="Jev decisions")
        self._transport = transport or _urllib_transport
        self._sleep = sleep

    @property
    def model(self) -> str:
        return self.config.model

    def decide(
        self, state: DecisionState, questions: Mapping[str, DecisionQuestion]
    ) -> DecisionResult:
        payload = {
            "state": state,
            "model": self.config.model,
            "questions": {name: question.to_payload() for name, question in questions.items()},
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }
        attempts = max(1, self.config.retries + 1)
        started = time.perf_counter()
        last_error: str = "no attempt was made"
        for attempt in range(attempts):
            status, text = self._transport(self.url, body, headers, self.config.timeout)
            if status == 200:
                elapsed_ms = (time.perf_counter() - started) * 1000
                return self._parse(text, questions, elapsed_ms)
            if status == 401:
                raise DecisionUnavailable("jev rejected the API key (401)")
            if status == 422:
                # Our request was wrong. Surfacing it as invalid rather than
                # unavailable keeps a bug in our question schema from looking
                # like a provider outage in the metrics.
                raise DecisionInvalid(f"jev rejected the request (422): {text[:200]}")
            last_error = f"HTTP {status}"
            if status not in self.RETRY_STATUSES or attempt == attempts - 1:
                break
            self._sleep(self.config.backoff_seconds * (2 ** attempt))
        raise DecisionUnavailable(f"jev did not answer after {attempts} attempt(s): {last_error}")

    def _parse(
        self, text: str, questions: Mapping[str, DecisionQuestion], elapsed_ms: float
    ) -> DecisionResult:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DecisionInvalid(f"jev returned invalid JSON: {exc}") from exc
        if not isinstance(data, Mapping):
            raise DecisionInvalid(f"jev returned a {type(data).__name__}, expected an object")
        answers = normalize_answers(questions, data.get("answers"))
        raw_usage = data.get("usage")
        usage_raw: Mapping[str, Any] = raw_usage if isinstance(raw_usage, Mapping) else {}
        usage = {
            key: int(value)
            for key, value in usage_raw.items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        }
        return DecisionResult(
            provider=self.name,
            # The response names the concrete version (jev-1.13.0) behind the
            # jev-latest alias; record what actually answered.
            model=str(data.get("model") or self.config.model),
            answers=answers,
            latency_ms=elapsed_ms,
            usage=usage,
        )


class LayaDecisionProvider:
    """The open-weight ``laya-typed-decisions`` checkpoint, run locally.

    The model is loaded on first use, not at construction, so configuring Laya as
    a fallback costs nothing until it is actually needed. ``loader`` is injected
    in tests, which is why no unit test needs torch or a downloaded checkpoint.
    """

    name = "laya"

    def __init__(self, config: LayaConfig, loader: Callable[[], Any] | None = None) -> None:
        self.config = config
        self._loader = loader
        self._agent: Any | None = None

    @property
    def model(self) -> str:
        return self.config.model

    def _resolve_device(self) -> str | None:
        """Pick a device. ``None`` means "let laya decide"."""
        requested = (self.config.device or "auto").lower()
        if requested and requested != "auto":
            return requested
        try:  # torch arrives with laya; absent for a Jev-only install
            import torch  # type: ignore[import-not-found]
        except Exception:
            return None
        try:
            if torch.cuda.is_available():
                return "cuda"
            mps = getattr(getattr(torch, "backends", None), "mps", None)
            if mps is not None and mps.is_available():
                return "mps"
        except Exception:  # a probe must never break a decision
            return None
        return "cpu"

    def _load(self) -> Any:
        if self._agent is not None:
            return self._agent
        if self._loader is not None:
            self._agent = self._loader()
            return self._agent
        try:
            import laya  # type: ignore[import-not-found]
        except ImportError as exc:
            raise DecisionConfigError(
                "Laya needs the optional extra: pip install '.[laya]'"
            ) from exc
        device = self._resolve_device()
        try:
            # The published examples call laya.load(model); a device argument is
            # not documented, so try it and fall back rather than assuming.
            self._agent = laya.load(self.config.model, device=device) if device else laya.load(self.config.model)
        except TypeError:
            self._agent = laya.load(self.config.model)
        except Exception as exc:
            raise DecisionUnavailable(f"laya model {self.config.model!r} failed to load: {exc}") from exc
        return self._agent

    def decide(
        self, state: DecisionState, questions: Mapping[str, DecisionQuestion]
    ) -> DecisionResult:
        agent = self._load()
        payload = {name: question.to_payload() for name, question in questions.items()}
        started = time.perf_counter()
        try:
            raw = agent.predict(state, payload)
        except Exception as exc:
            raise DecisionUnavailable(f"laya inference failed: {exc}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000
        if not isinstance(raw, Mapping):
            raise DecisionInvalid(f"laya returned a {type(raw).__name__}, expected a mapping")
        answers = normalize_answers(questions, raw.get("answers"))
        raw_routing = raw.get("routing")
        reported: Mapping[str, Any] = raw_routing if isinstance(raw_routing, Mapping) else {}
        return DecisionResult(
            provider=self.name,
            model=str(reported.get("model") or self.config.model),
            answers=answers,
            latency_ms=elapsed_ms,
            # Laya does report token counts, but local inference has no per-token
            # price. The evaluation harness prices any reported usage at Jev's
            # rate, so passing it through would invent a cost; it is dropped.
            usage={},
        )


def build_provider(
    name: str,
    config: DecisionConfig,
    *,
    transport: Transport | None = None,
    laya_loader: Callable[[], Any] | None = None,
) -> DecisionProvider:
    """Construct one provider by name. Raises :class:`DecisionConfigError`."""
    if name == "jev":
        return JevDecisionProvider(config.jev, transport=transport)
    if name == "laya":
        return LayaDecisionProvider(config.laya, loader=laya_loader)
    if name == "none":
        return DisabledDecisionProvider()
    raise DecisionConfigError(f"unknown decision provider {name!r}")

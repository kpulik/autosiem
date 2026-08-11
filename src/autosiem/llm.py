"""Optional LLM adapter layer for the AutoSIEM Analyst Runtime.

Backends are loaded and called via stdlib ``urllib`` only, so the base package
keeps zero hard third-party dependencies. Supported backends:

- ``none``            deterministic local fallback (default, always safe)
- ``ollama``          self-hosted local LLM at an Ollama /api/chat endpoint
- ``openai``          hosted OpenAI-compatible /v1/chat/completions endpoint

PII/secrets are redacted before anything leaves the process, and responses are
schema-validated and safely parsed. If a call or parse fails, the service falls
back to the deterministic local investigator so the pipeline never breaks.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .ai import Investigator
from .net import InsecureURLError, require_https
from .redaction import Redactor
from .schemas import Finding, Incident
from .soc_runtime import DecisionType

ALLOWED_DECISIONS = {d.value for d in DecisionType}


@dataclass(slots=True)
class LLMConfig:
    backend: str = "none"
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    timeout: float = 30.0
    temperature: float = 0.2
    top_p: float | None = None
    mask_pii: bool = True
    max_tokens: int = 800
    context_window: int | None = None  # model context size in tokens; used to trim prompts


def _env_int(name: str, default: int | None) -> int | None:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float | None) -> float | None:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


def config_from_env() -> LLMConfig:
    # Backend inference: if a URL is provided and the backend was not set
    # explicitly, assume any OpenAI-compatible server (LM Studio, Ollama
    # OpenAI-mode, vLLM, ...). Setup is just URL + optional API key.
    backend_env = os.environ.get("AUTOSIEM_LLM_BACKEND")
    backend = (backend_env or "none").strip().lower()
    if backend_env is None and os.environ.get("AUTOSIEM_LLM_URL"):
        backend = "openai_compat"
    return LLMConfig(
        backend=backend,
        model=os.environ.get("AUTOSIEM_LLM_MODEL"),
        base_url=os.environ.get("AUTOSIEM_LLM_URL"),
        api_key=os.environ.get("AUTOSIEM_LLM_API_KEY"),
        temperature=_env_float("AUTOSIEM_LLM_TEMPERATURE", 0.2) or 0.2,
        top_p=_env_float("AUTOSIEM_LLM_TOP_P", None),
        mask_pii=os.environ.get("AUTOSIEM_LLM_MASK_PII", "1").strip().lower() not in {"0", "false", "no"},
        max_tokens=_env_int("AUTOSIEM_LLM_MAX_TOKENS", 800) or 800,
        context_window=_env_int("AUTOSIEM_LLM_CONTEXT_WINDOW", None),
    )


class LLMError(RuntimeError):
    pass


class LLMBackend:
    """OpenAI-compatible chat completion backend via stdlib urllib."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self.base_url = (config.base_url or "http://localhost:11434").rstrip("/")

    def chat(self, system: str, user: str) -> str:
        raise NotImplementedError


class OpenAIBackend(LLMBackend):
    def __init__(self, config: LLMConfig) -> None:
        super().__init__(config)
        # api_key is optional: hosted and self-hosted (LM Studio/vLLM/etc.)
        # OpenAI-compatible servers may not require one. Only send it if present.

    def chat(self, system: str, user: str) -> str:
        url = f"{self.base_url}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.config.model or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if self.config.top_p is not None:
            payload["top_p"] = self.config.top_p
        headers = {}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        data = _post_json(url, payload, headers, self.config.timeout)
        return _extract_choice(data)


class OllamaBackend(LLMBackend):
    def chat(self, system: str, user: str) -> str:
        url = f"{self.base_url}/api/chat"
        payload: dict[str, Any] = {
            "model": self.config.model or "llama3.2",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json",
        }
        options: dict[str, Any] = {}
        if self.config.top_p is not None:
            options["top_p"] = self.config.top_p
        if self.config.max_tokens:
            options["num_predict"] = self.config.max_tokens
        if options:
            payload["options"] = options
        data = _post_json(url, payload, {}, self.config.timeout)
        return data.get("message", {}).get("content", "")


def _checked_base_url(config: LLMConfig, default: str) -> str:
    """Validate the endpoint before any prompt is built for it.

    Prompts carry incident detail, so a plaintext *remote* endpoint would put
    that on the wire in the clear. Loopback is allowed because a local model
    server never leaves the machine and is the documented default. Checked here
    rather than per-request so a misconfiguration fails at startup instead of
    silently falling back to the deterministic investigator on every incident
    (SEC-017).
    """
    url = config.base_url or default
    try:
        return require_https(url, allow_loopback=True, what="LLM prompts to")
    except InsecureURLError as exc:
        raise LLMError(str(exc)) from exc


def make_backend(config: LLMConfig) -> LLMBackend | None:
    if config.backend == "none":
        return None
    if config.backend == "openai":
        config.base_url = _checked_base_url(config, "https://api.openai.com/v1")
        return OpenAIBackend(config)
    if config.backend in {"ollama", "openai_compat"}:
        if config.backend == "ollama":
            config.base_url = _checked_base_url(config, "http://localhost:11434")
            return OllamaBackend(config)
        # openai_compat: default to LM Studio's local OpenAI-compatible endpoint.
        config.base_url = _checked_base_url(config, "http://localhost:1234/v1")
        return OpenAIBackend(config)
    raise LLMError(f"Unknown LLM backend '{config.backend}'")


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise LLMError(f"LLM request failed: {exc}") from exc


def _extract_choice(data: dict[str, Any]) -> str:
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"Unexpected LLM response shape: {data}") from exc


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract the first balanced JSON object from an LLM response."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMError("LLM response contained no JSON object")
    raw = text[start : end + 1]
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM returned invalid JSON: {exc}") from exc


DECISION_SCHEMA = ("decision_type", "confidence", "rationale", "recommended_owner", "summary")


def validate_decision(data: dict[str, Any]) -> dict[str, Any]:
    """Validate and coerce an LLM decision dict into the safe object model."""
    decision_type = str(data.get("decision_type", DecisionType.SUSPICIOUS_MONITOR.value)).strip().lower()
    if decision_type not in ALLOWED_DECISIONS:
        decision_type = DecisionType.SUSPICIOUS_MONITOR.value
    try:
        confidence = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    return {
        "decision_type": decision_type,
        "confidence": confidence,
        "rationale": str(data.get("rationale", "")).strip(),
        "recommended_owner": str(data.get("recommended_owner", "tier-2-analyst")).strip(),
        "summary": str(data.get("summary", "")).strip(),
    }


@dataclass(slots=True)
class AnnotationResult:
    report: str
    decision: dict[str, Any] | None
    used_llm: bool = False


class LLMService:
    """Investigation report + decision provider with safe local fallback."""

    def __init__(self, config: LLMConfig | None = None, redactor: Redactor | None = None) -> None:
        self.config = config or config_from_env()
        self.redactor = redactor or Redactor(mask_pii=self.config.mask_pii)
        self.backend = make_backend(self.config)
        self.local = Investigator()

    @property
    def enabled(self) -> bool:
        return self.backend is not None

    def annotate(self, incident: Incident, findings: list[Finding], extra_context: str = "") -> AnnotationResult:
        related = [finding for finding in findings if finding.finding_id in incident.finding_ids]
        if self.backend is None:
            return AnnotationResult(report=self.local.explain(incident, related), decision=None)

        system = (
            "You are the AutoSIEM SOC analyst runtime. Given an incident and its findings, "
            "write a concise investigation report (a few short paragraphs) for a tier-2 analyst. "
            "Then return a JSON object at the end with keys: decision_type (one of "
            "likely_benign, suspicious_monitor, escalate, containment_proposed), confidence "
            "(0.0-1.0), rationale, recommended_owner, summary. Base every claim on the provided "
            "evidence only. Do not invent facts."
        )
        user = self._build_user_prompt(incident, related, extra_context=extra_context)
        system, user = self._fit_context(system, user, incident, related, extra_context=extra_context)
        try:
            raw = self.backend.chat(system, user)
            payload = extract_json_object(raw)
            decision = validate_decision(payload)
            report = str(payload.get("report") or payload.get("summary") or self.local.explain(incident, related))
            return AnnotationResult(report=report, decision=decision, used_llm=True)
        except (LLMError, ValueError, TypeError):
            # Safe fallback: never let the pipeline break because an LLM is flaky.
            return AnnotationResult(report=self.local.explain(incident, related), decision=None)

    def _build_user_prompt(self, incident: Incident, findings: list[Finding], max_evidence: int | None = None, extra_context: str = "") -> str:
        incident_doc = self.redactor.redact(
            json.dumps(
                {
                    "title": incident.title,
                    "severity": incident.severity.name.lower(),
                    "risk_score": incident.risk_score,
                    "entities": incident.entities,
                    "mitre_attack": incident.mitre_attack,
                    "summary": incident.summary,
                },
                sort_keys=True,
            )
        )
        cap = max_evidence if max_evidence is not None else 20
        evidence = []
        for finding in findings[:cap]:
            event = self.redactor.redact(json.dumps(finding.evidence.get("event", {}), sort_keys=True))
            evidence.append(
                {
                    "rule": finding.rule_id,
                    "rule_name": finding.rule_name,
                    "severity": finding.severity.name.lower(),
                    "risk_points": finding.risk_points,
                    "event": event,
                }
            )
        prompt = f"INCIDENT:\n{incident_doc}\n\nFINDINGS:\n{json.dumps(evidence, indent=2)}"
        if extra_context:
            prompt += (
                "\n\nREFERENCE CONTEXT (runbooks / historical incidents — use only to inform"
                f" your report, never invent facts):\n{extra_context}"
            )
        return prompt

    def _fit_context(self, system: str, user: str, incident: Incident, findings: list[Finding], extra_context: str = "") -> tuple[str, str]:
        """Trim the evidence list so the prompt fits the model's context window.

        Rough estimate: ~4 characters per token. We reserve the requested
        ``max_tokens`` output plus a small safety margin, then keep as many
        findings as fit; a hard truncation note is appended as a last resort.
        """
        if self.config.context_window is None:
            return system, user
        output_tokens = self.config.max_tokens or 800
        budget_tokens = max(self.config.context_window - output_tokens - 128, 1)
        budget_chars = int(budget_tokens * 4)
        if len(system) + len(user) <= budget_chars:
            return system, user
        lo, hi = 0, len(findings)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            candidate = self._build_user_prompt(incident, findings, max_evidence=mid, extra_context=extra_context)
            if len(system) + len(candidate) <= budget_chars:
                lo = mid
            else:
                hi = mid - 1
        trimmed = self._build_user_prompt(incident, findings, max_evidence=lo, extra_context=extra_context)
        if len(system) + len(trimmed) > budget_chars:
            # Last resort: split the budget across both prompts, keeping a
            # small marker each, so the total is guaranteed to fit.
            marker_user = "\n[evidence truncated]"
            marker_sys = "\n[system truncated]"
            sys_budget, usr_budget = budget_chars // 2, budget_chars - budget_chars // 2
            if len(system) > sys_budget - len(marker_sys):
                system = system[: max(sys_budget - len(marker_sys), 0)] + marker_sys
            if len(trimmed) > usr_budget - len(marker_user):
                trimmed = trimmed[: max(usr_budget - len(marker_user), 0)] + marker_user
        return system, trimmed
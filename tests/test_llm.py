from __future__ import annotations

from autosiem.llm import (
    LLMBackend,
    LLMConfig,
    LLMError,
    LLMService,
    OllamaBackend,
    OpenAIBackend,
    Redactor,
    config_from_env,
    extract_json_object,
    make_backend,
    validate_decision,
)


class _FakeBackend(LLMBackend):
    def __init__(self, content: str) -> None:
        super().__init__(LLMConfig())
        self.content = content

    def chat(self, system: str, user: str) -> str:
        return self.content


def test_redactor_masks_secrets_and_pii() -> None:
    r = Redactor(mask_pii=True)
    text = 'password="hunter2" token=abc123 email="a.b@example.com" ip=203.0.113.10'
    out = r.redact(text)
    assert "hunter2" not in out
    assert "abc123" not in out
    assert "a.b@example.com" not in out
    assert "203.0.113.10" not in out


def test_redactor_without_pii_keeps_ips() -> None:
    r = Redactor(mask_pii=False)
    assert "203.0.113.10" in r.redact("ip=203.0.113.10")
    assert "hunter2" not in r.redact('password="hunter2"')


def test_extract_json_object_handles_code_fences() -> None:
    text = '```json\n{"decision_type": "escalate", "confidence": 0.8}\n```'
    assert extract_json_object(text)["confidence"] == 0.8


def test_extract_json_object_raises_on_no_json() -> None:
    try:
        extract_json_object("no json here")
    except LLMError:
        return
    raise AssertionError("expected LLMError")


def test_validate_decision_coerces_bad_input() -> None:
    decision = validate_decision(
        {
            "decision_type": "not_a_real_type",
            "confidence": "oops",
            "rationale": "  seen it  ",
        }
    )
    assert decision["decision_type"] == "suspicious_monitor"
    assert 0.0 <= decision["confidence"] <= 1.0
    assert decision["rationale"] == "seen it"


def test_make_backend_lm_studio_defaults_no_key_required() -> None:
    backend = make_backend(LLMConfig(backend="openai_compat"))
    assert isinstance(backend, OpenAIBackend)
    assert backend.base_url == "http://localhost:1234/v1"


def test_make_backend_ollama() -> None:
    backend = make_backend(LLMConfig(backend="ollama"))
    assert isinstance(backend, OllamaBackend)


def test_make_backend_none_is_none() -> None:
    assert make_backend(LLMConfig(backend="none")) is None


def test_llm_service_disabled_config_returns_local_fallback() -> None:
    service = LLMService(config=LLMConfig(backend="none"))
    assert service.enabled is False

    from autosiem.pipeline import AutoSIEMPipeline
    from autosiem.rules import load_rules
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules, llm=service).process_lines(lines)
    incident = result.incidents[0]
    annotation = service.annotate(incident, result.findings)
    assert annotation.decision is None
    assert annotation.report


def _load_incident():
    from pathlib import Path

    from autosiem.pipeline import AutoSIEMPipeline
    from autosiem.rules import load_rules

    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    return result.incidents[0], result.findings


def test_llm_service_uses_llm_decision_on_valid_response() -> None:
    incident, findings = _load_incident()
    service = LLMService(config=LLMConfig(backend="none"))
    service.backend = _FakeBackend(
        '{"decision_type": "containment_proposed", "confidence": 0.95, "rationale": "high risk", "recommended_owner": "tier-2", "report": "LLM report text"}'
    )
    annotation = service.annotate(incident, findings)
    assert annotation.used_llm is True
    assert annotation.decision is not None
    assert annotation.decision["decision_type"] == "containment_proposed"
    assert annotation.report == "LLM report text"


def test_llm_service_falls_back_on_garbage_response() -> None:
    incident, findings = _load_incident()
    service = LLMService(config=LLMConfig(backend="none"))
    service.backend = _FakeBackend("this is not json at all")
    annotation = service.annotate(incident, findings)
    assert annotation.used_llm is False
    assert annotation.decision is None
    assert annotation.report


def test_config_from_env_infers_openai_compat_from_url(monkeypatch) -> None:
    monkeypatch.setenv("AUTOSIEM_LLM_URL", "http://localhost:1234/v1")
    assert config_from_env().backend == "openai_compat"


def test_config_from_env_respects_explicit_none(monkeypatch) -> None:
    monkeypatch.setenv("AUTOSIEM_LLM_BACKEND", "none")
    monkeypatch.setenv("AUTOSIEM_LLM_URL", "http://x/v1")
    assert config_from_env().backend == "none"


def test_config_from_env_reads_sampling_and_context(monkeypatch) -> None:
    monkeypatch.setenv("AUTOSIEM_LLM_CONTEXT_WINDOW", "8192")
    monkeypatch.setenv("AUTOSIEM_LLM_MAX_TOKENS", "256")
    monkeypatch.setenv("AUTOSIEM_LLM_TEMPERATURE", "0.7")
    monkeypatch.setenv("AUTOSIEM_LLM_TOP_P", "0.9")
    cfg = config_from_env()
    assert cfg.context_window == 8192
    assert cfg.max_tokens == 256
    assert cfg.temperature == 0.7
    assert cfg.top_p == 0.9


def test_fit_context_respects_window() -> None:
    incident, findings = _load_incident()
    service = LLMService(config=LLMConfig(backend="none", context_window=200, max_tokens=50))
    system = "system prompt " * 40
    user = service._build_user_prompt(incident, findings)
    s, u = service._fit_context(system, user, incident, findings)
    budget = (200 - 128 - 50) * 4  # 22 tokens * 4 chars
    assert len(s) + len(u) <= budget


def test_fit_context_no_window_is_passthrough() -> None:
    incident, findings = _load_incident()
    service = LLMService(config=LLMConfig(backend="none"))
    system = "hello system"
    user = service._build_user_prompt(incident, findings)
    s, u = service._fit_context(system, user, incident, findings)
    assert s == system
    assert u == user

def test_used_llm_is_recorded_not_inferred() -> None:
    """A configured-but-failing backend must not be reported as 'used an LLM'.

    The old CLI derived this by string-matching 'decision_from_llm' in the audit
    log, which is a proxy for the fact rather than the fact.
    """
    import json as _json
    from pathlib import Path as _Path

    from autosiem.llm import LLMBackend, LLMConfig, LLMError, LLMService
    from autosiem.pipeline import AutoSIEMPipeline
    from autosiem.rules import load_rules

    root = _Path(__file__).resolve().parents[1]
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    rules = load_rules(root / "rules")

    class _Working(LLMBackend):
        def chat(self, system: str, user: str) -> str:
            return _json.dumps(
                {
                    "decision_type": "escalate",
                    "confidence": 0.4,
                    "rationale": "stub",
                    "recommended_owner": "tier-2-analyst",
                    "summary": "stub report",
                }
            )

    class _Broken(LLMBackend):
        def chat(self, system: str, user: str) -> str:
            raise LLMError("backend down")

    working = LLMService(config=LLMConfig())
    working.backend = _Working(working.config)
    result = AutoSIEMPipeline(rules, llm=working).process_lines(lines)
    assert result.llm_reports == {incident.incident_id for incident in result.incidents}

    broken = LLMService(config=LLMConfig())
    broken.backend = _Broken(broken.config)
    fallback = AutoSIEMPipeline(rules, llm=broken).process_lines(lines)
    # Backend configured and enabled, but it never answered.
    assert broken.enabled is True
    assert fallback.llm_reports == set()


def test_no_llm_configured_records_no_llm_reports() -> None:
    from pathlib import Path as _Path

    from autosiem.pipeline import AutoSIEMPipeline
    from autosiem.rules import load_rules

    root = _Path(__file__).resolve().parents[1]
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(load_rules(root / "rules")).process_lines(lines)
    assert result.llm_reports == set()

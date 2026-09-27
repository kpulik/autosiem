"""Real provider integration. Skipped unless explicitly enabled.

These are the only tests that talk to a hosted API or load a real model, so they
are gated twice: by the ``system_one_integration`` marker and by the environment
they need. Run them deliberately::

    # Jev (costs money, needs a key)
    TYPESAFE_API_KEY=... AUTOSIEM_RUN_SYSTEM_ONE_INTEGRATION=1 \\
        PYTHONPATH=src python3 -m pytest tests/test_system_one_integration.py -m system_one_integration -q

    # Laya (needs `pip install '.[laya]'`, downloads ~421M params on first run)
    AUTOSIEM_RUN_SYSTEM_ONE_INTEGRATION=1 \\
        PYTHONPATH=src python3 -m pytest tests/test_system_one_integration.py -m system_one_integration -q

They assert the *contract* (typed answers that validate), not specific verdicts:
a model's opinion about a synthetic incident is not a stable test fixture.
"""

from __future__ import annotations

import os

import pytest

from autosiem.system_one import SECURITY_QUESTIONS, config_from_env
from autosiem.system_one.providers import JevDecisionProvider, LayaDecisionProvider

pytestmark = pytest.mark.system_one_integration

def _answer(result, name):
    """The answer for ``name``, asserted present (also narrows the type)."""
    answer = result.answer(name)
    assert answer is not None, f"no answer for {name!r}"
    return answer


ENABLED = os.environ.get("AUTOSIEM_RUN_SYSTEM_ONE_INTEGRATION") == "1"

STATE = {
    "incident": {
        "title": "Repeated failed logins then a successful one from a new country",
        "summary": "12 failed authentications for user alice from 198.51.100.25, then one success",
        "deterministic_severity": "high",
        "deterministic_risk_score": 320,
        "entities": ["user:alice", "host:vpn-1"],
        "mitre_attack": ["T1110"],
    },
    "ueba": {
        "signal_names": ["novel_src_ip", "off_hours", "burst"],
        "off_hours": True,
        "burst": True,
        "total_points": 55,
    },
}


def _require(condition: bool, reason: str) -> None:
    if not ENABLED:
        pytest.skip("set AUTOSIEM_RUN_SYSTEM_ONE_INTEGRATION=1 to run provider integration tests")
    if not condition:
        pytest.skip(reason)


def test_jev_answers_the_real_question_set() -> None:
    config = config_from_env()
    _require(config.jev.configured, "TYPESAFE_API_KEY is not set")

    result = JevDecisionProvider(config.jev).decide(STATE, SECURITY_QUESTIONS)

    assert result.provider == "jev"
    assert result.model  # the concrete version that answered
    assert set(result.answers) == set(SECURITY_QUESTIONS)
    malicious = result.answer("malicious")
    assert malicious is not None and malicious.value is not None
    assert 0.0 <= malicious.value <= 1.0
    severity = result.answer("severity")
    assert severity is not None and severity.selected in SECURITY_QUESTIONS["severity"].options
    assert severity.confidence is None or 0.0 <= severity.confidence <= 1.0
    action = result.answer("action")
    assert action is not None and action.selected in SECURITY_QUESTIONS["action"].options
    # Usage is what the cost estimate is built from, so it has to be present.
    assert result.usage.get("input_tokens", 0) > 0
    assert result.latency_ms > 0


def test_laya_answers_the_real_question_set_locally() -> None:
    try:
        import laya  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        laya_available = False
    else:
        laya_available = True
    _require(laya_available, "laya is not installed (pip install '.[laya]')")

    config = config_from_env()
    result = LayaDecisionProvider(config.laya).decide(STATE, SECURITY_QUESTIONS)

    assert result.provider == "laya"
    assert set(result.answers) == set(SECURITY_QUESTIONS)
    assert _answer(result, "severity").selected in SECURITY_QUESTIONS["severity"].options
    assert _answer(result, "action").selected in SECURITY_QUESTIONS["action"].options
    # Local inference: no token usage to report, and therefore no cost claim.
    assert result.usage == {}

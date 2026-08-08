from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules
from autosiem.schemas import Finding, Severity
from autosiem.suppression import DEFAULT_CREATED_BY, Suppression, SuppressionEngine

NEXT_DAY = datetime.now(timezone.utc) + timedelta(days=1)
NOW = datetime.now(timezone.utc)


def _finding(rule_id: str, entity: str, severity: Severity = Severity.MEDIUM, at: datetime | None = None) -> Finding:
    return Finding(
        finding_id=str(uuid4()),
        rule_id=rule_id,
        rule_name=f"rule {rule_id}",
        event_id=str(uuid4()),
        timestamp=at or NOW,
        severity=severity,
        risk_points=severity.value,
        entities=[entity] if entity else [],
        mitre_attack=[],
        evidence={},
    )


def test_suppress_drops_matching_findings() -> None:
    engine = SuppressionEngine(
        [Suppression(rule_id="X", name="n", action="suppress", reason="noise", suppression_id="s1")]
    )
    kept, suppressed = engine.apply([_finding("X", "user:alice"), _finding("Y", "user:bob")])
    assert [f.rule_id for f in kept] == ["Y"]
    assert len(suppressed) == 1
    assert suppressed[0]["finding_id"]
    assert suppressed[0]["action"] == "suppress"


def test_downgrade_lowers_severity() -> None:
    engine = SuppressionEngine(
        [Suppression(rule_id="X", name="n", action="downgrade", downgrade_to="low", reason="messy", suppression_id="s1")]
    )
    kept, suppressed = engine.apply([_finding("X", "user:alice", Severity.HIGH)])
    assert len(kept) == 1
    assert kept[0].severity == Severity.LOW
    assert suppressed[0]["action"] == "downgrade"
    assert suppressed[0]["to"] == "low"


def test_wildcard_with_entity_scoping() -> None:
    engine = SuppressionEngine(
        [Suppression(rule_id="*", name="n", action="suppress", reason="noise", entity="user:alice", suppression_id="s1")]
    )
    kept, suppressed = engine.apply([_finding("X", "user:alice"), _finding("Y", "user:bob")])
    assert [f.rule_id for f in kept] == ["Y"]
    assert len(suppressed) == 1


def test_expired_suppression_ignored() -> None:
    engine = SuppressionEngine(
        [
            Suppression(
                rule_id="*", name="n", action="suppress", reason="noise",
                suppression_id="s1", expires_at=NOW - timedelta(hours=1),
            )
        ]
    )
    kept, suppressed = engine.apply([_finding("X", "user:alice")])
    assert len(kept) == 1
    assert not suppressed


def test_suppression_defaults_generate_id_and_action() -> None:
    suppression = Suppression(rule_id="X")
    assert suppression.suppression_id
    assert suppression.action == "suppress"
    assert suppression.created_by == DEFAULT_CREATED_BY


def test_engine_add_suppression_accepts_raw_fields_with_defaults() -> None:
    engine = SuppressionEngine()
    added = engine.add_suppression(rule_id="X", reason="noise")
    assert isinstance(added, Suppression)
    assert added.suppression_id
    assert added.action == "suppress"
    assert added.created_by == DEFAULT_CREATED_BY
    kept, suppressed = engine.apply([_finding("X", "user:alice")])
    assert not kept
    assert len(suppressed) == 1
    assert suppressed[0]["suppression_id"] == added.suppression_id


def test_engine_add_suppression_accepts_suppression_object() -> None:
    engine = SuppressionEngine()
    added = engine.add_suppression(
        Suppression(rule_id="X", name="n", action="downgrade", downgrade_to="low", reason="messy")
    )
    assert added.suppression_id
    kept, suppressed = engine.apply([_finding("X", "user:alice", Severity.HIGH)])
    assert kept[0].severity == Severity.LOW
    assert suppressed[0]["action"] == "downgrade"


def test_engine_add_suppression_validates_fields() -> None:
    engine = SuppressionEngine()
    with pytest.raises(ValueError):
        engine.add_suppression(rule_id="X", action="explode", reason="r")
    with pytest.raises(ValueError):
        engine.add_suppression(rule_id="X", action="downgrade", reason="r")
    with pytest.raises(ValueError):
        engine.add_suppression(Suppression(rule_id="X", action="downgrade", reason="r"))


def test_auto_repeat_suppresses_after_threshold_within_window() -> None:
    engine = SuppressionEngine(repeat_threshold=2)
    base = NOW
    findings = [
        _finding("X", "user:alice", at=base + timedelta(seconds=i * 60))
        for i in range(4)
    ]
    kept, suppressed = engine.apply(findings)
    # threshold=2: first two kept, repeats from the 3rd suppressed
    assert len(kept) == 2
    assert len(suppressed) == 2
    assert all(r["suppression_id"].startswith("auto-repeat") for r in suppressed)


def test_auto_repeat_respects_window() -> None:
    engine = SuppressionEngine(repeat_threshold=2, repeat_window_minutes=5)
    findings = [
        _finding("X", "user:alice", at=NOW + timedelta(minutes=0)),
        _finding("X", "user:alice", at=NOW + timedelta(minutes=1)),
        _finding("X", "user:alice", at=NOW + timedelta(minutes=10)),  # outside window
    ]
    kept, suppressed = engine.apply(findings)
    # The 10-minute finding prunes the earlier window before counting,
    # so it sits alone (count 1) and is kept.
    assert len(kept) == 3
    assert not suppressed


def test_pipeline_applies_suppressions() -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    engine = SuppressionEngine(
        [Suppression(suppression_id="s1", rule_id="*", name="alice noise", action="suppress", reason="noise", entity="user:alice")]
    )
    result = AutoSIEMPipeline(rules, suppression_engine=engine).process_lines(lines)
    assert result.suppressed
    assert all(r["action"] == "suppress" for r in result.suppressed)
    # all alice findings are suppressed, so they no longer drive detections
    assert not any(f.rule_id.startswith("builtin-anomaly") for f in result.findings)
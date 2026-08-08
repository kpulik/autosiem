"""Tests for analyst feedback learning (feedback.py)."""
from __future__ import annotations

from pathlib import Path

from autosiem.feedback import FeedbackEngine, FeedbackRecord


def _finding(rule_id: str = "R1") -> dict:
    return {"rule_id": rule_id, "risk_points": 100}


def test_rejects_lower_weight_and_adjusted_risk() -> None:
    engine = FeedbackEngine()
    for _ in range(3):
        engine.record(FeedbackRecord(decision="reject", rule_id="R1", entity="user:alice"))
    assert engine.weight_for_rule("R1") < 1.0
    raw = _finding()
    assert engine.adjusted_risk(raw) < raw["risk_points"]

    # other rules unaffected
    assert engine.weight_for_rule("R2") == 1.0


def test_approves_increase_weight_and_cap_at_max() -> None:
    engine = FeedbackEngine()
    for _ in range(30):
        engine.record(FeedbackRecord(decision="approve", rule_id="R1"))
    assert engine.weight_for_rule("R1") == 3.0


def test_save_load_round_trip_preserves_count(tmp_path: Path) -> None:
    engine = FeedbackEngine()
    engine.record(FeedbackRecord(decision="approve", rule_id="R1", actor="bob"))
    engine.record(FeedbackRecord(decision="reject", rule_id="R2", entity="host:vpn-1"))
    engine.record(FeedbackRecord(decision="comment", rule_id="R3"))

    path = tmp_path / "feedback.json"
    engine.save(path)

    loaded = FeedbackEngine()
    loaded.load(path)
    assert len(loaded.list_records()) == 3
    assert loaded.to_dict() == engine.to_dict()


def test_suppression_map_lists_rejected_pairs() -> None:
    engine = FeedbackEngine()
    engine.record(FeedbackRecord(decision="reject", rule_id="R1", entity="user:alice"))
    engine.record(FeedbackRecord(decision="reject", rule_id="R1", entity="user:bob"))
    engine.record(FeedbackRecord(decision="approve", rule_id="R1", entity="user:carol"))
    entries = engine.suppression_map()
    assert any(e.rule_id == "R1" and e.entity == "user:alice" for e in entries)
    assert all("user:carol" not in e.entity for e in entries)
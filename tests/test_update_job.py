"""Tests for the hourly update job (update_job.py)."""
from __future__ import annotations

import json
from pathlib import Path

from autosiem.rules import load_rules
from autosiem.threat_intel import load_intel_state
from autosiem.update_job import UpdateJob

ROOT = Path(__file__).resolve().parents[1]


def _bundle() -> dict:
    return {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "id": "indicator--1", "name": "Bad IP", "pattern": "[ipv4-addr:value = '203.0.113.66']"}
        ],
    }


def test_run_once_reloads_rules_and_coverage() -> None:
    job = UpdateJob(rules_dir=ROOT / "rules")
    report = job.run_once()
    assert report.rules_loaded == len(load_rules(ROOT / "rules"))
    assert report.coverage
    assert report.coverage["total_rules"] == report.rules_loaded


def test_intel_refresh_from_local_path(tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
    state_path = tmp_path / "intel_state.json"

    job = UpdateJob(
        rules_dir=ROOT / "rules",
        intel_path=bundle_path,
        intel_state_path=state_path,
    )
    report = job.run_once()
    assert report.intel_refreshed is True
    assert state_path.exists()
    indicators = load_intel_state(state_path)
    assert len(indicators) == 1
    assert indicators[0].indicator_id == "indicator--1"


def test_intel_refresh_failure_reported(tmp_path: Path) -> None:
    job = UpdateJob(
        rules_dir=ROOT / "rules",
        intel_path=tmp_path / "missing.json",
        intel_state_path=tmp_path / "state.json",
    )
    report = job.run_once()
    assert report.intel_refreshed is False
    assert any("intel refresh failed" in message for message in report.messages)
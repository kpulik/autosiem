"""The labelled evaluation set stays buildable.

A rule change can silently break the dataset: a scenario that stops producing
an incident no longer tests anything, because System One only sees incidents.
These tests run the real builder over the real scenarios file, so that breaks
the suite instead of the benchmark.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "evals/system_one/scenarios.json"


def _builder():
    spec = importlib.util.spec_from_file_location("build_cases", ROOT / "scripts/build_system_one_cases.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_scenario_builds_into_a_labelled_incident() -> None:
    cases, rows, errors = _builder().build(SCENARIOS)
    assert errors == []
    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))["scenarios"]
    assert len(cases) == len(scenarios)
    # The state is what the pipeline itself would send a provider.
    for case in cases:
        assert set(case["state"]) >= {"incident", "correlation", "ueba", "findings"}
        assert set(case["labels"]) == {"malicious", "severity", "action"}


def test_the_labels_do_not_just_copy_the_engine() -> None:
    # If every label matched the engine's severity, the deterministic baseline
    # would score 100% by construction and the benchmark would measure nothing.
    _, rows, _ = _builder().build(SCENARIOS)
    disagreements = [row for row in rows if row["labels"]["severity"] != row["engine_severity"]]
    assert len(disagreements) >= len(rows) // 4


def test_both_classes_are_represented() -> None:
    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))["scenarios"]
    malicious = [s for s in scenarios if s["labels"]["malicious"]]
    benign = [s for s in scenarios if not s["labels"]["malicious"]]
    assert malicious and benign
    assert min(len(malicious), len(benign)) / len(scenarios) >= 0.3


def test_a_bad_label_is_reported_not_built(tmp_path) -> None:
    doc = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    doc["scenarios"] = doc["scenarios"][:1]
    doc["scenarios"][0]["labels"]["severity"] = "apocalyptic"
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    cases, _, errors = _builder().build(path)
    assert cases == []
    assert any("labels.severity" in error for error in errors)


def test_a_scenario_that_raises_no_incident_is_an_error(tmp_path) -> None:
    doc = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    quiet = dict(doc["scenarios"][0])
    quiet["id"] = "quiet"
    quiet["events"] = [{"timestamp": "2026-09-01T10:00:00Z", "category": "process", "action": "process_start",
                        "user": "lena", "host": "ws-1", "process_name": "notepad.exe", "command_line": "notepad.exe",
                        "outcome": "success"}]
    doc["scenarios"] = [quiet]
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    _, _, errors = _builder().build(path)
    assert any("no incident" in error for error in errors)

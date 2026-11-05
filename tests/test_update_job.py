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

# --- a failed refresh must be visible to a scheduler ---------------------------


def _offline(url: str) -> bytes:
    raise OSError(f"network unreachable: {url}")


def test_every_failed_refresh_is_recorded_while_the_cycle_still_finishes(tmp_path: Path) -> None:
    job = UpdateJob(
        rules_dir=ROOT / "rules",
        db_path=tmp_path / "a.db",
        intel_path=tmp_path / "missing.json",
        intel_state_path=tmp_path / "state.json",
        refresh_attack=True,
        attack_fetch=_offline,
        refresh_kev_catalog=True,
        kev_fetch=_offline,
    )
    report = job.run_once()
    assert [failure.split(":")[0] for failure in report.failures] == ["attack", "kev", "intel"]
    assert report.rules_loaded > 0 and report.coverage, "the rest of the cycle still ran"


def test_a_cycle_with_nothing_requested_has_no_failures(tmp_path: Path) -> None:
    report = UpdateJob(rules_dir=ROOT / "rules", db_path=tmp_path / "a.db").run_once()
    assert report.failures == []


def test_cli_update_exits_1_when_a_requested_refresh_fails(capsys, monkeypatch, tmp_path: Path) -> None:
    """It exited 0 with the failure buried in JSON messages, so a feed run from
    cron or a systemd timer could stay broken for ever unnoticed."""
    import sys

    import pytest

    from autosiem.cli import main

    monkeypatch.setattr(sys, "argv", ["autosiem", "update", "--intel-path", str(tmp_path / "missing.json"), "--db", str(tmp_path / "a.db")])
    with pytest.raises(SystemExit) as excinfo:
        main()
    message = str(excinfo.value)
    assert message.startswith("update finished, but 1 requested refresh(es) failed: intel: ")
    assert "\n" not in message
    payload = json.loads(capsys.readouterr().out)
    assert payload["failures"] and payload["rules_loaded"] > 0


def test_cli_update_exits_0_when_nothing_failed(capsys, monkeypatch, tmp_path: Path) -> None:
    import sys

    from autosiem.cli import main

    monkeypatch.setattr(sys, "argv", ["autosiem", "update", "--db", str(tmp_path / "a.db")])
    main()
    assert json.loads(capsys.readouterr().out)["failures"] == []

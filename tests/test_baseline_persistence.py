"""Tests for persisting the UEBA baseline between pipeline runs."""

from __future__ import annotations

import json
from typing import Any

from autosiem.anomaly import AnomalyDetector, BaselineState, BaselineStore
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.storage import AutoSIEMStorage

EVENTS = [
    {"timestamp": "2026-08-04T10:00:00Z", "category": "authentication", "action": "login_success", "user": "alice", "src_ip": "203.0.113.10", "host": "vpn-1", "outcome": "success"},
    {"timestamp": "2026-08-04T10:05:00Z", "category": "authentication", "action": "login_success", "user": "alice", "src_ip": "203.0.113.10", "host": "vpn-1", "outcome": "success"},
]

LINES = [json.dumps(event) for event in EVENTS]


class BrokenStore:
    def load_baseline(self, tenant_id: str | None = None) -> dict[str, Any] | None:
        raise RuntimeError("database is locked")

    def save_baseline(self, state: dict[str, Any], tenant_id: str | None = None) -> None:
        raise RuntimeError("database is locked")


# --- storage layer ---------------------------------------------------------


def test_storage_satisfies_the_baseline_store_protocol(tmp_path) -> None:
    assert isinstance(AutoSIEMStorage(tmp_path / "probe.db"), BaselineStore)


def test_missing_baseline_reads_as_none(tmp_path) -> None:
    assert AutoSIEMStorage(tmp_path / "empty.db").load_baseline() is None


def test_baseline_round_trips_through_storage(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "b.db")
    detector = AnomalyDetector()
    for line in LINES:
        detector.finding_for_event(_normalize(line))

    store.save_baseline(detector.state.to_dict())
    restored = BaselineState.from_dict(store.load_baseline() or {})

    assert restored.total_events == detector.state.total_events
    assert restored.seen_actions_by_entity == detector.state.seen_actions_by_entity


def test_saving_replaces_the_previous_baseline(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "b.db")
    store.save_baseline({"total_events": 1})
    store.save_baseline({"total_events": 99})
    loaded = store.load_baseline()
    assert loaded is not None
    assert loaded["total_events"] == 99


def test_baselines_are_isolated_per_tenant(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "b.db")
    store.save_baseline({"total_events": 5}, tenant_id="acme")
    store.save_baseline({"total_events": 50}, tenant_id="globex")

    acme = store.load_baseline(tenant_id="acme")
    globex = store.load_baseline(tenant_id="globex")
    assert acme is not None and acme["total_events"] == 5
    assert globex is not None and globex["total_events"] == 50
    assert store.load_baseline(tenant_id="nobody") is None


def test_a_corrupt_baseline_reads_as_none_instead_of_raising(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "b.db")
    with store.connect() as conn:
        conn.execute(
            "insert or replace into baselines(tenant_id,state,updated_at) values(?,?,?)",
            ("default", "{not json", "2026-08-04T10:00:00Z"),
        )
    assert store.load_baseline() is None


# --- pipeline wiring -------------------------------------------------------


def test_pipeline_persists_the_baseline(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "p.db")
    AutoSIEMPipeline([], baseline_store=store).process_lines(LINES)

    saved = store.load_baseline()
    assert saved is not None
    assert saved["total_events"] == len(EVENTS)


def test_second_run_resumes_the_stored_baseline(tmp_path) -> None:
    """The point of persistence: run two starts warm, not from zero."""
    store = AutoSIEMStorage(tmp_path / "p.db")
    AutoSIEMPipeline([], baseline_store=store).process_lines(LINES)
    AutoSIEMPipeline([], baseline_store=store).process_lines(LINES)

    saved = store.load_baseline()
    assert saved is not None
    assert saved["total_events"] == len(EVENTS) * 2


def test_a_warm_baseline_starts_with_prior_knowledge(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "p.db")
    AutoSIEMPipeline([], baseline_store=store).process_lines(LINES)

    warm = AutoSIEMPipeline([], baseline_store=store)
    assert warm.anomaly_detector.state.total_events == len(EVENTS)
    assert warm.anomaly_detector.state.seen_actions_by_entity["user:alice"]["login_success"] == 2
    # Already-known behaviour scores zero on a warm start.
    assert warm.anomaly_detector.score(_normalize(LINES[0])) == 0
    # A genuinely new action still scores, so the baseline is not just inert.
    novel = dict(EVENTS[0], action="file_delete")
    assert warm.anomaly_detector.score(_normalize(json.dumps(novel))) > 0


def test_without_a_store_nothing_is_persisted_and_runs_are_independent(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "p.db")
    AutoSIEMPipeline([]).process_lines(LINES)
    assert store.load_baseline() is None

    fresh = AutoSIEMPipeline([])
    assert fresh.anomaly_detector.state.total_events == 0


def test_an_explicit_detector_wins_over_the_stored_baseline(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "p.db")
    store.save_baseline({"total_events": 42})
    detector = AnomalyDetector()

    pipeline = AutoSIEMPipeline([], anomaly_detector=detector, baseline_store=store)
    assert pipeline.anomaly_detector is detector
    assert pipeline.anomaly_detector.state.total_events == 0


def test_tenant_scoped_pipelines_keep_separate_baselines(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "p.db")
    AutoSIEMPipeline([], baseline_store=store, tenant_id="acme").process_lines(LINES)

    acme = store.load_baseline(tenant_id="acme")
    assert acme is not None and acme["total_events"] == len(EVENTS)
    assert store.load_baseline(tenant_id="globex") is None


def test_a_broken_baseline_store_never_breaks_a_run() -> None:
    """Detection must survive a failing baseline store."""
    pipeline = AutoSIEMPipeline([], baseline_store=BrokenStore())
    assert pipeline.anomaly_detector.state.total_events == 0

    result = pipeline.process_lines(LINES)  # save also raises; must be swallowed
    assert len(result.events) == len(EVENTS)


def _normalize(line: str):
    from autosiem.normalization import normalize, parse_raw_line

    return normalize(parse_raw_line(line))

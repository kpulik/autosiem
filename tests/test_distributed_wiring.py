"""Regression tests for the distributed pipeline wiring.

These cover bugs the original tests missed because they only asserted event
counts and never checked that the queue and archive actually did anything.
"""

from __future__ import annotations

import json
import pytest
from typing import Any

from autosiem.bus import DurableQueue
from autosiem.distributed import DistributedConfig, DistributedPipeline
from autosiem.pipeline import PipelineResult

LINES = [
    json.dumps({"timestamp": "2026-08-04T10:00:00Z", "category": "authentication", "action": "login_success", "user": "alice", "src_ip": "203.0.113.10", "host": "vpn-1"}),
    json.dumps({"timestamp": "2026-08-04T10:05:00Z", "category": "authentication", "action": "login_failed", "user": "alice", "src_ip": "198.51.100.25", "host": "vpn-1"}),
]


class CountingPipeline:
    """Stands in for AutoSIEMPipeline and records how often it is invoked."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def process_lines(self, lines: list[str]) -> PipelineResult:
        self.calls.append(list(lines))
        result = PipelineResult()
        result.events = [object() for _ in lines]  # type: ignore[list-item]
        return result


def _config(tmp_path, **kwargs: Any) -> DistributedConfig:
    return DistributedConfig(**kwargs)


# --- the empty-queue truthiness bug ---------------------------------------


def test_an_empty_durable_queue_is_truthy(tmp_path) -> None:
    """DurableQueue defines __len__, so without __bool__ an empty queue is falsy.

    Every `if self._queue:` guard then skipped enqueueing on a fresh queue,
    which is precisely when the queue is empty. Backpressure and replay were
    dead on the ingest path.
    """
    queue = DurableQueue(str(tmp_path / "q.db"))
    assert len(queue) == 0
    assert bool(queue) is True
    assert queue if queue else False


def test_a_fresh_queue_receives_the_ingested_lines(tmp_path) -> None:
    config = _config(tmp_path, queue_path=str(tmp_path / "q.db"))
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"))
    pipeline.run(LINES)

    queue = DurableQueue(str(tmp_path / "q.db"))
    assert len(queue) == len(LINES)


def test_every_enqueued_message_is_acked_after_a_successful_run(tmp_path) -> None:
    config = _config(tmp_path, queue_path=str(tmp_path / "q.db"))
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"))
    pipeline.run(LINES)

    queue = DurableQueue(str(tmp_path / "q.db"))
    assert queue.pending() == 0


# --- single-pass processing ------------------------------------------------


def test_the_injected_pipeline_runs_exactly_once(tmp_path) -> None:
    """The CLI used to run the distributed pipeline AND the standard one."""
    counting = CountingPipeline()
    config = _config(tmp_path, queue_path=str(tmp_path / "q.db"), archive_path=str(tmp_path / "a.jsonl"))
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"), pipeline=counting)
    pipeline.run(LINES)

    assert len(counting.calls) == 1
    assert counting.calls[0] == LINES


def test_run_returns_the_real_pipeline_result(tmp_path) -> None:
    counting = CountingPipeline()
    config = _config(tmp_path)
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"), pipeline=counting)

    result = pipeline.run(LINES)
    assert isinstance(result, PipelineResult)
    assert len(result.events) == len(LINES)


def test_process_lines_still_returns_counts(tmp_path) -> None:
    counting = CountingPipeline()
    pipeline = DistributedPipeline(_config(tmp_path), [], db_path=str(tmp_path / "d.db"), pipeline=counting)
    assert pipeline.process_lines(LINES)["events"] == len(LINES)


def test_an_injected_pipeline_takes_precedence_over_workers(tmp_path) -> None:
    counting = CountingPipeline()
    config = _config(tmp_path, workers=4)
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"), pipeline=counting)
    pipeline.run(LINES)
    assert len(counting.calls) == 1


# --- archive is not coupled to the ingest queue ----------------------------


def test_the_archive_does_not_push_markers_onto_the_ingest_queue(tmp_path) -> None:
    """Archive markers in the ingest queue mixed journal seqs into queue offsets.

    That broke the queue checkpoint and made both replay paths return nothing.
    """
    config = _config(
        tmp_path, queue_path=str(tmp_path / "q.db"), archive_path=str(tmp_path / "a.jsonl")
    )
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"), pipeline=CountingPipeline())
    pipeline.run(LINES)

    queue = DurableQueue(str(tmp_path / "q.db"))
    topics = {row["topic"] for row in queue.replay(0)} | {
        row["topic"] for row in queue.pull(limit=100)
    }
    assert "archive" not in topics
    assert len(queue) == len(LINES)


def test_the_archive_still_records_every_line(tmp_path) -> None:
    config = _config(tmp_path, archive_path=str(tmp_path / "a.jsonl"))
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"), pipeline=CountingPipeline())
    pipeline.run(LINES)

    assert (tmp_path / "a.jsonl").read_text().strip().count("\n") + 1 == len(LINES)


# --- replay ----------------------------------------------------------------


def test_replay_reprocesses_unacked_ingest_messages(tmp_path) -> None:
    queue = DurableQueue(str(tmp_path / "q.db"))
    for index, line in enumerate(LINES):
        queue.push(topic="ingest", payload={"line": line, "seq": index})

    counting = CountingPipeline()
    config = _config(tmp_path, queue_path=str(tmp_path / "q.db"))
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"), pipeline=counting)

    report = pipeline.replay_from_queue()
    assert report["replayed"] == len(LINES)
    assert len(counting.calls) == 1
    assert DurableQueue(str(tmp_path / "q.db")).pending() == 0


def test_replay_survives_non_dict_payloads(tmp_path) -> None:
    """Archive markers carry a bare int; .get() on those aborted the replay."""
    queue = DurableQueue(str(tmp_path / "q.db"))
    queue.push(topic="archive", payload=7)
    queue.push(topic="ingest", payload={"line": LINES[0], "seq": 0})

    counting = CountingPipeline()
    config = _config(tmp_path, queue_path=str(tmp_path / "q.db"))
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"), pipeline=counting)

    report = pipeline.replay_from_queue()
    assert report["replayed"] == 1
    assert DurableQueue(str(tmp_path / "q.db")).pending() == 0


def test_replay_with_only_markers_acks_them_and_reports_nothing(tmp_path) -> None:
    queue = DurableQueue(str(tmp_path / "q.db"))
    queue.push(topic="archive", payload=1)

    counting = CountingPipeline()
    config = _config(tmp_path, queue_path=str(tmp_path / "q.db"))
    pipeline = DistributedPipeline(config, [], db_path=str(tmp_path / "d.db"), pipeline=counting)

    report = pipeline.replay_from_queue()
    assert report["replayed"] == 0
    assert counting.calls == []
    assert DurableQueue(str(tmp_path / "q.db")).pending() == 0


def test_replay_without_a_queue_is_a_no_op(tmp_path) -> None:
    pipeline = DistributedPipeline(_config(tmp_path), [], db_path=str(tmp_path / "d.db"))
    assert pipeline.replay_from_queue()["replayed"] == 0


def test_failed_persistence_keeps_input_pending_and_replay_saves_before_ack(tmp_path):
    config = _config(tmp_path, queue_path=str(tmp_path / "queue.db"))
    assert config.queue_path is not None
    queue = DurableQueue(config.queue_path)
    saved = []
    fail = True
    def persist(result):
        nonlocal fail
        assert queue.pending() == len(LINES)
        if fail:
            fail = False
            raise RuntimeError("database unavailable")
        saved.append(result)
    pipeline = DistributedPipeline(config, [], pipeline=CountingPipeline(), persist=persist, transactional_outbox=True)
    with pytest.raises(RuntimeError, match="unavailable"):
        pipeline.run(LINES)
    assert queue.pending() == len(LINES)
    assert pipeline.replay_from_queue()["replayed"] == len(LINES)
    assert len(saved) == 1 and queue.pending() == 0


def test_postgres_outbox_does_not_dual_write_the_alternate_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(DistributedPipeline, "_make_backend", lambda *_: pytest.fail("direct projection write"))
    config = _config(tmp_path, backend_type="opensearch", queue_path=str(tmp_path / "queue.db"))
    saved = []
    pipeline = DistributedPipeline(config, [], pipeline=CountingPipeline(), persist=saved.append, transactional_outbox=True)
    pipeline.run(LINES)
    assert len(saved) == 1


def test_postgres_no_save_is_rejected_before_enqueue(tmp_path):
    config = _config(tmp_path, queue_path=str(tmp_path / "queue.db"))
    assert config.queue_path is not None
    pipeline = DistributedPipeline(config, [], pipeline=CountingPipeline(), transactional_outbox=True)
    with pytest.raises(ValueError, match="persistence"):
        pipeline.run(LINES)
    assert DurableQueue(config.queue_path).pending() == 0

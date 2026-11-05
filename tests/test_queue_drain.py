"""The listener's durable queue: queued in the receive thread, drained in-process.

Before this, a transient save failure left lines pending and nothing drained
them until a restart, so after ``AUTOSIEM_QUEUE_MAX_PENDING`` failures every new
datagram was refused for good. Lines also waited in memory until their batch
was processed, so a SIGKILL lost what had been read (737 of 1000 measured).
"""

from __future__ import annotations

import json
import socket
import sqlite3
import threading
import time
from typing import Any

import pytest

import autosiem.distributed as distributed
from autosiem.anomaly import BaselineState
from autosiem.backends import BackendError
from autosiem.bus import DurableQueue
from autosiem.distributed import DistributedConfig, DistributedPipeline
from autosiem.listeners import QueueDrainer, SyslogServer
from autosiem.pipeline import AutoSIEMPipeline, PipelineResult


def _line(i: int, user: str = "alice") -> str:
    return json.dumps({
        "timestamp": f"2026-08-04T10:{(i // 60) % 60:02d}:{i % 60:02d}Z", "category": "authentication",
        "action": "login_success", "user": user, "host": "vpn-1",
    })


class CountingPipeline:
    """Records every processing call; ``poison`` in a line makes it raise."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def process_lines(self, lines: list[str]) -> PipelineResult:
        self.calls.append(list(lines))
        if any("poison" in line for line in lines):
            raise ValueError("cannot process 'poison' payload text")
        result = PipelineResult()
        result.events = list(lines)  # type: ignore[assignment]
        return result


class Saves:
    """A persist callback that fails a set number of times first."""

    def __init__(self, fail_times: int = 0, exc: Exception | None = None) -> None:
        self.fail_times = fail_times
        self.exc = exc or sqlite3.OperationalError("database is locked")
        self.saved: list[Any] = []
        self.attempts = 0

    def __call__(self, result: Any) -> None:
        self.attempts += 1
        if self.attempts <= self.fail_times:
            raise self.exc
        self.saved.extend(result.events)


def _dist(tmp_path, *, pipeline: Any = None, persist: Any = None, max_pending: int = 100_000, **config: Any) -> DistributedPipeline:
    cfg = DistributedConfig(queue_path=str(tmp_path / "q.db"), queue_max_pending=max_pending, workers=1, **config)
    return DistributedPipeline(cfg, [], db_path=str(tmp_path / "d.db"), pipeline=pipeline or CountingPipeline(), persist=persist)


# --- DurableQueue ---------------------------------------------------------------


def test_push_many_takes_only_what_fits(tmp_path) -> None:
    queue = DurableQueue(str(tmp_path / "q.db"))
    queue.push("ingest", {"line": "x"})
    offsets = queue.push_many("ingest", [{"line": str(i)} for i in range(5)], max_pending=3)
    assert len(offsets) == 2
    assert queue.pending() == 3
    assert [m["payload"]["line"] for m in queue.pull(10)] == ["x", "0", "1"]


def test_a_dead_letter_is_kept_but_never_pending(tmp_path) -> None:
    queue = DurableQueue(str(tmp_path / "q.db"))
    offset = queue.push("ingest", {"line": "bad"})
    queue.dead_letter(offset)
    assert queue.pending() == 0 and queue.pull(10) == []
    assert queue.compact() == 0, "compaction must not delete a set-aside line"
    assert queue.dead_letters() == 1
    assert queue.requeue_dead_letters() == 1
    assert queue.pending() == 1 and queue.dead_letters() == 0


def test_pending_uses_the_partial_index(tmp_path) -> None:
    """17 lines/s at 1M acked rows: pending() ran on every push and scanned them all."""
    queue = DurableQueue(str(tmp_path / "q.db"))
    plan = queue._conn.execute("EXPLAIN QUERY PLAN SELECT COUNT(*) FROM messages WHERE acked = 0").fetchall()
    assert "messages_pending" in " ".join(str(row) for row in plan)


# --- drain_queue ----------------------------------------------------------------


def test_drain_processes_everything_pending_not_just_the_first_thousand(tmp_path) -> None:
    pipeline, saves = CountingPipeline(), Saves()
    dist = _dist(tmp_path, pipeline=pipeline, persist=saves)
    assert dist.admit([_line(i) for i in range(2500)]) == 2500
    assert dist.drain_queue(batch_size=200) == 2500
    assert len(saves.saved) == 2500
    assert max(len(call) for call in pipeline.calls) == 200
    assert dist.stats["queue_pending"] == 0


def test_a_transient_save_failure_retries_the_save_without_reprocessing(tmp_path) -> None:
    pipeline, saves = CountingPipeline(), Saves(fail_times=2)
    dist = _dist(tmp_path, pipeline=pipeline, persist=saves)
    dist.admit([_line(i) for i in range(5)])
    for _ in range(2):
        with pytest.raises(sqlite3.OperationalError):
            dist.drain_queue()
        assert dist.stats["queue_pending"] == 5, "nothing is acknowledged before it is saved"
    assert dist.drain_queue() == 5
    assert len(pipeline.calls) == 1, "processing again would count the batch into the baseline twice"
    assert len(saves.saved) == 5 and dist.stats["queue_pending"] == 0


@pytest.mark.parametrize("error", [sqlite3.OperationalError("disk I/O error"), RuntimeError("unexpected")], ids=["transient", "other"])
def test_a_failed_ack_after_a_save_only_retries_the_ack(tmp_path, monkeypatch, error: Exception) -> None:
    """Whatever the error, a saved batch is never split and saved again."""
    pipeline, saves = CountingPipeline(), Saves()
    dist = _dist(tmp_path, pipeline=pipeline, persist=saves)
    dist.admit([_line(i) for i in range(3)])
    queue = dist._queue
    assert queue is not None
    real_ack = queue.ack_many
    calls = {"n": 0}

    def flaky(offsets: list[int]) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise error
        real_ack(offsets)

    monkeypatch.setattr(queue, "ack_many", flaky)
    with pytest.raises(type(error)):
        dist.drain_queue()
    dist.drain_queue()
    assert saves.attempts == 1, "a saved batch must not be saved again"
    assert len(pipeline.calls) == 1
    assert dist.stats["queue_pending"] == 0


def test_a_line_that_can_never_be_processed_is_set_aside_not_blocking(tmp_path, caplog) -> None:
    saves = Saves()
    dist = _dist(tmp_path, persist=saves)
    lines = [_line(i) for i in range(9)]
    lines[6] = json.dumps({"user": "poison"})
    dist.admit(lines)
    with caplog.at_level("WARNING", logger="autosiem.distributed"):
        assert dist.drain_queue() == 8
    assert saves.saved == [line for line in lines if "poison" not in line], "order is kept"
    assert dist.stats["queue_pending"] == 0 and dist.stats["queue_dead_letters"] == 1
    assert "ValueError" in caplog.text
    assert "poison" not in caplog.text, "the line, or error text quoting it, is never logged"


def test_a_save_that_always_fails_for_one_line_sets_that_line_aside(tmp_path) -> None:
    class RejectsPoison(Saves):
        def __call__(self, result: Any) -> None:
            if any("poison" in event for event in result.events):
                raise ValueError("bad value")
            super().__call__(result)

    class Passes:
        def process_lines(self, lines: list[str]) -> PipelineResult:
            return _result_of(lines)

    dist = _dist(tmp_path, pipeline=Passes(), persist=RejectsPoison())
    lines = [_line(i) for i in range(4)] + ['{"user": "poison"}']
    dist.admit(lines)
    assert dist.drain_queue() == 4
    assert dist.stats["queue_dead_letters"] == 1


@pytest.mark.parametrize("error", [sqlite3.DatabaseError("database disk image is malformed"), sqlite3.ProgrammingError("no such table: events"), ValueError("bug")])
def test_a_store_that_rejects_every_line_sets_nothing_aside(tmp_path, error: Exception) -> None:
    """A corrupt or unmigrated store fails every line. Blaming the lines emptied
    the whole queue into dead letters and stopped retrying."""
    saves = Saves(fail_times=10**6, exc=error)
    dist = _dist(tmp_path, persist=saves)
    dist.admit([_line(i) for i in range(50)])
    with pytest.raises(type(error)):
        dist.drain_queue(batch_size=20)
    assert dist.stats["queue_pending"] == 50 and dist.stats["queue_dead_letters"] == 0
    saves.fail_times = 0  # the store is repaired
    assert dist.drain_queue(batch_size=20) == 50


def test_a_lone_failing_line_waits_for_a_working_one_to_be_set_aside(tmp_path) -> None:
    dist = _dist(tmp_path, persist=Saves())
    dist.admit(['{"user": "poison"}'])
    with pytest.raises(ValueError):
        dist.drain_queue()
    assert dist.stats["queue_dead_letters"] == 0 and dist.stats["queue_pending"] == 1
    dist.admit([_line(0)])
    assert dist.drain_queue() == 1
    assert dist.stats["queue_dead_letters"] == 1 and dist.stats["queue_pending"] == 0


def _result_of(lines: list[str]) -> PipelineResult:
    result = PipelineResult()
    result.events = list(lines)  # type: ignore[assignment]
    return result


def test_set_aside_lines_can_be_requeued_and_then_processed(tmp_path) -> None:
    pipeline, saves = CountingPipeline(), Saves()
    dist = _dist(tmp_path, pipeline=pipeline, persist=saves)
    dist.admit(['{"user": "poison"}', _line(0)])
    assert dist.drain_queue() == 1
    assert dist.requeue_dead_letters() == 1
    pipeline.process_lines = lambda lines: _result_of(lines)  # type: ignore[method-assign]
    assert dist.drain_queue() == 1 and len(saves.saved) == 2


def test_messages_that_carry_no_line_are_cleared_not_left_pending(tmp_path) -> None:
    """An archive marker from an old queue would otherwise count against the limit for ever."""
    dist = _dist(tmp_path, persist=Saves())
    assert dist._queue is not None
    dist._queue.push("archive", 7)
    dist.admit([_line(0)])
    assert dist.drain_queue() == 1
    assert dist.stats["queue_pending"] == 0 and dist.stats["queue_dead_letters"] == 0


def test_admit_archives_only_the_lines_the_queue_accepted(tmp_path) -> None:
    from autosiem.archive import JournalFile

    dist = _dist(tmp_path, max_pending=2, archive_path=str(tmp_path / "a.jsonl"))
    assert dist.admit([_line(i) for i in range(5)]) == 2
    assert dist.admit([_line(i) for i in range(2, 5)]) == 0
    assert len(JournalFile(str(tmp_path / "a.jsonl")).read_all()) == 2


# --- the behavioral baseline is learned once ------------------------------------


def _baseline_after(tmp_path, lines: list[str], persist: Any, name: str) -> dict[str, Any]:
    pipeline = AutoSIEMPipeline([])
    dist = _dist(tmp_path / name, pipeline=pipeline, persist=persist)
    dist.admit(lines)
    for _ in range(5):
        try:
            dist.drain_queue()
            break
        except sqlite3.OperationalError:
            continue
    return pipeline.anomaly_detector.state.to_dict()


@pytest.mark.parametrize("failure", ["transient", "poison"])
def test_a_retried_or_bisected_batch_is_learned_once(tmp_path, failure: str) -> None:
    lines = [_line(i, user=f"u{i % 3}") for i in range(12)]
    (tmp_path / "clean").mkdir()
    (tmp_path / "retried").mkdir()
    clean = _baseline_after(tmp_path, lines, Saves(), "clean")
    if failure == "transient":
        retried = _baseline_after(tmp_path, lines, Saves(fail_times=2), "retried")
    else:
        class RejectsPoison(Saves):
            def __call__(self, result: Any) -> None:
                if any(event.user == "poison" for event in result.events):
                    raise ValueError("bad value")
                super().__call__(result)

        retried = _baseline_after(tmp_path, lines[:5] + [json.dumps({"user": "poison", "action": "x"})] + lines[5:], RejectsPoison(), "retried")
        assert "poison" not in json.dumps(retried), "the set-aside line is not learned either"
    assert BaselineState.from_dict(retried).to_dict() == clean


def test_suppression_repeats_are_counted_once_when_a_batch_is_bisected(tmp_path) -> None:
    """The suppression engine counts repeats in memory. Bisection used to count
    the good lines again, so they crossed the auto-repeat threshold and real
    findings around a bad line came out suppressed."""
    from autosiem.rules import load_rules
    from autosiem.suppression import SuppressionEngine
    from pathlib import Path

    rules = load_rules(Path(__file__).resolve().parents[1] / "rules")
    failed = [json.dumps({"timestamp": f"2026-08-04T10:00:{i:02d}Z", "category": "authentication", "action": "login_failed",
                          "outcome": "failure", "user": "mallory", "host": "vpn-1", "src_ip": "198.51.100.25"}) for i in range(4)]

    class RejectsPoison(Saves):
        def __call__(self, result: Any) -> None:
            if any(event.user == "poison" for event in result.events):
                raise ValueError("bad value")
            super().__call__(result)

    def run(lines: list[str], name: str) -> tuple[int, int]:
        (tmp_path / name).mkdir()
        pipeline = AutoSIEMPipeline(rules, suppression_engine=SuppressionEngine())
        counts = {"findings": 0, "suppressed": 0}

        def tally(result: Any) -> None:
            counts["findings"] += len(result.findings)
            counts["suppressed"] += len(result.suppressed)

        dist = _dist(tmp_path / name, pipeline=pipeline, persist=RejectsPoison())
        dist.admit(lines)
        dist.drain_queue(on_result=tally)
        return counts["findings"], counts["suppressed"]

    clean = run(failed, "clean")
    bisected = run(failed[:2] + [json.dumps({"user": "poison", "action": "x"})] + failed[2:], "bisected")
    assert clean[0] > 0
    assert bisected == clean


def test_a_failed_ack_still_delivers_the_backend_copy_and_the_report(tmp_path, monkeypatch) -> None:
    backend = FakeBackend(failing=False)
    dist = _with_backend(tmp_path, backend)
    queue = dist._queue
    assert queue is not None
    real_ack = queue.ack_many
    calls = {"n": 0}

    def flaky(offsets: list[int]) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.OperationalError("database is locked")
        real_ack(offsets)

    monkeypatch.setattr(queue, "ack_many", flaky)
    reported: list[Any] = []
    dist.admit([_line(i) for i in range(5)])
    with pytest.raises(sqlite3.OperationalError):
        dist.drain_queue(on_result=reported.append)
    dist.drain_queue(on_result=reported.append)
    assert len(backend.stored) == 5 and len(reported) == 1
    assert dist.stats["queue_pending"] == 0


def test_a_processing_failure_is_not_learned_before_the_retry(tmp_path) -> None:
    pipeline = AutoSIEMPipeline([])
    before = pipeline.anomaly_detector.state.to_dict()
    calls = {"n": 0}
    real = pipeline.process_lines

    def flaky(lines: list[str]) -> Any:
        result = real(lines)  # the baseline has learned these events by now
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.OperationalError("database is locked")
        return result

    pipeline.process_lines = flaky  # type: ignore[method-assign]
    dist = _dist(tmp_path, pipeline=pipeline, persist=Saves())
    dist.admit([_line(0)])
    with pytest.raises(sqlite3.OperationalError):
        dist.drain_queue()
    assert pipeline.anomaly_detector.state.to_dict() == before


# --- the event backend ----------------------------------------------------------


class FakeBackend:
    def __init__(self, failing: bool = True) -> None:
        self.failing = failing
        self.calls = 0
        self.stored: list[Any] = []

    def store_events(self, events: list[Any]) -> None:
        self.calls += 1
        if self.failing:
            raise BackendError("OpenSearch request failed: timed out")
        self.stored.extend(events)


def _with_backend(tmp_path, backend: FakeBackend, **kwargs: Any) -> DistributedPipeline:
    dist = _dist(tmp_path, persist=Saves(), backend_type="opensearch", **kwargs)
    dist._backend = backend  # type: ignore[assignment]
    return dist


def test_a_backend_outage_never_holds_up_the_primary_store(tmp_path, monkeypatch) -> None:
    clock = {"now": 1000.0}
    monkeypatch.setattr(distributed.time, "monotonic", lambda: clock["now"])
    backend = FakeBackend()
    dist = _with_backend(tmp_path, backend)
    for i in range(3):
        dist.admit([_line(i)])
        assert dist.drain_queue() == 1
    assert dist.stats["queue_pending"] == 0
    assert backend.calls == 1, "a silent cluster costs a timeout per call; it is left alone for a while"
    assert dist.backend_backlog == 3
    backend.failing = False
    clock["now"] += distributed.BACKEND_RETRY_SECONDS
    dist.drain_queue()
    assert len(backend.stored) == 3 and dist.backend_backlog == 0


def test_the_backend_backlog_is_bounded(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(distributed.time, "monotonic", lambda: 0.0)
    dist = _with_backend(tmp_path, FakeBackend(), max_pending=4)
    for i in range(7):
        dist.admit([_line(i)])
        dist.drain_queue()
    assert dist.backend_backlog == 4 and dist.backend_dropped == 3


# --- QueueDrainer ---------------------------------------------------------------


def _wait_until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("timed out")
        time.sleep(0.01)


def test_the_drainer_retries_a_failure_with_nothing_new_arriving() -> None:
    """The wedge: one notify, an outage, then silence. The lines must still go."""
    attempts: list[float] = []
    done = threading.Event()

    def drain() -> None:
        attempts.append(time.monotonic())
        if len(attempts) < 3:
            raise sqlite3.OperationalError("database is locked")
        done.set()

    drainer = QueueDrainer(drain, max_wait=0.0, retry_initial=0.02, retry_max=0.05)
    try:
        drainer.notify(1)
        assert done.wait(5)
        assert len(attempts) == 3
        assert attempts[2] - attempts[1] >= attempts[1] - attempts[0] - 0.005, "the delay grows"
    finally:
        drainer.close()


def test_the_drainer_waits_for_a_batch_to_fill() -> None:
    drained = threading.Event()
    drainer = QueueDrainer(drained.set, max_batch=10, max_wait=30.0)
    try:
        drainer.notify(3)
        assert not drained.wait(0.1)
        drainer.notify(7)
        assert drained.wait(2)
    finally:
        drainer.close()


def test_a_full_batch_drains_without_waiting() -> None:
    drained = threading.Event()
    drainer = QueueDrainer(drained.set, max_batch=10, max_wait=30.0)
    try:
        drainer.notify(10)
        assert drained.wait(2)
    finally:
        drainer.close()


def test_close_drains_one_last_time() -> None:
    count = {"n": 0}
    drainer = QueueDrainer(lambda: count.__setitem__("n", count["n"] + 1), max_wait=30.0)
    drainer.notify(1)
    drainer.close()
    assert count["n"] >= 1


# --- SyslogServer bursts --------------------------------------------------------


def _send(port: int, payloads: list[bytes]) -> None:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for payload in payloads:
            client.sendto(payload, ("127.0.0.1", port))
    finally:
        client.close()


def test_bursts_are_handed_over_by_the_receive_thread() -> None:
    bursts: list[tuple[str, list[dict[str, Any]]]] = []
    lock = threading.Lock()

    def take(raws: list[dict[str, Any]]) -> None:
        with lock:
            bursts.append((threading.current_thread().name, raws))

    server = SyslogServer(lambda raw: None, port=0, batch_handler=take)
    server.start()
    try:
        _send(server.port, [b"<13>Oct 11 22:14:15 host app: one\n<13>Oct 11 22:14:15 host app: two", b"<13>Oct 11 22:14:15 host app: three"])
        _wait_until(lambda: sum(len(raws) for _name, raws in bursts) == 3)
    finally:
        server.stop()
    assert {name for name, _raws in bursts} == {"autosiem-listener"}
    assert server._executor is None
    assert all(raw["sender_ip"] == "127.0.0.1" for _name, raws in bursts for raw in raws)


def test_the_allowlist_still_applies_to_bursts() -> None:
    got: list[dict[str, Any]] = []
    server = SyslogServer(lambda raw: None, port=0, allowed_hosts={"192.0.2.1"}, batch_handler=got.extend)
    server.start()
    try:
        _send(server.port, [b"<13>Oct 11 22:14:15 host app: refused"])
        time.sleep(0.2)
    finally:
        server.stop()
    assert got == []


def test_a_failing_burst_handler_is_counted_per_line() -> None:
    def broken(raws: list[dict[str, Any]]) -> None:
        raise RuntimeError("disk full")

    server = SyslogServer(lambda raw: None, port=0, batch_handler=broken)
    server.start()
    try:
        _send(server.port, [b"<13>Oct 11 22:14:15 host app: a\n<13>Oct 11 22:14:15 host app: b"])
        _wait_until(lambda: server.failures == 2)
    finally:
        server.stop()
    assert server.failures_by_stage["process"] == 2


def test_a_received_line_is_durable_before_it_is_processed(tmp_path) -> None:
    """What makes SIGKILL lose nothing that was read: the queue file has every
    line while the drainer has not processed one."""
    dist = _dist(tmp_path, persist=Saves())

    def admit(raws: list[dict[str, Any]]) -> None:
        dist.admit([json.dumps(raw) for raw in raws])

    server = SyslogServer(lambda raw: None, port=0, batch_handler=admit)
    server.start()
    try:
        _send(server.port, [f"<13>Oct 11 22:14:15 host app: line {i}".encode() for i in range(50)])
        other = DurableQueue(str(tmp_path / "q.db"))  # another connection, as a restart would open
        _wait_until(lambda: other.pending() == 50)
    finally:
        server.stop()

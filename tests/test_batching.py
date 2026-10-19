"""Micro-batching for the UDP listener.

`AutoSIEMPipeline.process_lines` builds incidents from the findings of ONE call,
and the listener made one call per datagram: 1500 failed logins for one user
gave 1500 incidents and nothing ever correlated.
"""

from __future__ import annotations

import threading

import pytest

from autosiem.listeners import BatchingHandler, SyslogServer


def _handler(process, failed=None, **kwargs):
    return BatchingHandler(process, failed or (lambda exc, count: None), **kwargs)


def test_a_full_batch_is_processed_at_once() -> None:
    batches: list[list[dict]] = []
    done = threading.Event()

    def process(batch: list[dict]) -> None:
        batches.append(batch)
        done.set()

    handler = _handler(process, max_batch=10, max_wait=60.0)
    for i in range(10):
        handler({"i": i})
    assert done.wait(timeout=5)
    handler.close()
    assert len(batches) == 1 and [r["i"] for r in batches[0]] == list(range(10))


def test_a_partial_batch_is_flushed_after_max_wait() -> None:
    batches: list[list[dict]] = []
    done = threading.Event()

    def process(batch: list[dict]) -> None:
        batches.append(batch)
        done.set()

    handler = _handler(process, max_batch=1000, max_wait=0.3)
    for i in range(3):
        handler({"i": i})
    assert done.wait(timeout=5)
    handler.close()
    assert [len(b) for b in batches] == [3]


def test_close_flushes_everything_still_buffered() -> None:
    batches: list[list[dict]] = []
    handler = _handler(batches.append, max_batch=1000, max_wait=3600.0)
    for i in range(7):
        handler({"i": i})
    handler.close()
    assert [len(b) for b in batches] == [7]


def test_batches_never_exceed_max_batch_and_nothing_is_lost() -> None:
    batches: list[list[dict]] = []
    handler = _handler(batches.append, max_batch=4, max_wait=3600.0)
    for i in range(10):
        handler({"i": i})
    handler.close()
    assert [len(b) for b in batches] == [4, 4, 2]
    assert [r["i"] for b in batches for r in b] == list(range(10))


def test_batches_run_one_at_a_time_in_one_thread() -> None:
    threads: set[int] = set()
    active = {"now": 0, "max": 0}
    guard = threading.Lock()

    def process(batch: list[dict]) -> None:
        with guard:
            threads.add(threading.get_ident())
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
        threading.Event().wait(0.005)
        with guard:
            active["now"] -= 1

    handler = _handler(process, max_batch=3, max_wait=0.01)

    def feed(start: int) -> None:
        for i in range(start, start + 30):
            handler({"i": i})

    feeders = [threading.Thread(target=feed, args=(n * 30,)) for n in range(4)]
    for t in feeders:
        t.start()
    for t in feeders:
        t.join()
    handler.close()
    assert active["max"] == 1 and len(threads) == 1


def test_a_failing_batch_is_reported_with_its_line_count_and_the_loop_survives() -> None:
    failures: list[tuple[str, int]] = []
    seen: list[int] = []
    calls = {"n": 0}

    def process(batch: list[dict]) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database is locked")
        seen.append(len(batch))

    handler = _handler(process, lambda exc, count: failures.append((type(exc).__name__, count)), max_batch=3, max_wait=3600.0)
    for i in range(6):
        handler({"i": i})
    handler.close()
    assert failures == [("RuntimeError", 3)]
    assert seen == [3]


def test_a_batch_size_of_one_is_synchronous_and_serialized() -> None:
    order: list[int] = []
    active = {"now": 0, "max": 0}
    guard = threading.Lock()

    def process(batch: list[dict]) -> None:
        with guard:
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
        threading.Event().wait(0.002)
        order.append(batch[0]["i"])
        with guard:
            active["now"] -= 1

    handler = _handler(process, max_batch=1)
    feeders = [threading.Thread(target=lambda n=n: [handler({"i": n * 10 + k}) for k in range(10)]) for n in range(4)]
    for t in feeders:
        t.start()
    for t in feeders:
        t.join()
    assert len(order) == 40, "handled before the call returned"
    assert active["max"] == 1
    handler.close()


def test_a_synchronous_failure_propagates_to_the_server_which_counts_it() -> None:
    def process(batch: list[dict]) -> None:
        raise RuntimeError("disk full")

    server = SyslogServer(_handler(process, max_batch=1))
    server._process_line("<13>Aug  5 09:30:00 vpn-1 sshd[1]: ok", ("203.0.113.9", 514))
    assert server.failures == 1 and server.failures_by_stage["process"] == 1


def test_record_failure_counts_every_line_of_a_batch() -> None:
    server = SyslogServer(lambda raw: None)
    server.record_failure("process", "batch", RuntimeError("database is locked"), count=200)
    assert server.failures == 200 and server.failures_by_stage["process"] == 200


@pytest.mark.parametrize("bad", [0, -3])
def test_a_non_positive_batch_size_is_treated_as_one(bad: int) -> None:
    out: list[int] = []
    handler = _handler(lambda b: out.append(len(b)), max_batch=bad)
    handler({"i": 1})
    assert out == [1]
    handler.close()

from __future__ import annotations

import sys
import types

import pytest

from autosiem.bus import DurableQueue, InMemoryBus, KafkaBus, QueueFullError


def test_inmemorybus_order_and_subscriber_count() -> None:
    bus = InMemoryBus()
    seen: list[tuple[str, object]] = []

    bus.subscribe("alerts", lambda t, m: seen.append(("first", m)))
    bus.subscribe("alerts", lambda t, m: seen.append(("second", m)))

    assert bus.subscriber_count("alerts") == 2
    assert bus.subscriber_count("none") == 0

    bus.publish("alerts", "boom")
    assert seen == [("first", "boom"), ("second", "boom")]
    assert bus.topics() == ["alerts"]

    # Handlers fire again on later publishes, in insertion order.
    bus.publish("alerts", "again")
    assert seen[2:] == [("first", "again"), ("second", "again")]
    assert bus.subscriber_count("alerts") == 2


def test_inmemorybus_untouched_topics_updated() -> None:
    bus = InMemoryBus()
    bus.subscribe("a", lambda t, m: None)
    bus.subscribe("b", lambda t, m: None)
    assert bus.topics() == ["a", "b"]


def test_kafka_available_publishes(monkeypatch) -> None:
    module = types.ModuleType("kafka")
    sent: list[tuple[str, bytes]] = []

    class FakeProducer:
        def __init__(self, bootstrap_servers: str = "localhost:9092") -> None:
            self.bootstrap_servers = bootstrap_servers

        def send(self, topic: str, value: bytes) -> None:
            sent.append((topic, value))

    setattr(module, "KafkaProducer", FakeProducer)
    monkeypatch.setitem(sys.modules, "kafka", module)

    bus = KafkaBus()
    assert bus.available is True

    got: list[object] = []
    bus.subscribe("t", lambda t, m: got.append(m))
    bus.publish("t", {"x": 1})

    assert sent and sent[0][0] == "t"
    assert got == [{"x": 1}]


def test_kafka_unavailable_raises_on_use_not_init(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "kafka", None)  # import kafka -> ImportError
    bus = KafkaBus()
    assert bus.available is False

    with pytest.raises(RuntimeError, match="kafka-python"):
        bus.publish("t", "m")
    with pytest.raises(RuntimeError, match="kafka-python"):
        bus.subscribe("t", lambda t, m: None)


def test_durablequeue_push_pull_ack_pending_replay(tmp_path) -> None:
    q = DurableQueue(str(tmp_path / "queue.db"))
    q.push("t", {"n": 1})
    q.push("t", {"n": 2})

    assert q.pending() == 2
    assert q.pull() == [
        {"offset": 1, "topic": "t", "payload": {"n": 1}},
        {"offset": 2, "topic": "t", "payload": {"n": 2}},
    ]

    # Replay returns all unacked in offset order.
    assert [r["payload"] for r in q.replay()] == [{"n": 1}, {"n": 2}]

    q.ack(1)
    assert q.pending() == 1
    assert q.checkpoint() == 1
    assert [r["payload"] for r in q.replay()] == [{"n": 2}]


def test_durablequeue_max_pending_raises_queue_full(tmp_path) -> None:
    q = DurableQueue(str(tmp_path / "queue.db"))
    q.push("t", "a", max_pending=2)
    q.push("t", "b", max_pending=2)
    assert len(q) == 2
    with pytest.raises(QueueFullError):
        q.push("t", "c", max_pending=2)
    assert len(q) == 2


def test_durablequeue_checkpoint_reflects_acked(tmp_path) -> None:
    q = DurableQueue(str(tmp_path / "queue.db"))
    assert q.checkpoint() == 0
    for i in range(4):
        q.push("t", i)
    rows = q.pull(10)
    for row in rows[:3]:
        q.ack(row["offset"])
    assert q.checkpoint() == 3
    assert q.pending() == 1


def test_durablequeue_compact_deletes_acked(tmp_path) -> None:
    q = DurableQueue(str(tmp_path / "queue.db"))
    for i in range(5):
        q.push("t", i)
    rows = q.pull(10)
    for row in rows[:3]:
        q.ack(row["offset"])

    assert len(q) == 5
    q.compact(max_acked=3)  # remove offsets 1, 2, 3 (all acked)
    assert len(q) == 2
    assert [r["payload"] for r in q.pull()] == [3, 4]


def test_compact_never_deletes_a_pending_message_below_the_checkpoint(tmp_path) -> None:
    """With concurrent workers, offset 3 can be acked while offset 2 is pending."""
    q = DurableQueue(str(tmp_path / "queue.db"))
    offsets = [q.push("t", i) for i in range(4)]
    for offset in (offsets[0], offsets[2], offsets[3]):
        q.ack(offset)

    removed = q.compact(max_acked=q.checkpoint())
    assert removed == 3
    assert [row["payload"] for row in q.pull()] == [1]


def test_compact_with_no_ceiling_removes_every_acked_row(tmp_path) -> None:
    """The old default (max_acked=1000) was an offset ceiling, so a bare
    compact() on a busy queue removed only the first thousand."""
    q = DurableQueue(str(tmp_path / "queue.db"))
    offsets = [q.push("t", i) for i in range(1500)]
    for offset in offsets[:-1]:
        q.ack(offset)

    assert q.compact() == 1499
    assert len(q) == 1 and q.pending() == 1

# --- used from the listener's worker threads ----------------------------------
# The listener builds the queue on the main thread and pushes from its syslog
# worker pool. A plain sqlite3 connection refuses that, and the listener
# swallowed the error, so with AUTOSIEM_QUEUE_PATH set every event was lost.


def test_durablequeue_can_be_used_from_another_thread(tmp_path) -> None:
    import threading

    queue = DurableQueue(str(tmp_path / "q.db"))
    errors: list[BaseException] = []

    def push() -> None:
        try:
            offset = queue.push("ingest", {"line": "x"})
            queue.ack(offset)
        except BaseException as exc:  # noqa: BLE001 - the test inspects it
            errors.append(exc)

    worker = threading.Thread(target=push)
    worker.start()
    worker.join(5)
    assert errors == []
    assert len(queue) == 1 and queue.pending() == 0


def test_concurrent_pushes_get_distinct_offsets_and_respect_capacity(tmp_path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    queue = DurableQueue(str(tmp_path / "q.db"))

    def push(i: int) -> int | None:
        try:
            return queue.push("ingest", {"i": i}, max_pending=25)
        except QueueFullError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        offsets = list(pool.map(push, range(100)))
    accepted = [offset for offset in offsets if offset is not None]
    # The capacity check and the insert are one step, so racing threads cannot
    # all see 24 pending and all insert.
    assert len(accepted) == 25
    assert len(set(accepted)) == 25
    assert queue.pending() == 25

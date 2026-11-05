"""The durable queue deletes acknowledged rows instead of keeping one per event for ever."""

from __future__ import annotations

import json
import sqlite3
import sys

import pytest

import autosiem.bus as bus
from autosiem.bus import DurableQueue


@pytest.fixture
def small(monkeypatch):
    monkeypatch.setattr(bus, "COMPACT_AFTER_ACKS", 10)
    monkeypatch.setattr(bus, "COMPACT_CHUNK", 3)


def _filled(path, n: int) -> tuple[DurableQueue, list[int]]:
    queue = DurableQueue(str(path))
    return queue, queue.push_many("ingest", [{"line": str(i)} for i in range(n)])


def test_acknowledging_enough_rows_deletes_them(tmp_path, small) -> None:
    queue, offsets = _filled(tmp_path / "q.db", 30)
    queue.dead_letter(offsets[0])
    queue.ack_many(offsets[1:9])
    assert len(queue) == 30, "below the threshold nothing is deleted"
    queue.ack_many(offsets[9:20])
    checkpoint = offsets[19]
    assert queue.checkpoint() == checkpoint, "the newest acknowledged row is kept"
    assert queue.pending() == 10 and queue.dead_letters() == 1
    assert len(queue) == 1 + 1 + 10  # dead letter, newest acked, pending
    assert [m["payload"]["line"] for m in queue.pull(100)] == [str(i) for i in range(20, 30)]


def test_new_offsets_never_reuse_deleted_ones(tmp_path, small) -> None:
    queue, offsets = _filled(tmp_path / "q.db", 12)
    queue.ack_many(offsets)
    assert queue.push("ingest", {"line": "next"}) > offsets[-1]


def test_a_queue_left_large_by_an_older_version_is_cleared_on_the_first_ack(tmp_path, monkeypatch) -> None:
    path = tmp_path / "old.db"
    queue, offsets = _filled(path, 40)
    queue.ack_many(offsets[:39])  # threshold 10 000: nothing deleted yet
    assert len(queue) == 40
    monkeypatch.setattr(bus, "COMPACT_AFTER_ACKS", 10)
    reopened = DurableQueue(str(path))
    reopened.ack(offsets[39])
    assert len(reopened) == 1 and reopened.checkpoint() == offsets[39]


def test_rows_are_deleted_in_chunks(tmp_path, small) -> None:
    """One DELETE of a million rows held the queue lock for seconds, and the
    listener's receive thread waits on that lock."""
    queue, offsets = _filled(tmp_path / "q.db", 13)
    deletes: list[str] = []
    queue._conn.set_trace_callback(lambda sql: deletes.append(sql) if sql.startswith("DELETE") else None)
    queue.ack_many(offsets)
    assert len(deletes) == 5  # 12 rows, 3 at a time: 4 full chunks and the empty one that ends it
    assert len(queue) == 1


def test_a_failed_compaction_never_fails_the_ack(tmp_path, small, monkeypatch, caplog) -> None:
    queue, offsets = _filled(tmp_path / "q.db", 12)

    def locked(self) -> int:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(DurableQueue, "compact_acked", locked)
    with caplog.at_level("WARNING", logger="autosiem.bus"):
        queue.ack_many(offsets[:11])
    assert queue.pending() == 1, "the acknowledgement itself landed"
    assert "could not compact the durable queue" in caplog.text
    monkeypatch.undo()
    monkeypatch.setattr(bus, "COMPACT_AFTER_ACKS", 10)
    queue.ack(offsets[11])  # retried on the very next ack
    assert len(queue) == 1


def test_vacuum_shrinks_the_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(bus, "COMPACT_AFTER_ACKS", 10**9)
    queue, offsets = _filled(tmp_path / "q.db", 0)
    offsets = queue.push_many("ingest", [{"line": "x" * 500} for _ in range(4000)])
    queue.ack_many(offsets)
    assert queue.compact_acked() == 3999
    before, after = queue.vacuum()
    assert after < before / 10
    assert queue.checkpoint() == offsets[-1]


def test_distributed_compact_reports_what_it_removed(capsys, monkeypatch, tmp_path) -> None:
    from autosiem.cli import main

    monkeypatch.setattr(bus, "COMPACT_AFTER_ACKS", 10**9)
    queue_path = tmp_path / "cli.db"
    queue, _ = _filled(queue_path, 0)
    offsets = queue.push_many("ingest", [{"line": json.dumps({"user": "u"}), "seq": i} for i in range(300)])
    queue.ack_many(offsets[:250])
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))
    monkeypatch.setattr(sys, "argv", ["autosiem", "distributed", "--compact", "--db", str(tmp_path / "d.db")])
    main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["compacted"]["removed"] == 249
    assert payload["compacted"]["bytes_after"] <= payload["compacted"]["bytes_before"]
    assert payload["stats"]["queue_pending"] == 50 and payload["stats"]["queue_total"] == 51


@pytest.mark.parametrize("flag", ["--compact", "--replay", "--requeue-dead-letters"])
def test_a_queue_flag_without_a_queue_says_so_instead_of_exiting_0(capsys, monkeypatch, tmp_path, flag: str) -> None:
    from autosiem.cli import main

    monkeypatch.delenv("AUTOSIEM_QUEUE_PATH", raising=False)
    monkeypatch.setattr(sys, "argv", ["autosiem", "distributed", flag, "--db", str(tmp_path / "d.db")])
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert str(excinfo.value) == f"{flag} needs a durable queue; set AUTOSIEM_QUEUE_PATH"
    assert capsys.readouterr().out == ""


def test_compacting_a_queue_in_use_fails_in_one_line(capsys, monkeypatch, tmp_path) -> None:
    import subprocess
    import time

    from autosiem.cli import main

    queue_path = tmp_path / "busy.db"
    queue, offsets = _filled(queue_path, 5)
    queue.ack_many(offsets)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sqlite3, sys, time; c = sqlite3.connect(sys.argv[1], isolation_level=None); "
         "c.execute('BEGIN IMMEDIATE'); print('held', flush=True); time.sleep(30)", str(queue_path)],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "held"
        monkeypatch.setattr(bus, "COMPACT_AFTER_ACKS", 10**9)
        monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))
        monkeypatch.setattr(sys, "argv", ["autosiem", "distributed", "--compact", "--db", str(tmp_path / "d.db")])
        started = time.monotonic()
        with pytest.raises(SystemExit) as excinfo:
            main()
    finally:
        holder.kill()
        holder.wait()
    message = str(excinfo.value)
    assert message.startswith("could not compact the queue: OperationalError: database is locked")
    assert "\n" not in message and "Traceback" not in message
    assert time.monotonic() - started < 30


# --- a refused commit must not leave the transaction open ----------------------


def _reader_holding_a_read_lock(path) -> sqlite3.Connection:
    reader = sqlite3.connect(str(path), isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM messages").fetchone()
    return reader


def _another_writer_can_write(path) -> bool:
    other = sqlite3.connect(str(path), timeout=0.2)
    try:
        other.execute("INSERT INTO messages (topic, payload, created_at) VALUES ('ingest', '{}', 'x')")
        other.commit()
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        other.close()


def test_a_compaction_refused_at_commit_does_not_keep_the_queue_locked(tmp_path, small, caplog) -> None:
    """Found by Codex review on #36: the failed DELETE stayed open and held the
    write lock against every other producer, even after the reader left."""
    path = tmp_path / "q.db"
    queue, offsets = _filled(path, 12)
    queue.ack_many(offsets[:9])
    queue._conn.execute("PRAGMA busy_timeout = 100")
    reader = _reader_holding_a_read_lock(path)
    with caplog.at_level("WARNING", logger="autosiem.bus"):
        queue._acks_since_compact = 10
        queue._compact_quietly()
    assert "could not compact the durable queue" in caplog.text
    assert not queue._conn.in_transaction
    reader.execute("COMMIT")
    reader.close()
    assert _another_writer_can_write(path)


def test_a_push_refused_at_commit_is_not_stored_by_a_later_one(tmp_path) -> None:
    """Left open, the failed insert was committed by the next push: lines the
    listener counted as refused were stored after all."""
    path = tmp_path / "q.db"
    queue = DurableQueue(str(path))
    queue._conn.execute("PRAGMA busy_timeout = 100")
    reader = _reader_holding_a_read_lock(path)
    with pytest.raises(sqlite3.OperationalError):
        queue.push_many("ingest", [{"line": "refused"}])
    reader.execute("COMMIT")
    reader.close()
    queue.push("ingest", {"line": "accepted"})
    assert [m["payload"]["line"] for m in queue.pull(10)] == ["accepted"]


def test_an_ack_refused_at_commit_can_be_retried(tmp_path) -> None:
    path = tmp_path / "q.db"
    queue, offsets = _filled(path, 3)
    queue._conn.execute("PRAGMA busy_timeout = 100")
    reader = _reader_holding_a_read_lock(path)
    with pytest.raises(sqlite3.OperationalError):
        queue.ack_many(offsets)
    assert not queue._conn.in_transaction and queue.pending() == 3
    reader.execute("COMMIT")
    reader.close()
    queue.ack_many(offsets)
    assert queue.pending() == 0

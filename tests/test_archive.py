from __future__ import annotations

from autosiem.archive import ArchiveWriter, JournalFile, list_archived, restore
from autosiem.bus import DurableQueue


def test_append_read_all_sequence(tmp_path) -> None:
    journal = JournalFile(str(tmp_path / "journal.jsonl"))
    assert journal.sequence() == 0

    journal.append({"a": 1})
    journal.append({"a": 2})
    journal.append({"a": 3})

    assert journal.sequence() == 3
    assert journal.read_all() == [{"a": 1}, {"a": 2}, {"a": 3}]


def test_tail_order_and_explicit_seq(tmp_path) -> None:
    journal = JournalFile(str(tmp_path / "journal.jsonl"))
    for i in range(5):
        journal.append({"n": i})

    assert journal.tail(2) == [{"n": 3}, {"n": 4}]
    assert journal.tail(10) == [{"n": i} for i in range(5)]

    # Explicit seq is honored; records don't need to be contiguous.
    assert journal.append({"n": 99}, seq=50) == 50
    assert journal.sequence() == 6


def test_restore_from_seq(tmp_path) -> None:
    path = str(tmp_path / "journal.jsonl")
    journal = JournalFile(path)
    for i in range(5):
        journal.append({"n": i})

    assert [r["n"] for r in restore(path)] == [0, 1, 2, 3, 4]
    assert [r["n"] for r in restore(path, start_seq=2)] == [2, 3, 4]


def test_list_archived(tmp_path) -> None:
    path = str(tmp_path / "journal.jsonl")
    journal = JournalFile(path)
    journal.append({"n": 7}, seq=0)
    journal.append({"n": 8}, seq=1)

    entries = list_archived(path)
    assert entries == [
        {"seq": 0, "record": {"n": 7}},
        {"seq": 1, "record": {"n": 8}},
    ]


def test_archive_writer_replay_from_checkpoint(tmp_path) -> None:
    journal = JournalFile(str(tmp_path / "journal.jsonl"))
    queue = DurableQueue(str(tmp_path / "queue.db"))
    writer = ArchiveWriter(journal, queue)

    writer.write({"a": 1})  # seq 0
    writer.write({"a": 2})  # seq 1
    writer.write({"a": 3})  # seq 2

    assert journal.read_all() == [{"a": 1}, {"a": 2}, {"a": 3}]
    assert queue.pending() == 3

    # Acknowledge the first queued record (queue offset 1 -> journal seq 0).
    pulled = queue.pull(1)
    queue.ack(pulled[0]["offset"])
    assert queue.checkpoint() == 1

    replayed = writer.replay_from_checkpoint()
    assert [r["a"] for r in replayed] == [2, 3]


def test_archive_writer_without_queue(tmp_path) -> None:
    journal = JournalFile(str(tmp_path / "journal.jsonl"))
    writer = ArchiveWriter(journal, queue=None)
    writer.write({"k": "v"})
    assert journal.read_all() == [{"k": "v"}]
    assert writer.replay_from_checkpoint() == [{"k": "v"}]
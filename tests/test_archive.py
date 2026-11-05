from __future__ import annotations

import json

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

def test_concurrent_appends_get_distinct_sequence_numbers(tmp_path) -> None:
    """The listener appends from several worker threads; seq is read-then-write."""
    from concurrent.futures import ThreadPoolExecutor

    journal = JournalFile(str(tmp_path / "archive.jsonl"))
    with ThreadPoolExecutor(max_workers=8) as pool:
        seqs = list(pool.map(lambda i: journal.append({"i": i}), range(200)))
    assert sorted(seqs) == list(range(200))
    assert sorted(entry["seq"] for entry in list_archived(journal.path)) == list(range(200))


# --- append cost, torn lines, several processes ---------------------------------


def test_append_scans_only_what_was_written_since_the_last_look(tmp_path, monkeypatch) -> None:
    """Every append re-parsed the whole file: 7 appends/s at 100k lines."""
    import autosiem.archive as archive

    path = tmp_path / "j.jsonl"
    path.write_text("".join(json.dumps({"seq": i, "record": {"i": i}}) + "\n" for i in range(1000)))
    journal = JournalFile(str(path))
    assert journal.append({"i": 1000}) == 1000  # the one full scan
    parsed = {"n": 0}
    real_parse = archive._parse

    def counting(line: bytes):
        parsed["n"] += 1
        return real_parse(line)

    monkeypatch.setattr(archive, "_parse", counting)
    for i in range(100):
        journal.append({"i": 1001 + i})
    assert parsed["n"] == 0
    assert journal.sequence() == 1101


def test_a_torn_last_line_does_not_break_every_later_append(tmp_path, caplog) -> None:
    path = tmp_path / "j.jsonl"
    path.write_text(json.dumps({"seq": 0, "record": {"a": 1}}) + "\n" + '{"seq": 1, "rec')
    journal = JournalFile(str(path))
    assert journal.append({"b": 2}) == 1
    assert journal.append_many([{"c": 3}, {"d": 4}]) == [2, 3]
    with caplog.at_level("WARNING", logger="autosiem.archive"):
        assert journal.read_all() == [{"a": 1}, {"b": 2}, {"c": 3}, {"d": 4}]
    assert "skipped 1 line(s)" in caplog.text
    assert path.read_text().splitlines()[1] == '{"seq": 1, "rec', "the fragment is kept, on its own line"


def test_writes_by_another_journal_object_are_counted(tmp_path) -> None:
    path = str(tmp_path / "j.jsonl")
    first, second = JournalFile(path), JournalFile(path)
    seqs = [first.append({"n": 0}), second.append({"n": 1}), first.append({"n": 2}), *second.append_many([{"n": 3}, {"n": 4}])]
    assert seqs == [0, 1, 2, 3, 4]
    assert [entry["seq"] for entry in list_archived(path)] == [0, 1, 2, 3, 4]


def test_a_replaced_journal_is_counted_afresh(tmp_path) -> None:
    path = tmp_path / "j.jsonl"
    journal = JournalFile(str(path))
    journal.append_many([{"n": i} for i in range(5)])
    path.write_text("")  # rotated by an operator
    assert journal.append({"n": 0}) == 0


def test_several_processes_never_share_a_sequence_number(tmp_path) -> None:
    """Sequence numbers were unique per process only."""
    import subprocess
    import sys
    from pathlib import Path

    path = str(tmp_path / "shared.jsonl")
    src = str(Path(__file__).resolve().parents[1] / "src")
    script = (
        "import sys; sys.path.insert(0, sys.argv[1]); from autosiem.archive import JournalFile; "
        "j = JournalFile(sys.argv[2]); [j.append({'p': sys.argv[3]}) if i % 2 else j.append_many([{'p': sys.argv[3]}] * 3) for i in range(60)]"
    )
    procs = [subprocess.Popen([sys.executable, "-c", script, src, path, str(n)]) for n in range(4)]
    assert all(proc.wait(timeout=60) == 0 for proc in procs)
    seqs = [entry["seq"] for entry in list_archived(path)]
    assert len(seqs) == 4 * 30 * 4
    assert sorted(seqs) == list(range(len(seqs)))

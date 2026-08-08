"""Durable journaling and archived-record replay for AutoSIEM.

A :class:`JournalFile` is an append-only JSON-lines log of records. Each line
is ``{"seq": n, "record": {...}}`` where ``seq`` is auto-assigned from the
number of records already present. :class:`ArchiveWriter` pairs a journal with
an optional :class:`~autosiem.bus.DurableQueue` so records can be appended and
re-enqueued for backpressure, then replayed from the last acknowledged
checkpoint after a restart.
"""

from __future__ import annotations

import json
import os
from typing import Any


class JournalFile:
    """An append-only, JSON-lines journal of records keyed by sequence."""

    def __init__(self, path: str) -> None:
        self.path = str(path)

    def _entries(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as fh:
            return [
                json.loads(line)
                for line in fh
                if line.strip()
            ]

    def sequence(self) -> int:
        """The number of records written; the next auto sequence value."""
        return len(self._entries())

    def append(self, record: Any, seq: int | None = None) -> int:
        if seq is None:
            seq = self.sequence()
        line = json.dumps({"seq": seq, "record": record})
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return seq

    def read_all(self) -> list[dict[str, Any]]:
        """All records in insertion order."""
        return [entry["record"] for entry in self._entries()]

    def tail(self, n: int) -> list[dict[str, Any]]:
        """The last ``n`` records."""
        return [entry["record"] for entry in self._entries()[-n:]]


def list_archived(path: str) -> list[dict[str, Any]]:
    """Return the raw journal entries as ``{"seq", "record"}`` dicts."""
    return JournalFile(path)._entries()


def restore(path: str, start_seq: int = 0) -> list[dict[str, Any]]:
    """Records with ``seq >= start_seq`` (replay from a checkpoint)."""
    return [
        entry["record"]
        for entry in JournalFile(path)._entries()
        if entry["seq"] >= start_seq
    ]


class ArchiveWriter:
    """Appends records to a journal and optionally enqueues them to a queue."""

    def __init__(self, journal: JournalFile, queue: Any | None = None) -> None:
        self.journal = journal
        self.queue = queue

    def write(self, record: Any) -> int:
        seq = self.journal.append(record)
        if self.queue is not None:
            self.queue.push(topic="archive", payload=seq)
        return seq

    def replay_from_checkpoint(self) -> list[dict[str, Any]]:
        """Replay journal records that were not yet acknowledged.

        Uses the durable queue's highest acked offset as the starting sequence
        number; with no queue, replays from the beginning.
        """
        start = 0
        if self.queue is not None:
            start = self.queue.checkpoint()
        return restore(self.journal.path, start_seq=start)
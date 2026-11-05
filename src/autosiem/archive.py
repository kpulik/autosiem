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
import logging
import os
import threading
from contextlib import contextmanager
from typing import IO, Any, Iterator

from .private_files import create_private

try:  # POSIX; on Windows the journal is safe within one process only
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

_LOG = logging.getLogger(__name__)


class JournalFile:
    """An append-only, JSON-lines journal of records keyed by sequence.

    Appending used to re-read and parse the whole file to find the next sequence
    number (7 appends/s at 100k lines), a torn last line from a crash made every
    later append raise, and two processes could hand out the same number. Now an
    exclusive file lock spans count-and-write, only bytes written since the last
    look are scanned, and a torn line is ended before anything is appended after
    it. Readers skip lines that do not parse, and say how many.
    """

    def __init__(self, path: str) -> None:
        self.path = str(path)
        # Serializes this process's threads; the file lock serializes processes.
        self._lock = threading.Lock()
        self._scanned = 0  # bytes of whole lines already counted
        self._count = 0  # records among them

    @contextmanager
    def _locked(self) -> Iterator[IO[bytes]]:
        with self._lock:
            create_private(self.path)
            with open(self.path, "a+b") as fh:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    yield fh
                finally:
                    if fcntl is not None:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _catch_up(self, fh: IO[bytes]) -> bool:
        """Count records written since the last look; True if the last line is torn."""
        size = fh.seek(0, os.SEEK_END)
        if size < self._scanned:  # truncated or replaced: start over
            self._scanned = self._count = 0
        if size == self._scanned:
            return False
        fh.seek(self._scanned)
        data = fh.read(size - self._scanned)
        whole = data.rfind(b"\n") + 1
        self._count += sum(1 for line in data[:whole].splitlines() if _parse(line) is not None)
        self._scanned += whole
        return whole < len(data)

    def sequence(self) -> int:
        """The number of records written; the next auto sequence value."""
        with self._locked() as fh:
            self._catch_up(fh)
            return self._count

    def append(self, record: Any, seq: int | None = None) -> int:
        with self._locked() as fh:
            if seq is None:
                seq = self._next(fh)
            else:
                self._next(fh)
            self._write(fh, [{"seq": seq, "record": record}])
            return seq

    def append_many(self, records: list[Any]) -> list[int]:
        """Append records in one write; returns their sequence numbers."""
        if not records:
            return []
        with self._locked() as fh:
            first = self._next(fh)
            self._write(fh, [{"seq": first + i, "record": record} for i, record in enumerate(records)])
            return list(range(first, first + len(records)))

    def _next(self, fh: IO[bytes]) -> int:
        if self._catch_up(fh):
            # A crash tore the last line. End it so the next record starts on a
            # line of its own; readers skip it. It is never truncated: the
            # journal is evidence, and the fragment may be all there is.
            fh.write(b"\n")
            fh.flush()
            self._scanned = fh.tell()
        return self._count

    def _write(self, fh: IO[bytes], entries: list[dict[str, Any]]) -> None:
        data = "".join(json.dumps(entry) + "\n" for entry in entries).encode("utf-8")
        fh.write(data)
        fh.flush()
        self._scanned += len(data)
        self._count += len(entries)

    def _entries(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        entries: list[dict[str, Any]] = []
        skipped = 0
        with open(self.path, "rb") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entry = _parse(line)
                if entry is None:
                    skipped += 1
                else:
                    entries.append(entry)
        if skipped:
            _LOG.warning("journal %s: skipped %d line(s) that are not whole records", self.path, skipped)
        return entries

    def read_all(self) -> list[dict[str, Any]]:
        """All records in insertion order."""
        return [entry["record"] for entry in self._entries()]

    def tail(self, n: int) -> list[dict[str, Any]]:
        """The last ``n`` records."""
        return [entry["record"] for entry in self._entries()[-n:]]


def _parse(line: bytes) -> dict[str, Any] | None:
    """One journal entry, or None for a line that is not one (torn, foreign)."""
    try:
        entry = json.loads(line)
    except ValueError:
        return None
    return entry if isinstance(entry, dict) and "seq" in entry and "record" in entry else None


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

    def write_many(self, records: list[Any]) -> list[int]:
        seqs = self.journal.append_many(records)
        if self.queue is not None:
            for seq in seqs:
                self.queue.push(topic="archive", payload=seq)
        return seqs

    def replay_from_checkpoint(self) -> list[dict[str, Any]]:
        """Replay journal records that were not yet acknowledged.

        Uses the durable queue's highest acked offset as the starting sequence
        number; with no queue, replays from the beginning.
        """
        start = 0
        if self.queue is not None:
            start = self.queue.checkpoint()
        return restore(self.journal.path, start_seq=start)
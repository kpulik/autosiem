"""Distributed pipeline configuration for AutoSIEM.

Reads environment variables to enable optional Phase 3 components:
- DurableQueue: backpressure and replay via SQLite FIFO
- JournalFile: append-only archive for durability
- ParserWorkerPool: parallel event processing
- Alternate backends: ClickHouse or OpenSearch storage

All components are opt-in via environment variables. When not configured,
the pipeline runs in the default single-threaded SQLite mode.
"""

from __future__ import annotations

import copy
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Callable

from .archive import ArchiveWriter, JournalFile
from .backends import BackendError, ClickHouseBackend, EventBackend, OpenSearchBackend, SqliteBackend, make_backend
from .bus import DurableQueue, QueueFullError
from .workers import ParserWorkerPool

_LOG = logging.getLogger(__name__)

#: How long the listener leaves a failed event backend alone. A silent cluster
#: costs a 30 s timeout per call, which must not be paid on every batch.
BACKEND_RETRY_SECONDS = 60.0

#: Longest quiet time between warnings about lines being set aside.
SET_ASIDE_WARNING_SECONDS = 10.0


def _is_transient(exc: Exception) -> bool:
    """Whether the whole batch should be retried later, unchanged: an outage.

    Anything else is bisected to find the lines that fail (see
    ``DistributedPipeline._settle``). psycopg is optional, so its errors are
    matched by name.
    """
    if isinstance(exc, (OSError, MemoryError)):
        return True
    return any(cls.__name__ in ("OperationalError", "InterfaceError") for cls in type(exc).__mro__)


@dataclass
class DistributedConfig:
    """Configuration for distributed pipeline mode."""

    # Queue settings
    queue_path: str | None = None
    queue_max_pending: int = 100_000

    # Archive settings
    archive_path: str | None = None

    # Worker settings
    workers: int = 4

    # Backend settings
    backend_type: str = "sqlite"  # sqlite, clickhouse, opensearch
    backend_url: str = ""
    backend_table: str = "events"
    backend_index: str = "events"

    @property
    def queue_enabled(self) -> bool:
        return self.queue_path is not None

    @property
    def archive_enabled(self) -> bool:
        return self.archive_path is not None

    @property
    def parallel_enabled(self) -> bool:
        return self.workers > 1

    @property
    def alternate_backend(self) -> bool:
        return self.backend_type != "sqlite"


def config_from_env() -> DistributedConfig:
    """Read distributed pipeline configuration from environment variables."""
    return DistributedConfig(
        queue_path=os.environ.get("AUTOSIEM_QUEUE_PATH"),
        queue_max_pending=int(os.environ.get("AUTOSIEM_QUEUE_MAX_PENDING", "100000")),
        archive_path=os.environ.get("AUTOSIEM_ARCHIVE_PATH"),
        workers=int(os.environ.get("AUTOSIEM_WORKERS", "4")),
        backend_type=os.environ.get("AUTOSIEM_BACKEND", "sqlite").lower(),
        backend_url=os.environ.get("AUTOSIEM_BACKEND_URL", ""),
        backend_table=os.environ.get("AUTOSIEM_BACKEND_TABLE", "events"),
        backend_index=os.environ.get("AUTOSIEM_BACKEND_INDEX", "events"),
    )


class DistributedPipeline:
    """High-level distributed pipeline coordinator.

    Orchestrates archive → queue → workers → backend in sequence.
    Falls back to simple pipeline when components are not configured.
    """

    def __init__(
        self,
        config: DistributedConfig,
        rules: list[Any],
        db_path: str = "data/autosiem.db",
        pipeline: Any | None = None,
        persist: Callable[[Any], None] | None = None,
        transactional_outbox: bool = False,
    ) -> None:
        self.config = config
        self.rules = rules
        self.db_path = db_path
        # A caller-supplied, fully configured AutoSIEMPipeline (suppressions,
        # threat intel, RAG, SOAR, baseline store). When present it is used for
        # the single processing pass and takes precedence over the worker pool,
        # whose chunks would otherwise run bare pipelines and give each chunk its
        # own behavioral baseline.
        self.pipeline = pipeline
        self.persist = persist
        self.transactional_outbox = transactional_outbox

        # Initialize optional components
        self._queue: DurableQueue | None = None
        self._archive: ArchiveWriter | None = None
        self._workers: ParserWorkerPool | None = None
        self._backend: EventBackend | None = None
        #: A processed batch awaiting a successful save: its result, its queue
        #: messages, and the behavioral baseline from before it was processed.
        self._held: tuple[Any, list[dict[str, Any]], dict[str, Any] | None] | None = None
        #: Offsets of a saved batch whose acknowledgement failed. Retrying only
        #: acknowledges them: processing them again would save them twice.
        self._unacked: list[int] = []
        self._last_set_aside_warning = float("-inf")
        self._backend_backlog: list[Any] = []
        self._backend_retry_at = 0.0
        #: Events whose backend copy was given up on, oldest first, past the bound.
        self.backend_dropped = 0
        #: The last event-backend failure, for reports; None once delivery works.
        self.backend_error: str | None = None

        if config.queue_enabled and config.queue_path:
            self._queue = DurableQueue(config.queue_path)

        if config.archive_enabled and config.archive_path:
            journal = JournalFile(config.archive_path)
            # Deliberately not wired to the ingest queue. ArchiveWriter would
            # push a marker per record onto it, mixing journal sequence numbers
            # into the queue's offset space: the queue's checkpoint then counted
            # archive markers, so it no longer matched any journal sequence and
            # both replay paths silently returned nothing. The journal is
            # durable on its own; replay it with archive.restore().
            self._archive = ArchiveWriter(journal)

        if config.parallel_enabled:
            self._workers = ParserWorkerPool(workers=config.workers, rules=rules)

        if config.alternate_backend and not transactional_outbox:
            self._backend = self._make_backend(config)

    @staticmethod
    def _make_backend(config: DistributedConfig) -> EventBackend | None:
        """Build the configured alternate backend, or None if unrecognised."""
        if config.backend_type == "clickhouse":
            kwargs: dict[str, Any] = {"table": config.backend_table}
            if config.backend_url:
                kwargs["url"] = config.backend_url
            return ClickHouseBackend(**kwargs)
        if config.backend_type == "opensearch":
            kwargs = {"index": config.backend_index}
            if config.backend_url:
                kwargs["url"] = config.backend_url
            return OpenSearchBackend(**kwargs)
        return None

    @property
    def queue_enabled(self) -> bool:
        return self._queue is not None

    def admit(self, lines: list[str]) -> int:
        """Make lines durable without processing them; returns how many fit.

        The lines beyond that were refused because the queue is full.
        :meth:`drain_queue` processes what was admitted.
        """
        if self._queue is None:
            raise ValueError("admit requires a durable queue")
        payloads = [{"line": line, "seq": index} for index, line in enumerate(lines)]
        accepted = len(self._queue.push_many("ingest", payloads, max_pending=self.config.queue_max_pending))
        # Only what was accepted is archived: a caller retries the refused rest,
        # and archiving it on each attempt would journal it more than once.
        self._archive_lines(lines[:accepted])
        return accepted

    @property
    def unacknowledged(self) -> int:
        """Lines saved whose acknowledgement failed: a new process would save them again."""
        return len(self._unacked)

    @property
    def backend_backlog(self) -> int:
        """Events processed and stored but not yet delivered to the event backend."""
        return len(self._backend_backlog)

    def compact_queue(self) -> dict[str, int]:
        """Delete acknowledged queue rows and shrink the file; see DurableQueue.vacuum."""
        if self._queue is None:
            return {"removed": 0, "bytes_before": 0, "bytes_after": 0}
        removed = self._queue.compact_acked()
        before, after = self._queue.vacuum()
        return {"removed": removed, "bytes_before": before, "bytes_after": after}

    def requeue_dead_letters(self) -> int:
        return self._queue.requeue_dead_letters() if self._queue is not None else 0

    def drain_queue(self, batch_size: int = 200, on_result: Callable[[Any], None] | None = None) -> int:
        """Process pending lines until none are left; returns how many settled.

        A transient failure raises and leaves everything pending, so a later
        call resumes. A batch that was processed but could not be saved is held
        and only its save is retried: processing it again would count its events
        into the behavioral baseline a second time. A line that cannot be
        processed at all is set aside (see :meth:`_settle_batch`), so it cannot block
        the lines behind it until the queue fills.
        """
        if self._queue is None:
            return 0
        if self.transactional_outbox and self.persist is None:
            raise ValueError("PostgreSQL durable ingest requires persistence; do not use --no-save")
        self._flush_backend()
        settled = 0
        while True:
            if self._unacked:
                self._queue.ack_many(self._unacked)
                self._unacked = []
            if self._held is not None:
                _result, held_batch, before = self._held
                try:
                    settled += self._save_held(on_result)
                except Exception as exc:
                    if _is_transient(exc) or self._unacked:
                        raise
                    # The save now fails for a reason retrying cannot cure, so
                    # find the line responsible the same way as below.
                    self._held = None
                    self._restore_baseline(before)
                    settled += self._settle_batch(held_batch, on_result)
                continue
            batch = self._queue.pull(limit=batch_size)
            if not batch:
                return settled
            # Only ingest messages carry lines. Anything else (an archive marker
            # from a queue written before the journal stopped pushing them) would
            # otherwise stay pending for ever and count against the queue limit.
            other = [message["offset"] for message in batch if message["topic"] != "ingest"]
            if other:
                self._queue.ack_many(other)
            batch = [message for message in batch if message["topic"] == "ingest"]
            if batch:
                settled += self._settle_batch(batch, on_result)

    def _settle_batch(self, batch: list[dict[str, Any]], on_result: Callable[[Any], None] | None) -> int:
        """Settle a batch; set aside its failing lines only if the store took the rest.

        A line is to blame only when lines beside it were saved. If none were,
        the store itself is failing (corrupt, unmigrated, read-only after a
        failover) and setting lines aside would empty the queue into dead
        letters, so the batch is left pending and the error raised for a retry.
        A batch holding nothing but failing lines therefore waits until a line
        that works arrives with them.
        """
        suspects: list[tuple[int, Exception]] = []
        settled = self._settle(batch, on_result, suspects)
        if suspects and not settled:
            raise suspects[-1][1]
        for offset, exc in suspects:
            self._set_aside(offset, exc)
        return settled

    def _settle(
        self, batch: list[dict[str, Any]], on_result: Callable[[Any], None] | None, suspects: list[tuple[int, Exception]]
    ) -> int:
        """Process and save one batch, bisecting it around lines that fail."""
        before = self._baseline_snapshot()
        try:
            lines = [str(message["payload"]["line"]) for message in batch]
            try:
                result = self._process(lines)
            except Exception:
                # Nothing is held, so a retry processes the batch again.
                self._restore_baseline(before)
                raise
            self._held = (result, batch, before)
            return self._save_held(on_result)
        except Exception as exc:
            # A processed batch stays held, so only its save is retried; a saved
            # one is only acknowledged. Neither may be processed again.
            if _is_transient(exc) or self._unacked:
                raise
            if self._held is not None:
                self._held = None
                self._restore_baseline(before)
            if len(batch) == 1:
                suspects.append((batch[0]["offset"], exc))
                return 0
            middle = len(batch) // 2
            return self._settle(batch[:middle], on_result, suspects) + self._settle(batch[middle:], on_result, suspects)

    # Two parts of the pipeline learn from every batch: the behavioral baseline
    # and the suppression engine's repeat counter. A batch processed again, on a
    # retry or in halves while a bad line is isolated, would be learned twice or
    # more without these: inflated counts mute ``rare_action``, trip ``burst``,
    # and auto-suppress real findings as repeats.

    def _baseline_snapshot(self) -> dict[str, Any] | None:
        snapshot: dict[str, Any] = {}
        state = getattr(getattr(self.pipeline, "anomaly_detector", None), "state", None)
        if state is not None:
            snapshot["baseline"] = state.to_dict()
        seen = getattr(getattr(self.pipeline, "suppression_engine", None), "_seen", None)
        if seen is not None:
            snapshot["seen"] = copy.deepcopy(seen)
        return snapshot or None

    def _restore_baseline(self, snapshot: dict[str, Any] | None) -> None:
        if snapshot is None:
            return
        if "baseline" in snapshot:
            from .anomaly import BaselineState

            self.pipeline.anomaly_detector.state = BaselineState.from_dict(snapshot["baseline"])  # type: ignore[union-attr]
        if "seen" in snapshot:
            self.pipeline.suppression_engine._seen = copy.deepcopy(snapshot["seen"])  # type: ignore[union-attr]

    def _save_held(self, on_result: Callable[[Any], None] | None) -> int:
        assert self._queue is not None and self._held is not None
        result, batch, _before = self._held
        self._persist(result)
        self._held = None
        self._unacked = [message["offset"] for message in batch]
        # Everything that needs the result happens before the ack, which is the
        # one step after the save that can fail: a retry then only acknowledges.
        self._send_to_backend(result.events)
        if on_result is not None:
            try:
                on_result(result)
            except Exception:  # reporting must never make a saved batch look failed
                _LOG.exception("could not report a saved batch of %d line(s)", len(batch))
        self._queue.ack_many(self._unacked)
        self._unacked = []
        return len(batch)

    def _set_aside(self, offset: int, exc: Exception) -> None:
        assert self._queue is not None
        self._queue.dead_letter(offset)
        # Any sender can craft such lines, so the warning is rate-limited, and it
        # names only the error type because the text can quote the line.
        now = time.monotonic()
        if now - self._last_set_aside_warning >= SET_ASIDE_WARNING_SECONDS:
            self._last_set_aside_warning = now
            _LOG.warning(
                "set aside a queued line that cannot be processed (%s); %d set aside in total. "
                "Requeue with `autosiem distributed --requeue-dead-letters` once fixed",
                type(exc).__name__,
                self._queue.dead_letters(),
            )

    def _send_to_backend(self, events: list[Any]) -> None:
        if self._backend is None or not self.config.alternate_backend:
            return
        self._backend_backlog.extend(events)
        excess = len(self._backend_backlog) - self.config.queue_max_pending
        if excess > 0:
            del self._backend_backlog[:excess]
            self.backend_dropped += excess
        self._flush_backend()

    def _flush_backend(self) -> None:
        """Deliver the backend copy. An outage here never stops detection.

        The primary store already has these events, so its queue messages are
        acknowledged. Retrying the whole batch would save them again, and waiting
        out a silent cluster on every batch would stall the primary store.
        """
        if self._backend is None or not self._backend_backlog or time.monotonic() < self._backend_retry_at:
            return
        try:
            self._backend.store_events(self._backend_backlog)
        except BackendError as exc:
            self.backend_error = str(exc)
            self._backend_retry_at = time.monotonic() + BACKEND_RETRY_SECONDS
            _LOG.warning(
                "event backend unavailable (%s); holding %d event(s), the primary store has them",
                type(exc).__name__,
                len(self._backend_backlog),
            )
        else:
            self._backend_backlog = []
            self.backend_error = None

    def process_lines(self, lines: list[str]) -> dict[str, Any]:
        """Run the pipeline and return count summary. See :meth:`run`."""
        result = self.run(lines)
        return {
            "events": len(result.events),
            "findings": len(result.findings),
            "incidents": len(result.incidents),
            "suppressed": len(result.suppressed),
        }

    def run(self, lines: list[str]) -> Any:
        """Archive, enqueue, process ONCE, store, ack; return the PipelineResult.

        A supplied persistence callback commits the full result before queue
        acknowledgement. PostgreSQL requires it and uses its transactional
        outbox instead of a direct alternate-backend write. Library callers
        without the callback retain responsibility for saving returned results.
        """
        from .pipeline import PipelineResult

        if not lines:
            return PipelineResult()

        if self.transactional_outbox and self.persist is None:
            raise ValueError("PostgreSQL durable ingest requires persistence; do not use --no-save")

        # Archive raw events first (for durability)
        self._archive_lines(lines)

        # Enqueue to durable queue (for backpressure). Offsets are remembered so
        # exactly these messages are acked after processing: the ArchiveWriter
        # also pushes marker messages, so acking "the first N pending" acked the
        # archive markers instead and left every ingest message pending, to be
        # replayed and reprocessed on the next start.
        enqueued: list[int] = []
        if self._queue is not None:
            for i, line in enumerate(lines):
                try:
                    enqueued.append(
                        self._queue.push(
                            topic="ingest",
                            payload={"line": line, "seq": i},
                            max_pending=self.config.queue_max_pending,
                        )
                    )
                except QueueFullError:
                    if self.persist is not None:
                        # Nothing is acknowledged or processed. Already queued
                        # input remains recoverable; the caller must retry the
                        # rejected batch after draining the queue.
                        raise
                    # Backpressure hit. Only the prefix reached the queue, so
                    # only the prefix is durable; processing the whole batch
                    # would report the un-enqueued suffix as handled and lose
                    # it on a retry. Narrow `lines` to what actually enqueued.
                    lines = lines[:len(enqueued)]
                    break

        result = self._process(lines)

        self._persist(result)

        # Store to alternate backend if configured
        if self._backend and self.config.alternate_backend:
            self._backend.store_events(result.events)

        # Ack exactly the messages this pass enqueued.
        if self._queue is not None:
            for offset in enqueued:
                self._queue.ack(offset)

        return result

    def _archive_lines(self, lines: list[str]) -> None:
        if self._archive is None:
            return
        import json as _json

        records = []
        for line in lines:
            try:
                raw = _json.loads(line) if line.strip().startswith("{") else {"raw": line}
            except Exception:
                raw = {"raw": line}
            records.append(raw)
        # One locked write per burst: the listener archives in its receive thread.
        self._archive.write_many(records)

    def _persist(self, result: Any) -> None:
        if self.persist is not None:
            self.persist(result)
        elif self.transactional_outbox:
            raise ValueError("PostgreSQL distributed ingest requires result persistence before acknowledgement")

    def _process(self, lines: list[str]) -> Any:
        """The single processing pass: injected pipeline, workers, or default."""
        if self.pipeline is not None:
            return self.pipeline.process_lines(lines)
        if self._workers:
            return self._workers.process_lines(lines)
        from .pipeline import AutoSIEMPipeline

        return AutoSIEMPipeline(self.rules).process_lines(lines)

    def replay_from_queue(self, batch_size: int = 200) -> dict[str, Any]:
        """Process everything pending in the durable queue, for ``distributed --replay``.

        This is :meth:`drain_queue` with totals: it used to replay at most 1000
        lines per run, and a backend failure after the save left the lines
        pending, so the next run saved their events and findings again. Now
        every line is acknowledged once saved and an unreachable backend only
        costs its copy, reported as ``backend_undelivered``. A failure that
        stops the replay raises; whatever was settled before it stays settled.
        """
        totals = {"events": 0, "findings": 0, "incidents": 0, "replayed": 0, "set_aside": 0}
        if self._queue is None:
            return totals | {"backend_undelivered": 0}

        def tally(result: Any) -> None:
            totals["events"] += len(result.events)
            totals["findings"] += len(result.findings)
            totals["incidents"] += len(result.incidents)

        set_aside_before = self._queue.dead_letters()
        totals["replayed"] = self.drain_queue(batch_size, on_result=tally)
        totals["set_aside"] = self._queue.dead_letters() - set_aside_before
        totals["backend_undelivered"] = self.backend_backlog + self.backend_dropped
        return totals

    @property
    def stats(self) -> dict[str, Any]:
        """Return current queue and archive statistics."""
        stats: dict[str, Any] = {}

        if self._queue is not None:
            stats["queue_pending"] = self._queue.pending()
            stats["queue_checkpoint"] = self._queue.checkpoint()
            stats["queue_total"] = len(self._queue)
            stats["queue_dead_letters"] = self._queue.dead_letters()

        if self._archive is not None:
            stats["archive_sequence"] = self._archive.journal.sequence()

        return stats

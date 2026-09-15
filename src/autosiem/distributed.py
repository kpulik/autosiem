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

import os
from dataclasses import dataclass
from typing import Any, Callable

from .archive import ArchiveWriter, JournalFile
from .backends import ClickHouseBackend, EventBackend, OpenSearchBackend, SqliteBackend, make_backend
from .bus import DurableQueue, QueueFullError
from .workers import ParserWorkerPool


@dataclass
class DistributedConfig:
    """Configuration for distributed pipeline mode."""

    # Queue settings
    queue_path: str | None = None
    queue_max_pending: int = 10000

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
        queue_max_pending=int(os.environ.get("AUTOSIEM_QUEUE_MAX_PENDING", "10000")),
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
        if self._archive is not None:
            import json as _json
            for line in lines:
                try:
                    raw = _json.loads(line) if line.strip().startswith("{") else {"raw": line}
                except Exception:
                    raw = {"raw": line}
                self._archive.write(raw)

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
                    # Backpressure hit - process what we have queued
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

    def replay_from_queue(self) -> dict[str, Any]:
        """Replay unacked messages from the durable queue.

        Called on startup to recover from crashes.
        """
        if self._queue is None:
            return {"events": 0, "findings": 0, "incidents": 0, "replayed": 0}

        pending = self._queue.pull(limit=1000)
        # Only "ingest" messages carry raw lines. The ArchiveWriter pushes
        # markers whose payload is a bare sequence int, and calling .get() on
        # those raised AttributeError and aborted the whole replay.
        ingest = [
            msg for msg in pending
            if msg.get("topic") == "ingest" and isinstance(msg.get("payload"), dict)
        ]
        lines = [str(msg["payload"]["line"]) for msg in ingest if msg["payload"].get("line")]
        if not lines:
            # Still ack any markers so they do not accumulate forever.
            for msg in pending:
                self._queue.ack(msg["offset"])
            return {"events": 0, "findings": 0, "incidents": 0, "replayed": 0}

        result = self._process(lines)

        self._persist(result)
        if self._backend and self.config.alternate_backend:
            self._backend.store_events(result.events)

        # Ack all replayed messages
        for msg in pending:
            self._queue.ack(msg["offset"])

        return {
            "events": len(result.events),
            "findings": len(result.findings),
            "incidents": len(result.incidents),
            "replayed": len(lines),
        }

    @property
    def stats(self) -> dict[str, Any]:
        """Return current queue and archive statistics."""
        stats: dict[str, Any] = {}

        if self._queue is not None:
            stats["queue_pending"] = self._queue.pending()
            stats["queue_checkpoint"] = self._queue.checkpoint()
            stats["queue_total"] = len(self._queue)

        if self._archive is not None:
            stats["archive_sequence"] = self._archive.journal.sequence()

        return stats

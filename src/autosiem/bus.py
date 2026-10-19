"""Message bus abstractions and a durable replay queue for AutoSIEM.

Provides an in-memory pub/sub bus (the default transport), an optional Kafka
integration that works without ``kafka-python`` installed, and a SQLite-backed
durable FIFO used for backpressure and replay after restart.

Only the Python standard library is required at runtime.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from .private_files import create_private


class QueueFullError(Exception):
    """Raised when a durable queue exceeds its configured ``max_pending``."""


class Bus:
    """Interface for an event bus."""

    def publish(self, topic: str, message: object) -> None:
        raise NotImplementedError

    def subscribe(self, topic: str, handler: Callable[[str, object], None]) -> None:
        raise NotImplementedError


class InMemoryBus(Bus):
    """In-memory publish/subscribe bus.

    Handlers are invoked synchronously in insertion order with ``(topic,
    message)``.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[str, object], None]]] = {}

    def publish(self, topic: str, message: object) -> None:
        for handler in list(self._subscribers.get(topic, [])):
            handler(topic, message)

    def subscribe(self, topic: str, handler: Callable[[str, object], None]) -> None:
        self._subscribers.setdefault(topic, []).append(handler)

    def subscriber_count(self, topic: str) -> int:
        return len(self._subscribers.get(topic, []))

    def topics(self) -> list[str]:
        return list(self._subscribers)


class KafkaBus(Bus):
    """Optional Kafka-backed bus (``kafka-python``).

    If ``kafka-python`` is not installed the bus is created in an
    ``available=False`` state; no error is raised at init. All methods then
    raise a helpful ``RuntimeError`` with install instructions.
    """

    _INSTALL_HINT = "kafka-python is not installed; run `pip install kafka-python` to enable KafkaBus."

    def __init__(self, bootstrap_servers: str = "localhost:9092") -> None:
        self.bootstrap_servers = bootstrap_servers
        self.available = False
        self._kafka: Any = None
        self._producers: dict[str, Any] = {}
        self._subscribers: dict[str, list[Callable[[str, object], None]]] = {}
        try:
            import kafka  # type: ignore  # optional runtime dependency
        except ImportError:
            pass
        else:
            self._kafka = kafka
            self.available = True

    def _check_available(self) -> None:
        if not self.available:
            raise RuntimeError(self._INSTALL_HINT)

    def _producer(self, topic: str) -> Any:
        if topic not in self._producers:
            self._producers[topic] = self._kafka.KafkaProducer(
                bootstrap_servers=self.bootstrap_servers
            )
        return self._producers[topic]

    def publish(self, topic: str, message: object) -> None:
        self._check_available()
        payload = json.dumps(message, default=str).encode("utf-8")
        self._producer(topic).send(topic, value=payload)
        for handler in list(self._subscribers.get(topic, [])):
            handler(topic, message)

    def subscribe(self, topic: str, handler: Callable[[str, object], None]) -> None:
        self._check_available()
        self._subscribers.setdefault(topic, []).append(handler)


class DurableQueue:
    """SQLite-backed FIFO for backpressure and durable replay.

    Rows are append-only, each with a monotonically increasing ``offset``. A
    message is ``acked`` once consumed; un-acked rows form the replay set.

    Safe to share across threads. ``cli listen`` builds the queue on the main
    thread and pushes from its syslog worker pool; a default sqlite3 connection
    refuses that, and every event was lost. One connection, one lock.
    """

    def __init__(self, path: str) -> None:
        self.path = str(path)
        if self.path != ":memory:" and not self.path.startswith("file:"):
            create_private(self.path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                offset integer primary key autoincrement,
                topic text,
                payload text,
                acked integer default 0,
                created_at text
            )
            """
        )
        self._conn.commit()

    def _insert(self, topic: str, payload: Any) -> int:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO messages (topic, payload, created_at) VALUES (?, ?, ?)",
                (topic, json.dumps(payload), created_at),
            )
            self._conn.commit()
            return int(cursor.lastrowid or 0)

    def push(self, topic: str, payload: Any, max_pending: int | None = None) -> int:
        # Check and insert under one lock, or racing threads all pass the check.
        with self._lock:
            if max_pending is not None:
                pending = self.pending()
                if pending >= max_pending:
                    raise QueueFullError(f"queue overflow: {pending} >= {max_pending} pending")
            return self._insert(topic, payload)

    @staticmethod
    def _decode(row: tuple) -> dict[str, Any]:
        offset, topic, payload, _acked, _created_at = row
        return {"offset": offset, "topic": topic, "payload": json.loads(payload)}

    def pull(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT offset, topic, payload, acked, created_at FROM messages "
                "WHERE acked = 0 ORDER BY offset ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._decode(row) for row in rows]

    def ack(self, offset: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE messages SET acked = 1 WHERE offset = ?", (offset,))
            self._conn.commit()

    def pending(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM messages WHERE acked = 0"
            ).fetchone()
        return int(row[0])

    def checkpoint(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(offset), 0) FROM messages WHERE acked = 1"
            ).fetchone()
        return int(row[0])

    def __len__(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM messages").fetchone()
        return int(row[0])

    def __bool__(self) -> bool:
        """A queue always exists, even when empty.

        Without this, ``__len__`` decides truthiness and an empty queue is
        falsy, so ``if queue:`` guards silently skip enqueueing on a fresh
        queue - which is exactly when it is empty.
        """
        return True

    def replay(self, offset: int | None = None) -> list[dict]:
        start = int(offset or 0)
        with self._lock:
            rows = self._conn.execute(
                "SELECT offset, topic, payload, acked, created_at FROM messages "
                "WHERE acked = 0 AND offset >= ? ORDER BY offset ASC",
                (start,),
            ).fetchall()
        return [self._decode(row) for row in rows]

    def compact(self, max_acked: int | None = None) -> int:
        """Delete acknowledged rows, all of them or those at or below offset
        ``max_acked``; never a pending one.

        Acks arrive out of order once several threads push, so a pending
        message can sit below the highest acked offset (``checkpoint()``).
        SQLite reuses the freed pages; the file itself does not shrink
        without ``VACUUM``.
        """
        ceiling = -1 if max_acked is None else max_acked
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM messages WHERE acked = 1 AND (? < 0 OR offset <= ?)", (ceiling, ceiling)
            )
            self._conn.commit()
            return int(cursor.rowcount)
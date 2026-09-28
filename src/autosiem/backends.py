"""Alternate event storage backends.

``EventBackend`` defines the minimal store/list contract used by the workers.
``ClickHouseBackend`` and ``OpenSearchBackend`` talk HTTP through stdlib
``urllib``; ``SqliteBackend`` reuses ``AutoSIEMStorage`` via a local pipeline
round-trip. All network failures surface as ``BackendError`` so callers can
handle them uniformly.
"""

from __future__ import annotations

import http.client
import json
import os
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .net import open_url
from .pipeline import AutoSIEMPipeline
from .rules import load_rules
from .storage import AutoSIEMStorage

# backends.py lives at <repo>/src/autosiem/backends.py, so parents[2] is the
# repo root that contains the default `rules/` directory.
DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules"


#: Socket timeout for every backend call. urlopen's default is none, so a
#: cluster that accepts and never answers hung ingest for ever.
HTTP_TIMEOUT_SECONDS = 30.0


class BackendError(RuntimeError):
    """Raised when a backend cannot store or list events."""


def _http_text(url: str, service: str, body: str | None = None) -> str:
    """GET ``url`` (POST ``body`` when given) and return the decoded reply.

    Every way a cluster or its URL can fail becomes ``BackendError``: OSError
    (refused, reset, and a read timeout, which is a TimeoutError rather than a
    URLError), http.client.HTTPException (a truncated or non-HTTP reply, a bad
    port), and ValueError (a malformed URL, a body that is not UTF-8, a redirect
    off HTTPS). The request is built inside the guard so a bad URL is covered too.
    """
    try:
        request = urllib.request.Request(
            url,
            data=None if body is None else body.encode("utf-8"),
            method="GET" if body is None else "POST",
        )
        # The configured URL is the operator's and may be plaintext inside a trusted
        # network (both clusters default to http://localhost); allow_loopback
        # only governs redirect hops. See SEC-017 in docs/security-review.md.
        with open_url(request, timeout=HTTP_TIMEOUT_SECONDS, allow_loopback=True) as response:
            return response.read().decode("utf-8")
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise BackendError(f"{service} request failed: {exc}") from exc


class EventBackend:
    """Interface for event storage backends."""

    def store_events(self, events: list[Any]) -> None:
        raise NotImplementedError

    def list_events(self, limit: int = 100, query: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError


class ClickHouseBackend(EventBackend):
    """Store events in ClickHouse via the HTTP JSONEachRow interface."""

    def __init__(self, table: str = "events", url: str = "http://localhost:8123") -> None:
        self.table = table
        self.url = url.rstrip("/")

    def store_events(self, events: list[Any]) -> None:
        if not events:
            return
        body = "\n".join(json.dumps(event.to_dict()) for event in events) + "\n"
        query = f"INSERT INTO {self.table} FORMAT JSONEachRow"
        self._post(self._query_url(query), body)

    def list_events(self, limit: int = 100, query: str | None = None) -> list[dict[str, Any]]:
        query_text = query or f"SELECT * FROM {self.table} LIMIT {limit}"
        response = self._get(self._query_url(f"{query_text} FORMAT JSONEachRow"))
        return [json.loads(line) for line in response.splitlines() if line.strip()]

    def _query_url(self, query: str) -> str:
        return f"{self.url}/?{urllib.parse.urlencode({'query': query})}"

    def _post(self, url: str, body: str) -> str:
        return _http_text(url, "ClickHouse", body)

    def _get(self, url: str) -> str:
        return _http_text(url, "ClickHouse")


class OpenSearchBackend(EventBackend):
    """Store events in OpenSearch via the bulk and search APIs."""

    def __init__(self, url: str = "http://localhost:9200", index: str = "events") -> None:
        self.url = url.rstrip("/")
        self.index = index

    def store_events(self, events: list[Any]) -> None:
        if not events:
            return
        lines: list[str] = []
        for event in events:
            lines.append(json.dumps({"index": {"_index": self.index}}))
            lines.append(json.dumps(event.to_dict()))
        body = "\n".join(lines) + "\n"
        self._post(f"{self.url}/{self.index}/_bulk", body)

    def list_events(self, limit: int = 100, query: str | None = None) -> list[dict[str, Any]]:
        url = f"{self.url}/{self.index}/_search?size={limit}"
        if query:
            url += f"&q={urllib.parse.quote(query)}"
        response = self._get(url)
        data = json.loads(response)
        return [hit.get("_source") for hit in data.get("hits", {}).get("hits", [])]

    def _post(self, url: str, body: str) -> str:
        return _http_text(url, "OpenSearch", body)

    def _get(self, url: str) -> str:
        return _http_text(url, "OpenSearch")


class SqliteBackend(EventBackend):
    """Store events in a local SQLite database via ``AutoSIEMStorage``."""

    def __init__(self, db_path: str | Path | None = None, rules: list[Any] | None = None) -> None:
        if db_path is None:
            # A bare ":memory:" db would be recreated on every connection, so use
            # a temp file instead; callers can pass an explicit db_path.
            fd, tmp = tempfile.mkstemp(prefix="autosiem_", suffix=".db")
            os.close(fd)
            db_path = tmp
        self.db_path = Path(db_path)
        self.rules = rules if rules is not None else load_rules(DEFAULT_RULES)
        self.storage = AutoSIEMStorage(self.db_path)

    def store_events(self, events: list[Any]) -> None:
        if not events:
            return
        # Round-trip each normalized event through its JSON form so the pipeline
        # (and therefore AutoSIEMStorage) can persist it with the same event_id.
        lines = [json.dumps(event.to_dict()) for event in events]
        result = AutoSIEMPipeline(self.rules).process_lines(lines)
        self.storage.save_pipeline_result(result)

    def list_events(self, limit: int = 100, query: str | None = None) -> list[dict[str, Any]]:
        return self.storage.list_events(limit=limit)


_BACKENDS: dict[str, type[EventBackend]] = {
    "sqlite": SqliteBackend,
    "clickhouse": ClickHouseBackend,
    "opensearch": OpenSearchBackend,
}


def make_backend(name: str = "sqlite", **kwargs: Any) -> EventBackend:
    """Factory returning the built-in backend for ``name``."""
    try:
        backend_cls = _BACKENDS[name.lower()]
    except KeyError:
        raise ValueError(f"unknown backend: {name!r} (expected one of {sorted(_BACKENDS)})") from None
    return backend_cls(**kwargs)
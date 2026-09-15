"""Idempotent HTTP sinks for the PostgreSQL event outbox, not authorities."""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any


def event_key(tenant: str, event_id: str) -> str:
    return hashlib.sha256(json.dumps([tenant, event_id], separators=(",", ":")).encode()).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class EventProjection:
    """One explicitly configured destination with bounded, non-redirecting I/O.

    OpenSearch uses a stable document ID. ClickHouse requires the documented
    ReplacingMergeTree table and FINAL reads for logical deduplication.
    """
    def __init__(self, kind: str, url: str, name: str, token: str = "") -> None:
        parsed = urllib.parse.urlsplit(url)
        if kind not in {"opensearch", "clickhouse"}:
            raise ValueError("projection backend must be opensearch or clickhouse")
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("projection URL must have a host and no credentials, query, or fragment")
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("projection URL requires HTTPS except on loopback")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name):
            raise ValueError("projection name must be a lowercase table/index identifier")
        self.kind, self.url, self.name = kind, url.rstrip("/"), name
        self._token = token
        # Changing a target creates fresh receipts, so rebuilding cannot skip
        # records acknowledged by a different cluster, table, or index.
        self.destination = hashlib.sha256(json.dumps([kind, self.url, name]).encode()).hexdigest()
        self._opener = urllib.request.build_opener(_NoRedirect)

    def deliver(self, tenant: str, event_id: str, document: dict[str, Any]) -> None:
        key = event_key(tenant, event_id)
        if self.kind == "opensearch":
            url = f"{self.url}/{self.name}/_doc/{key}"
            body = json.dumps({"tenant_id": tenant, "event_id": event_id, "event": document}).encode()
            method = "PUT"
        else:
            query = urllib.parse.urlencode({"query": f"INSERT INTO {self.name} FORMAT JSONEachRow"})
            url = f"{self.url}/?{query}"
            body = (json.dumps({"tenant_id": tenant, "event_id": event_id, "data": json.dumps(document)}) + "\n").encode()
            method = "POST"
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(url, data=body, method=method, headers=headers)
        with self._opener.open(request, timeout=10) as response:
            # Bound the response and never copy backend error bodies into logs.
            data = response.read(65537)
            if response.status not in {200, 201} or len(data) > 65536:
                raise RuntimeError("projection delivery failed")
            if self.kind == "opensearch":
                result = json.loads(data)
                if result.get("_id") != key or result.get("result") not in {"created", "updated", "noop"}:
                    raise RuntimeError("projection acknowledgement is invalid")
                if result.get("_shards", {}).get("failed", 0):
                    raise RuntimeError("projection reported failed shards")
            elif data.strip():
                # ClickHouse can report a query error in a body after sending
                # HTTP 200 headers. A successful INSERT has an empty body.
                raise RuntimeError("ClickHouse projection did not acknowledge the insert")


def projection_from_env() -> EventProjection:
    kind = os.environ.get("AUTOSIEM_BACKEND", "")
    name_var = "AUTOSIEM_BACKEND_INDEX" if kind == "opensearch" else "AUTOSIEM_BACKEND_TABLE"
    return EventProjection(kind, os.environ.get("AUTOSIEM_BACKEND_URL", ""),
                           os.environ.get(name_var, "events"),
                           os.environ.get("AUTOSIEM_PROJECTION_TOKEN", ""))

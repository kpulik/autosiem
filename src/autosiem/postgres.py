"""Optional PostgreSQL authority with explicit migrations and an event outbox.

No driver import or database connection occurs in the default SQLite profile.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from importlib.resources import files
from typing import Any, Callable, Iterator, Sequence
from uuid import uuid4

from .storage import DEFAULT_TENANT, RelationalStorage, StorageConflict, _json

MIGRATION_LOCK = 0x415349454D01
AUDIT_LOCK = 0x415349454D02


def _driver() -> Any:
    try:
        return importlib.import_module("psycopg")
    except ImportError:
        raise RuntimeError("PostgreSQL requires the optional autosiem[postgres] extra") from None


def dsn_from_env() -> str:
    dsn = os.environ.get("AUTOSIEM_POSTGRES_DSN", "").strip()
    if not dsn:
        raise ValueError("AUTOSIEM_POSTGRES_DSN is required for PostgreSQL storage")
    return dsn


@contextmanager
def _connection(dsn: str) -> Iterator[Any]:
    driver = _driver()
    try:
        settings = driver.conninfo.conninfo_to_dict(dsn)
    except driver.Error:
        raise ValueError("Invalid PostgreSQL connection configuration") from None
    hosts = settings.get("host", os.environ.get("PGHOST", "")).split(",")
    addresses = settings.get("hostaddr", os.environ.get("PGHOSTADDR", "")).split(",")
    local_hosts = all(host in {"", "localhost", "127.0.0.1", "::1"} or host.startswith("/") for host in hosts)
    local_addresses = all(address in {"", "127.0.0.1", "::1"} for address in addresses)
    # A service file can hide a remote endpoint; require verified TLS unless
    # the connection is explicitly local and does not use a service definition.
    remote = not (local_hosts and local_addresses) or bool(settings.get("service") or os.environ.get("PGSERVICE"))
    if remote and settings.get("sslmode", os.environ.get("PGSSLMODE")) != "verify-full":
        raise ValueError("Remote PostgreSQL connections require sslmode=verify-full")
    try:
        # A SQL_ASCII database hands text columns back as bytes unless the
        # client encoding is pinned, which turned every checksum and JSON
        # column into an unreadable value and failed migration validation as
        # if the packaged migrations had been edited.
        raw = driver.connect(dsn, connect_timeout=10, row_factory=driver.rows.dict_row,
                             client_encoding="utf8")
    except driver.Error:
        # libpq errors may include credentials or connection-string details.
        raise RuntimeError("PostgreSQL connection failed; check database configuration") from None
    with raw:
        raw.execute("set local search_path = autosiem, pg_catalog")
        raw.execute("set local lock_timeout = '10s'")
        raw.execute("set local statement_timeout = '30s'")
        yield raw


def _migrations() -> list[tuple[int, str, str]]:
    migrations = []
    for path in sorted(files("autosiem").joinpath("migrations").iterdir(), key=lambda p: p.name):
        if re.fullmatch(r"[0-9]{3}_[a-z_]+\.sql", path.name):
            sql = path.read_text(encoding="utf-8")
            migrations.append((int(path.name[:3]), hashlib.sha256(sql.encode()).hexdigest(), sql))
    if [version for version, _, _ in migrations] != list(range(1, len(migrations) + 1)) or not migrations:
        raise RuntimeError("Invalid or missing packaged PostgreSQL migrations")
    return migrations


def _validate_history(rows: list[Any], migrations: list[tuple[int, str, str]]) -> int:
    if len(rows) > len(migrations):
        raise RuntimeError("PostgreSQL schema is newer than this application")
    for row, (version, checksum, _) in zip(rows, migrations):
        if row["version"] != version or row["checksum"] != checksum:
            raise RuntimeError("PostgreSQL migration history mismatch; do not edit applied migrations")
    return len(rows)


def migrate(dsn: str) -> list[int]:
    """Apply packaged forward migrations atomically under a database lock.

    Use a dedicated migration role, not the runtime role. No down migrations
    or implicit startup DDL are provided.
    """
    migrations = _migrations()
    with _connection(dsn) as conn:
        conn.execute("select pg_advisory_xact_lock(%s)", (MIGRATION_LOCK,))
        conn.execute("create schema if not exists autosiem")
        conn.execute("create table if not exists autosiem.schema_migrations "
                     "(version integer primary key, checksum text not null, "
                     "applied_at timestamptz not null default clock_timestamp())")
        applied = _validate_history(conn.execute(
            "select version, checksum from autosiem.schema_migrations order by version"
        ).fetchall(), migrations)
        pending = migrations[applied:]
        for version, checksum, sql in pending:
            conn.execute(sql)
            conn.execute("insert into autosiem.schema_migrations(version,checksum) values(%s,%s)",
                         (version, checksum))
    return [version for version, _, _ in pending]


# Only bind markers are adapted. SQL dialect differences stay in explicit
# backend methods. Quoted literals/identifiers and comments are left intact.
_SQL_TOKENS = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|--[^\n]*|/\*.*?\*/|\?", re.S)


def _qmark_sql(sql: str) -> str:
    return _SQL_TOKENS.sub(lambda m: "%s" if m.group() == "?" else m.group(), sql.replace("%", "%%"))


class _Connection:
    def __init__(self, raw: Any) -> None:
        self.raw = raw

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        return self.raw.execute(_qmark_sql(sql), tuple(params))


class PostgresStorage(RelationalStorage):
    """Transactional shared control plane; querying events remains authoritative.

    IDs are unique within a tenant. Unscoped single-record operations reject
    ambiguity. Row locks prevent lost triage updates and conflicting decisions.
    """
    _row_lock = " for update"
    _terminal_decisions = True

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._baseline_revisions: ContextVar[dict[str, int]] = ContextVar("baseline_revisions", default={})
        migrations = _migrations()
        with _connection(dsn) as conn:
            exists = conn.execute("select to_regclass('autosiem.schema_migrations') as name").fetchone()
            if not exists["name"]:
                raise RuntimeError("PostgreSQL schema is missing; run autosiem migrate explicitly")
            applied = _validate_history(conn.execute(
                "select version,checksum from schema_migrations order by version"
            ).fetchall(), migrations)
            if applied != len(migrations):
                raise RuntimeError("PostgreSQL schema is behind; run autosiem migrate explicitly")

    @contextmanager
    def connect(self) -> Iterator[Any]:
        with _connection(self._dsn) as raw:
            yield _Connection(raw)

    def _insert(self, conn: Any, table: str, columns: str, values: tuple[Any, ...]) -> bool:
        names = columns.split(",")
        quoted = ",".join(f'"{name}"' for name in names)
        binds = ",".join("?" for _ in values)
        cursor = conn.execute(f"insert into {table}({quoted}) values({binds}) on conflict do nothing", values)
        if cursor.rowcount:
            return True
        if table == "events":
            record = dict(zip(names, values))
            existing = conn.execute("select data from events where tenant_id = ? and event_id = ?",
                                    (record["tenant_id"], record["event_id"])).fetchone()
            if not existing or existing["data"] != record["data"]:
                raise StorageConflict("event_id already exists with different content in this tenant")
        # Re-saving a result must never reset analyst triage or approval state.
        return False

    def _event_saved(self, conn: Any, tenant: str, event_id: str, data: str) -> None:
        conn.execute("insert into event_outbox(tenant_id,event_id,data) values(?,?,?) "
                     "on conflict(tenant_id,event_id) do nothing", (tenant, event_id, data))

    def audit(self, conn: Any, actor: str, action: str, target: str | None, details: dict[str, Any]) -> None:
        # Held through COMMIT: another writer cannot hash an uncommitted tail.
        conn.execute("select pg_advisory_xact_lock(?)", (AUDIT_LOCK,))
        super().audit(conn, actor, action, target, details)

    def _add_comment(self, conn: Any, incident_id: str, actor: str, body: str,
                     tenant_id: str | None = None) -> dict[str, Any]:
        comment = {"comment_id": str(uuid4()), "incident_id": incident_id, "actor": actor,
                   "created_at": datetime.now(timezone.utc).isoformat(), "body": body,
                   "tenant_id": tenant_id or DEFAULT_TENANT}
        conn.execute("insert into incident_comments(comment_id,incident_id,actor,created_at,body,tenant_id) "
                     "values(?,?,?,?,?,?)", tuple(comment.values()))
        return comment

    def _list_comments(self, conn: Any, incident_id: str, tenant_id: str | None = None) -> list[dict[str, Any]]:
        sql = "select * from incident_comments where incident_id = ?"
        params = [incident_id]
        if tenant_id:
            sql += " and tenant_id = ?"
            params.append(tenant_id)
        return conn.execute(sql + " order by created_at", params).fetchall()

    def source_stats(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        where = " where tenant_id = ?" if tenant_id else ""
        with self.connect() as conn:
            return conn.execute("select coalesce(data::jsonb->>'source', 'unknown') as source, "
                                "count(*) as events, min(timestamp) as first_seen, max(timestamp) as last_seen "
                                f"from events{where} group by source order by last_seen desc",
                                [tenant_id] if tenant_id else []).fetchall()

    def load_baseline(self, tenant_id: str | None = None) -> dict[str, Any] | None:
        tenant = tenant_id or DEFAULT_TENANT
        with self.connect() as conn:
            row = conn.execute("select state,revision from baselines where tenant_id = ?", (tenant,)).fetchone()
        self._baseline_revisions.set({**self._baseline_revisions.get(), tenant: row["revision"] if row else 0})
        return json.loads(row["state"]) if row else None

    def save_baseline(self, state: dict[str, Any], tenant_id: str | None = None) -> None:
        tenant = tenant_id or DEFAULT_TENANT
        expected = self._baseline_revisions.get().get(tenant, 0)
        with self.connect() as conn:
            if expected == 0:
                cursor = conn.execute("insert into baselines(tenant_id,state,updated_at) values(?,?,?) "
                                      "on conflict do nothing returning revision",
                                      (tenant, _json(state), datetime.now(timezone.utc).isoformat()))
            else:
                cursor = conn.execute("update baselines set state = ?, updated_at = ?, revision = revision + 1 "
                                      "where tenant_id = ? and revision = ? returning revision",
                                      (_json(state), datetime.now(timezone.utc).isoformat(), tenant, expected))
            row = cursor.fetchone()
            if row is None:
                raise ValueError("baseline changed concurrently; reload before saving")
        self._baseline_revisions.set({**self._baseline_revisions.get(), tenant: row["revision"]})

    def outbox_stats(self, destination: str, tenant_id: str | None = None) -> dict[str, Any]:
        where = " and o.tenant_id = ?" if tenant_id else ""
        with self.connect() as conn:
            row = conn.execute(
                "select count(*) as pending, coalesce(extract(epoch from "
                "(clock_timestamp() - min(o.created_at))),0) as oldest_pending_seconds "
                "from event_outbox o where not exists (select 1 from projection_receipts r "
                "where r.outbox_id = o.outbox_id and r.destination = ?)" + where,
                [destination, tenant_id] if tenant_id else [destination],
            ).fetchone()
        return {"pending": row["pending"], "oldest_pending_seconds": float(row["oldest_pending_seconds"])}

    def drain_outbox(self, destination: str, deliver: Callable[[str, str, dict[str, Any]], None],
                     limit: int = 100) -> dict[str, int]:
        """Deliver a bounded batch with at-least-once, idempotent semantics.

        One record is locked per transaction. SKIP LOCKED lets workers progress
        independently. If delivery or COMMIT fails, no receipt is recorded and
        the record is retried. The sink must use a stable tenant/event key.
        """
        if not destination or not 1 <= limit <= 1000:
            raise ValueError("destination and a limit between 1 and 1000 are required")
        delivered = 0
        for _ in range(limit):
            with self.connect() as conn:
                row = conn.execute(
                    "select o.* from event_outbox o where not exists "
                    "(select 1 from projection_receipts r where r.outbox_id = o.outbox_id "
                    "and r.destination = ?) order by o.outbox_id limit 1 for update of o skip locked",
                    (destination,),
                ).fetchone()
                if row is None:
                    break
                deliver(row["tenant_id"], row["event_id"], json.loads(row["data"]))
                conn.execute("insert into projection_receipts(destination,outbox_id) values(?,?) "
                             "on conflict do nothing", (destination, row["outbox_id"]))
            delivered += 1
        return {"delivered": delivered}

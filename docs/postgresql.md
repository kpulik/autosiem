# PostgreSQL control plane and event outbox

This is an opt-in storage implementation, not an HA deployment certification.
SQLite remains the dependency-free default. No automatic migration or data
transfer from an existing SQLite database occurs.

## Enable on a new database

1. Install `python -m pip install '.[api,postgres]'`.
2. Provision a dedicated PostgreSQL database and migration role. Supply its
   connection string through `AUTOSIEM_POSTGRES_DSN` using a secret manager or
   protected process environment, never a CLI argument or committed file.
   Remote connections require `sslmode=verify-full` and a trusted CA; local
   Unix sockets and loopback connections may use local authentication.
3. Review the packaged SQL under `src/autosiem/migrations/`. Back up an existing
   target before changing it. Explicitly run `python -m autosiem.cli migrate`
   with the migration role. Applied checksums are verified; editing applied
   migrations, missing versions, and newer schemas are rejected. Failed
   migrations roll back together. There are no down migrations.
4. Switch the DSN to a restricted runtime role and set `AUTOSIEM_STORAGE=postgres`.
   Run the normal CLI or API. Startup checks schema history but performs no
   DDL. Bad configuration fails rather than silently falling back to SQLite.

`AUTOSIEM_DB` and CLI `--db` still locate local caches, connector state, and
related files. They are not PostgreSQL connection strings. PostgreSQL does not
create a SQLite authority at that path. Supply an explicit temporary `--db`
path for demos if local caches must also stay outside the repository.

Use separate migration and runtime credentials. The runtime role must not be
an object owner, superuser, or have schema CREATE privileges. Grant USAGE on
schema `autosiem`, SELECT on its tables and schema history, INSERT on data
tables, sequence USAGE, and UPDATE only for incidents, proposals, rule state,
and baselines. Suppression management additionally needs DELETE on suppressions.
The projector needs SELECT on the outbox/receipts, INSERT on receipts, and
UPDATE on at least the outbox ID column for row locking. Immutability triggers
reject actual event, audit, and outbox updates/deletes. Do not grant runtime
TRUNCATE, trigger-management, or migration-history mutation privileges.
These are database privileges for trusted application services, not substitutes
for API tenant authorization. PostgreSQL RLS is not implemented.

## What commits together

Events, findings, incidents, investigations, approval proposals, AI case notes,
audit entries, and event-outbox records commit in one result transaction.
Failure rolls back the whole transaction. Tenant IDs participate in PostgreSQL
primary and foreign keys. Incident bundles scope their related records to the
incident's tenant, even if another tenant uses the same identifiers.

Repeated saves preserve analyst triage and proposal decisions. Conflicting
content for the same `(tenant_id, event_id)` is rejected. Proposal decisions
are terminal in PostgreSQL: repeating the same decision is idempotent; a
competing decision conflicts. The API returns HTTP 409. Approval does not
change `approval_required` or make a high-risk action executable.

Triage writes lock the incident row before reading it, so updates to different
fields do not overwrite each other. Audit appends use a transaction-scoped
advisory lock for a single ordered hash chain. This is tamper-evident, not an
externally anchored or DBA-proof log. Database lock/statement timeouts fail
the operation instead of allowing indefinite waits. Failed transactions must
be retried by the caller; automatic deadlock retries are not provided.

## Deliver or rebuild an event projection

Configure `AUTOSIEM_BACKEND=opensearch` or `clickhouse`,
`AUTOSIEM_BACKEND_URL`, and `AUTOSIEM_BACKEND_INDEX` or
`AUTOSIEM_BACKEND_TABLE` (default `events`). Set `AUTOSIEM_PROJECTION_TOKEN`
only if the destination supports bearer authentication. HTTPS is required
outside loopback; redirects and credentials embedded in URLs are rejected.
No request is made until delivery is explicitly run.

```bash
python -m autosiem.cli outbox
python -m autosiem.cli outbox --deliver --limit 100
```

Both forms print one JSON document with `pending` and
`oldest_pending_seconds`; `--deliver` adds the committed `delivered` count and
reports the backlog left after that pass, so the output stays pipeable.

Run bounded delivery under a process supervisor or scheduler that retries
nonzero exits with backoff and alerts on persistent failure. This repository
does not install or start that supervisor. One worker transaction locks one
record, delivers it, and records a destination-specific receipt only after a
valid acknowledgement. Other workers use `SKIP LOCKED`. Delivery is at least
once: a crash after a sink write but before receipt commit replays the write.
A failing record stays pending and can block that worker's next batch; repair
the destination or offending payload/configuration rather than discarding it.

OpenSearch uses a deterministic SHA-256 document ID derived from tenant and
event ID. Replaying overwrites the same document, not a new document. Documents
contain `tenant_id`, `event_id`, and the normalized document under `event`.
Create appropriate index mappings and retention policy before production use.

ClickHouse requires this projection-specific table shape:

```sql
CREATE TABLE events (
    tenant_id String,
    event_id String,
    data String
) ENGINE = ReplacingMergeTree
ORDER BY (tenant_id, event_id);
```

Read it with `SELECT ... FROM events FINAL WHERE tenant_id = ...` for logical
deduplication before background merges. Physical duplicate rows can exist;
this is not exactly-once physical ingestion. See the
[ClickHouse engine contract](https://clickhouse.com/docs/reference/engines/table-engines/mergetree-family/replacingmergetree).
Do not reuse a table created for
the legacy event-only backend without checking its schema and engine.

Changing the destination URL, index, or table creates a separate receipt set
and rebuilds from retained outbox records. To rebuild a lost index, use a new
index name; do not delete receipts for a live target. Outbox data is retained
indefinitely in this initial implementation; plan disk capacity and backups.
Event search in the AutoSIEM UI still uses PostgreSQL as the authoritative
source. The external projections do not replace API authorization or drive
action execution.

With a configured sink, `/metrics` exposes `autosiem_outbox_pending` and
`autosiem_outbox_oldest_pending_seconds`, scoped to the requesting tenant.
The CLI reports the same backlog across tenants. Alert on sustained backlog
growth and age; zero pending only describes that configured destination.

## Recovery and remaining deployment gates

The durable CLI ingest/listener/replay path persists the full result before
acknowledging queued input. PostgreSQL does not directly dual-write the old
alternate backend. A persistence failure leaves input pending. Queue overflow
rejects the batch with already-enqueued messages retained for recovery.

Source retries are distinct from outbox retries. Sources without stable event
IDs generate new IDs when reparsed, and findings/incidents may also get new
IDs on reprocessing. This is not end-to-end exactly-once ingestion. Connector
cursors, RBAC files, queues, and caches are still local; do not run concurrent
collectors against the same source or independently mutate replicated RBAC
files. Use one ingestion owner per tenant. Baseline writes use optimistic
revisions to reject stale overwrites, but a conflict currently logs a warning
and skips that baseline update; baseline training is not atomic with result
persistence. Concurrent case-management writers and outbox workers are tested,
not unrestricted multi-writer ingestion.

Normalized records retain their parsed `raw` payload in immutable PostgreSQL
event rows. This is not byte-exact raw archival, object-lock retention, or an
external append-only archive. The separate raw archive/reference contract in
ADR-0001 remains a deployment prerequisite.

Before production, establish and rehearse the following:

1. Encrypted database backups plus WAL/PITR, including outbox receipts, and
   separately backed-up RBAC/configuration/raw archives. Test restore into a
   fresh isolated database, verify the audit chain, and compare record counts.
2. Forward-fix schema rollback strategy. Do not start an older binary against
   an unsupported schema. For disaster rollback, restore the matching backup
   and application version into a separate target before switching traffic.
3. Credential rotation with overlapping runtime credentials, verified TLS,
   least-privilege grants, and revocation after clients reconnect.
4. Real OpenSearch/ClickHouse integration, database failover/load tests, raw
   archive recovery, ingestion ownership, and source checkpoint recovery.
   No production service has been deployed or failed over by these tests.

## Validation

The default suite remains network-independent apart from existing local UDP
listener checks; PostgreSQL tests skip unless explicitly configured:

```bash
PYTHONPATH=src python -m pytest tests/ -q
```

Install `.[api,dev,postgres]`. Set `AUTOSIEM_TEST_POSTGRES_DSN` to a **local,
disposable PostgreSQL server** maintenance database whose role can create
databases. Each test creates and drops only its own random `autosiem_test_*`
database, never a configured application database. Then run the same suite.
The PostgreSQL CI job opts into this configuration. Integration tests cover
migrations, rollback, tenant collisions, concurrent approvals/triage/audit,
baseline conflicts, failed-delivery replay, concurrent workers, CLI recovery,
listener persistence, API permissions, and backlog metrics. HTTP sink tests
use test doubles; they do not certify a running external search cluster.

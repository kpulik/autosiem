# ADR-0001: PostgreSQL control plane before multi-writer deployment

**Status:** Accepted

**Date:** 2026-08-24

**Decider:** Repository owner

## Context

AutoSIEM's default `AutoSIEMStorage` is SQLite. It is the authoritative store
for events, findings, incidents, investigations, action proposals, baselines,
rule state, suppressions, comments, and the hash-chained audit log. SQLite is
appropriate for the local workstation profile, but one database file permits
only one writer at a time.

The optional ClickHouse and OpenSearch backends store events only. They do not
store incidents, approvals, audit records, or tenant-scoped control-plane
state. Enabling either backend therefore does not make AutoSIEM highly
available or safe for multiple concurrent writers.

The system must keep its current local, zero-runtime-dependency profile. A
production deployment must also preserve tenant isolation, human approval for
high-risk actions, and a verifiable audit history.

## Decision

Keep SQLite as the default local profile. The optional implementation uses
PostgreSQL as the authoritative control-plane store and treats
ClickHouse or OpenSearch as rebuildable event query projections.

The control plane will own tenants, RBAC state, source checkpoints, rule state,
suppressions, baselines, findings, incidents, investigations, action proposals,
comments, audit records, and event archive references. Immutable raw telemetry
must remain in an append-only archive. ClickHouse and OpenSearch must not be
the sole authority for raw event retention. Every control-plane write must be
tenant-scoped before it is committed.

Each control-plane transaction that produces an event query projection will add
an outbox record in the same PostgreSQL transaction. A separate delivery worker
will project that record to ClickHouse or OpenSearch and mark it delivered only
after success. Projection writes must be idempotent by `(tenant_id, event_id)`.
The query projection is not an authorization source and cannot authorize or
execute an action.

PostgreSQL support is the optional `postgres` extra using Psycopg 3. Packaged,
numbered SQL migrations run through an explicit checksum-validating command.
It adds no runtime dependency to the local SQLite profile. The initial
implementation and remaining deployment limits are documented in
[the PostgreSQL guide](../postgresql.md).

## Options considered

### Continue with SQLite plus event-only backends

**Benefits:** No new service, dependency, or migration work.

**Rejected because:** It leaves a single control-plane writer and does not make
case management, approvals, audit, or tenant state highly available.

### Make ClickHouse or OpenSearch the system of record

**Benefits:** Scales event search and ingestion.

**Rejected because:** Neither existing adapter provides transactional control
plane semantics, tenant-safe authorization state, or an audit-chain authority.

### PostgreSQL control plane with outbox-backed event projections

**Benefits:** Supports concurrent control-plane writers, transactional case and
approval changes, forward-only migrations, and reliable projection replay.

**Costs:** Adds a production database, an optional driver, migrations, backups,
monitoring, and an outbox delivery service.

**Selected because:** It separates authoritative SOC state from scalable event
search without pretending the current event backends provide HA.

## Consequences

- Local single-process CLI and dashboard operation remain SQLite by default.
- Narrow storage ports and a shared relational repository keep SQL reads and
  case workflows consistent; each driver owns schema and transaction behavior.
- Concurrent case-management writers use row locks and terminal proposal
  decisions. Audit writers serialize their append. Baselines reject stale
  revisions, but ingestion still requires one owner per tenant.
- The existing SHA-256 audit chain remains tamper-evident. The previously
  documented HMAC and external-anchor work remains separate from this ADR.
- Event search can scale independently, but delayed projections must be visible
  as freshness lag rather than silently treated as complete telemetry.

## Migration gates

1. [x] Define storage ports for control-plane transactions and event-query
   reads. `storage_ports.py` now defines the initial contracts, and SQLite
   remains behaviorally compatible. The production raw-event archive and
   reference contract remain part of the next implementation proposal.
2. [x] Add a PostgreSQL implementation behind an explicit production configuration.
   Use forward-only, versioned migrations. Do not auto-migrate a production
   database during application startup.
3. [x] Add an outbox table, idempotent projector contract, replay command, and lag metric.
   Real PostgreSQL tests verify failure replay and destination receipts with an
   idempotent test sink. OpenSearch/ClickHouse HTTP adapters have offline contract
   tests; live external-cluster verification remains a deployment gate.
4. [x] Exercise concurrent incident updates and proposal decisions with a real
   PostgreSQL test target. Verify tenant isolation, approval gates, and audit
   verification under concurrent writers.
5. [ ] Rehearse backup, restore, rollback, secret rotation, and incident recovery
   before calling the deployment mode highly available. The guide describes
   the required procedures; no production failover or restore is certified.

## Non-goals

- This ADR does not certify a highly available deployment or exactly-once ingestion.
- This ADR does not replace SQLite for local use.
- This ADR does not make ClickHouse or OpenSearch authoritative.
- This ADR does not relax policy gating or human approval requirements.

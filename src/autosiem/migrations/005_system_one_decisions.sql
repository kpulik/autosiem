-- Forward-only. Applied explicitly by `autosiem migrate`.
--
-- Advisory System One assessments (Jev / Laya) for correlated incidents. This
-- table is metadata about a signal, never authority: severity, risk score and
-- the policy gates are computed by the deterministic engine and are stored
-- elsewhere. Nothing here is read back into a gating decision.
--
-- Composite primary key for the same reason as every other tenant-scoped table:
-- a tenant_id column beside a single-column key lets one tenant overwrite
-- another's row on an upsert path.
--
-- The state sent to the provider is deliberately not stored. It is derived from
-- the events and findings already persisted, and duplicating it would put a
-- second copy of event content (and any PII in it) in another table.
create table system_one_decisions (
    tenant_id text not null default 'default',
    incident_id text not null,
    provider text not null,
    model text not null,
    created_at text not null,
    disposition text not null,
    malicious double precision,
    severity text,
    severity_confidence double precision,
    action text,
    action_confidence double precision,
    needs_llm double precision,
    latency_ms double precision,
    fallback_used integer not null default 0,
    llm_escalated integer not null default 0,
    data text not null,
    primary key (tenant_id, incident_id)
);

create index system_one_decisions_provider on system_one_decisions (tenant_id, provider, created_at desc);

-- Forward-only. Applied explicitly by `autosiem migrate`.
--
-- Audit rows name actors and targets belonging to one tenant, but the table had
-- no tenant column and list_audit() applied no filter, so any caller holding
-- audit:read saw every tenant's history. Existing rows join the default tenant,
-- which is correct for the single-tenant deployments that wrote them.
--
-- tenant_id is deliberately outside the hashed payload: including it would
-- recompute every historical digest and make `autosiem audit-verify` report
-- tamper on every existing database. The chain protects audit CONTENT.
alter table audit_log add column tenant_id text not null default 'default';

create index audit_log_tenant on audit_log (tenant_id, audit_id desc);

-- Forward-only. Applied explicitly by `autosiem migrate`, never on startup.
create table events (
    tenant_id text not null,
    event_id text not null,
    timestamp text not null,
    category text not null,
    action text not null,
    "user" text, host text, src_ip text, severity text,
    data text not null check (jsonb_typeof(data::jsonb) = 'object'),
    primary key (tenant_id, event_id)
);
create table findings (
    tenant_id text not null,
    finding_id text not null,
    rule_id text not null, rule_name text not null,
    event_id text not null, timestamp text not null,
    severity text not null, risk_points integer not null, data text not null,
    primary key (tenant_id, finding_id),
    foreign key (tenant_id, event_id) references events (tenant_id, event_id)
);
create table incidents (
    tenant_id text not null,
    incident_id text not null,
    title text not null, severity text not null, risk_score integer not null,
    status text not null default 'open'
        check (status in ('open', 'investigating', 'resolved', 'closed')),
    created_at text not null, data text not null,
    assignee text, resolution text, updated_at text,
    primary key (tenant_id, incident_id)
);
create table investigations (
    tenant_id text not null,
    investigation_id text not null,
    incident_id text not null,
    status text not null, decision text not null,
    confidence double precision not null check (confidence between 0 and 1),
    created_at text not null, data text not null,
    primary key (tenant_id, investigation_id),
    unique (tenant_id, investigation_id, incident_id),
    foreign key (tenant_id, incident_id) references incidents (tenant_id, incident_id)
);
create table action_proposals (
    tenant_id text not null,
    proposal_id text not null,
    investigation_id text not null, incident_id text not null,
    action text not null, target text not null,
    confidence double precision not null check (confidence between 0 and 1),
    approval_required integer not null check (approval_required in (0,1)),
    executable_now integer not null check (executable_now in (0,1)),
    status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
    data text not null,
    primary key (tenant_id, proposal_id),
    check (approval_required = 0 or executable_now = 0),
    foreign key (tenant_id, investigation_id, incident_id)
        references investigations (tenant_id, investigation_id, incident_id)
);
create table incident_comments (
    tenant_id text not null,
    comment_id text not null,
    incident_id text not null,
    actor text not null, created_at text not null, body text not null,
    primary key (tenant_id, comment_id),
    foreign key (tenant_id, incident_id) references incidents (tenant_id, incident_id)
);
create table suppressions (
    tenant_id text not null,
    suppression_id text not null,
    rule_id text not null, name text not null, action text not null,
    entity text, downgrade_to text, reason text not null, expires_at text,
    created_by text not null, created_at text not null,
    enabled integer not null default 1 check (enabled in (0,1)),
    primary key (tenant_id, suppression_id)
);
create table rule_state (
    tenant_id text not null, rule_id text not null,
    enabled integer not null check (enabled in (0,1)), updated_at text not null,
    primary key (tenant_id, rule_id)
);
create table baselines (
    tenant_id text primary key,
    state text not null, updated_at text not null,
    revision bigint not null default 1
);
create table audit_log (
    audit_id bigint generated always as identity primary key,
    timestamp text not null, actor text not null, action text not null,
    target text, details text not null, prev_hash text not null, hash text not null
);
create index events_tenant_timestamp on events (tenant_id, timestamp desc);
create index findings_tenant_timestamp on findings (tenant_id, timestamp desc);
create index incidents_tenant_risk on incidents (tenant_id, risk_score desc, created_at desc);
create index investigations_incident on investigations (tenant_id, incident_id);
create index proposals_incident on action_proposals (tenant_id, incident_id);
create index comments_incident on incident_comments (tenant_id, incident_id, created_at);

-- Application credentials must not own these objects or be superusers.
-- These triggers guard against accidental updates/deletes, not a hostile DBA.
create function reject_immutable_mutation() returns trigger language plpgsql as $$
begin
    raise exception 'immutable AutoSIEM record';
end;
$$;
create trigger events_immutable before update or delete on events
    for each statement execute function reject_immutable_mutation();
create trigger audit_immutable before update or delete on audit_log
    for each statement execute function reject_immutable_mutation();

create table event_outbox (
    outbox_id bigint generated always as identity primary key,
    tenant_id text not null,
    event_id text not null,
    data text not null,
    created_at timestamptz not null default clock_timestamp(),
    unique (tenant_id, event_id),
    foreign key (tenant_id, event_id) references events (tenant_id, event_id)
);
-- A destination has its own receipt. New destinations can rebuild from every
-- retained outbox record without resetting another destination's progress.
create table projection_receipts (
    destination text not null,
    outbox_id bigint not null references event_outbox (outbox_id),
    delivered_at timestamptz not null default clock_timestamp(),
    primary key (destination, outbox_id)
);
create trigger outbox_immutable before update or delete on event_outbox
    for each statement execute function reject_immutable_mutation();

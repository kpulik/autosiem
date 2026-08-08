from __future__ import annotations

from pathlib import Path

import pytest

from autosiem.pipeline import AutoSIEMPipeline, PipelineResult
from autosiem.rules import load_rules
from autosiem.storage import AutoSIEMStorage
from autosiem.suppression import Suppression


def test_storage_persists_pipeline_result_and_decisions(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)

    store = AutoSIEMStorage(tmp_path / "autosiem.db")
    store.save_pipeline_result(result)

    incidents = store.list_incidents()
    assert len(incidents) == len(result.incidents)
    assert incidents[0]["data"]["incident_id"] == incidents[0]["incident_id"]

    bundle = store.get_incident_bundle(incidents[0]["incident_id"])
    assert bundle is not None
    assert bundle["incident"]["title"]
    assert bundle["investigation"] is not None
    assert bundle["findings"]
    assert bundle["events"]
    assert bundle["timeline"]
    assert bundle["proposals"]
    assert all(proposal["status"] == "pending" for proposal in bundle["proposals"])

    proposal_id = bundle["proposals"][0]["proposal_id"]
    decided = store.decide_proposal(proposal_id, "approved", actor="test-analyst")
    assert decided is not None
    assert decided["status"] == "approved"

    updated_bundle = store.get_incident_bundle(incidents[0]["incident_id"])
    assert updated_bundle is not None
    updated = {proposal["proposal_id"]: proposal for proposal in updated_bundle["proposals"]}
    assert updated[proposal_id]["status"] == "approved"

    audit = store.list_audit()
    actions = {entry["action"] for entry in audit}
    assert "pipeline_result_saved" in actions
    assert "proposal_approved" in actions


def test_storage_lists_events(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)

    store = AutoSIEMStorage(tmp_path / "autosiem.db")
    store.save_pipeline_result(result)

    events = store.list_events()
    assert len(events) == len(result.events)
    assert events[0]["data"]["event_id"] == events[0]["event_id"]


def test_storage_searches_events_incidents_and_builds_timeline(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)

    store = AutoSIEMStorage(tmp_path / "autosiem.db")
    store.save_pipeline_result(result)

    event_matches = store.search_events(query="powershell")
    assert event_matches
    assert any(event["action"] == "process_start" for event in event_matches)

    entity_matches = store.search_events(entity="user:alice")
    assert len(entity_matches) == len(result.events)

    incident_matches = store.search_incidents(entity="user:alice")
    assert incident_matches

    timeline = store.incident_timeline(result.incidents[0].incident_id)
    assert timeline is not None
    assert timeline[-1]["kind"] == "incident_created"
    assert any(item["kind"] == "finding" for item in timeline)


def test_storage_add_suppression_accepts_object_and_defaults(tmp_path: Path) -> None:
    store = AutoSIEMStorage(tmp_path / "autosiem.db")

    row = store.add_suppression(Suppression(rule_id="*", name="noise", action="suppress", reason="r", entity="user:bob"))
    assert row["suppression_id"]
    assert row["rule_id"] == "*"
    assert row["entity"] == "user:bob"
    assert row["created_by"] == "analyst"

    defaulted = store.add_suppression(rule_id="*")
    assert defaulted["action"] == "suppress"
    assert defaulted["name"] == "manual suppression"

    with pytest.raises(ValueError):
        store.add_suppression(rule_id="*", action="downgrade")
    with pytest.raises(ValueError):
        store.add_suppression(rule_id="*", action="explode")


def test_storage_suppression_and_triage(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    result = AutoSIEMPipeline(rules).process_lines(lines)

    store = AutoSIEMStorage(tmp_path / "autosiem.db")
    store.save_pipeline_result(result)

    suppression = store.add_suppression(rule_id="*", name="alice noise", action="suppress", reason="noise", entity="user:alice")
    assert suppression["suppression_id"]
    assert any(s["suppression_id"] == suppression["suppression_id"] for s in store.list_suppressions())
    assert any(s["suppression_id"] == suppression["suppression_id"] for s in store.list_suppressions(enabled_only=True))

    incident_id = store.list_incidents()[0]["incident_id"]
    updated = store.update_incident(
        incident_id, status="investigating", assignee="bob", resolution="monitoring", note="first look", actor="analyst"
    )
    assert updated is not None
    assert updated["status"] == "investigating"
    assert updated["assignee"] == "bob"

    bundle = store.get_incident_bundle(incident_id)
    assert bundle is not None
    assert bundle["incident"]["status"] == "investigating"
    assert bundle["incident"]["assignee"] == "bob"
    # Two comments: the AI analyst's triage note written at save time, then the
    # analyst's own note from update_incident.
    assert len(bundle["comments"]) == 2
    assert bundle["comments"][0]["actor"] == "ai-analyst"
    assert bundle["comments"][0]["body"].startswith("AI triage note for")
    assert bundle["comments"][1]["body"] == "first look"

    comment = store.add_incident_comment(incident_id, "analyst", "follow-up")
    assert comment is not None
    assert comment["body"] == "follow-up"
    assert len(store.list_incident_comments(incident_id)) == 3

    assert store.delete_suppression(suppression["suppression_id"]) is True
    assert not any(s["suppression_id"] == suppression["suppression_id"] for s in store.list_suppressions())

    actions = {entry["action"] for entry in store.list_audit()}
    assert "incident_updated" in actions
    assert "incident_commented" in actions
    assert "suppression_added" in actions
    assert "suppression_deleted" in actions


def _tenant_store(tmp_path: Path) -> tuple[AutoSIEMStorage, PipelineResult, PipelineResult]:
    """Storage with the same demo run saved under two different tenants."""
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    store = AutoSIEMStorage(tmp_path / "tenants.db")
    acme = AutoSIEMPipeline(rules).process_lines(lines)
    globex = AutoSIEMPipeline(rules).process_lines(lines)
    store.save_pipeline_result(acme, tenant_id="acme")
    store.save_pipeline_result(globex, tenant_id="globex")
    return store, acme, globex


def test_tenant_scoped_reads_isolate_rows(tmp_path: Path) -> None:
    store, acme, globex = _tenant_store(tmp_path)

    # Unscoped reads (CLI/local mode) see everything.
    assert len(store.list_events(limit=1000)) == len(acme.events) + len(globex.events)
    assert len(store.list_incidents(limit=1000)) == len(acme.incidents) + len(globex.incidents)

    # Scoped reads only ever see their own tenant.
    acme_events = store.list_events(limit=1000, tenant_id="acme")
    assert len(acme_events) == len(acme.events)
    assert all(row["tenant_id"] == "acme" for row in acme_events)

    acme_incidents = store.list_incidents(limit=1000, tenant_id="acme")
    assert len(acme_incidents) == len(acme.incidents)
    assert all(row["tenant_id"] == "acme" for row in acme_incidents)

    assert len(store.list_findings(limit=1000, tenant_id="globex")) == len(globex.findings)

    # An unknown tenant sees nothing at all.
    assert store.list_events(limit=1000, tenant_id="nobody") == []
    assert store.list_incidents(limit=1000, tenant_id="nobody") == []


def test_tenant_scoped_search_and_counts(tmp_path: Path) -> None:
    store, acme, _ = _tenant_store(tmp_path)

    scoped = store.search_events(query="powershell", tenant_id="acme")
    assert scoped and all(row["tenant_id"] == "acme" for row in scoped)
    unscoped = store.search_events(query="powershell")
    assert len(unscoped) == 2 * len(scoped)

    scoped_incidents = store.search_incidents(entity="user:alice", tenant_id="acme")
    assert scoped_incidents and all(row["tenant_id"] == "acme" for row in scoped_incidents)

    counts = store.counts(tenant_id="acme")
    assert counts["events"] == len(acme.events)
    assert counts["incidents"] == len(acme.incidents)
    # Unscoped counts cover both tenants.
    assert store.counts()["events"] == 2 * counts["events"]

    stats = store.source_stats(tenant_id="acme")
    assert sum(row["events"] for row in stats) == len(acme.events)


def test_cross_tenant_access_is_invisible(tmp_path: Path) -> None:
    store, acme, _ = _tenant_store(tmp_path)
    acme_incident = store.list_incidents(limit=1000, tenant_id="acme")[0]["incident_id"]

    # The owning tenant can read and mutate it.
    assert store.get_incident_bundle(acme_incident, tenant_id="acme") is not None
    assert store.incident_timeline(acme_incident, tenant_id="acme") is not None
    updated = store.update_incident(acme_incident, status="investigating", tenant_id="acme")
    assert updated is not None and updated["status"] == "investigating"

    # Another tenant gets "not found" rather than a permission error, so it
    # cannot even probe for the existence of the row.
    assert store.get_incident_bundle(acme_incident, tenant_id="globex") is None
    assert store.incident_timeline(acme_incident, tenant_id="globex") is None
    assert store.update_incident(acme_incident, status="closed", tenant_id="globex") is None
    assert store.add_incident_comment(acme_incident, "mallory", "hi", tenant_id="globex") is None
    assert store.list_incident_comments(acme_incident, tenant_id="globex") == []

    # The cross-tenant write above did not take effect.
    still = store.get_incident_bundle(acme_incident, tenant_id="acme")
    assert still is not None and still["incident"]["status"] == "investigating"


def test_cross_tenant_proposal_decisions_are_blocked(tmp_path: Path) -> None:
    store, _, _ = _tenant_store(tmp_path)
    bundle = store.get_incident_bundle(
        store.list_incidents(limit=1000, tenant_id="acme")[0]["incident_id"], tenant_id="acme"
    )
    assert bundle is not None
    proposal_id = bundle["proposals"][0]["proposal_id"]

    # Wrong tenant cannot approve it.
    assert store.decide_proposal(proposal_id, "approved", tenant_id="globex") is None
    # Owning tenant can.
    decided = store.decide_proposal(proposal_id, "approved", tenant_id="acme")
    assert decided is not None and decided["status"] == "approved"


def test_default_tenant_is_used_when_unspecified(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    store = AutoSIEMStorage(tmp_path / "default.db")
    store.save_pipeline_result(AutoSIEMPipeline(rules).process_lines(lines))

    rows = store.list_events(limit=1000)
    assert rows and all(row["tenant_id"] == "default" for row in rows)
    # Reading with the explicit default tenant returns the same rows.
    assert len(store.list_events(limit=1000, tenant_id="default")) == len(rows)


def test_tenant_rule_state_isolation(tmp_path: Path) -> None:
    """Same rule can be disabled for one tenant and enabled for another."""
    store = AutoSIEMStorage(tmp_path / "tenant_rules.db")
    store.set_rule_enabled("AUTO-AUTH-001", False, actor="analyst-a", tenant_id="acme")
    store.set_rule_enabled("AUTO-AUTH-001", True, actor="analyst-b", tenant_id="globex")

    acme_state = store.rule_state_dict(tenant_id="acme")
    globex_state = store.rule_state_dict(tenant_id="globex")
    assert acme_state == {"AUTO-AUTH-001": False}
    assert globex_state == {"AUTO-AUTH-001": True}

    # list_rule_states returns both scoped entries.
    all_states = store.list_rule_states()
    assert len(all_states) == 2
    tenants = {row["tenant_id"] for row in all_states}
    assert tenants == {"acme", "globex"}

    # Scoped listing.
    acme_list = store.list_rule_states(tenant_id="acme")
    assert len(acme_list) == 1 and acme_list[0]["tenant_id"] == "acme"


def test_tenant_suppression_isolation(tmp_path: Path) -> None:
    """Suppressions are scoped per tenant; delete is scoped too."""
    store = AutoSIEMStorage(tmp_path / "tenant_sups.db")
    s_acme = store.add_suppression(
        rule_id="AUTO-AUTH-001", name="acme-sup", action="suppress",
        reason="r", tenant_id="acme",
    )
    s_globex = store.add_suppression(
        rule_id="AUTO-AUTH-001", name="globex-sup", action="suppress",
        reason="r", tenant_id="globex",
    )

    # Unscoped reads see both.
    all_sups = store.list_suppressions()
    assert len(all_sups) == 2

    # Scoped reads only see one.
    acme_sups = store.list_suppressions(tenant_id="acme")
    assert len(acme_sups) == 1 and acme_sups[0]["suppression_id"] == s_acme["suppression_id"]

    globex_sups = store.list_suppressions(tenant_id="globex")
    assert len(globex_sups) == 1 and globex_sups[0]["suppression_id"] == s_globex["suppression_id"]

    # Scoping enabled_only and tenant_id together.
    acme_enabled = store.list_suppressions(enabled_only=True, tenant_id="acme")
    assert len(acme_enabled) == 1

    # Delete is tenant-scoped: wrong tenant returns False.
    assert store.delete_suppression(s_acme["suppression_id"], tenant_id="globex") is False
    # Correct tenant succeeds.
    assert store.delete_suppression(s_acme["suppression_id"], tenant_id="acme") is True
    # The other tenant's suppression is unaffected.
    remaining = store.list_suppressions(tenant_id="globex")
    assert len(remaining) == 1


def test_migration_from_old_schema(tmp_path: Path) -> None:
    """An old DB lacking control-plane tenant_id columns is upgraded gracefully."""
    import sqlite3 as _sqlite
    from autosiem.storage import AutoSIEMStorage

    db = tmp_path / "old.db"
    conn = _sqlite.connect(db)
    conn.executescript("""
        create table suppressions (
            suppression_id text primary key, rule_id text not null,
            name text not null, action text not null,
            entity text, downgrade_to text, reason text not null,
            expires_at text, created_by text not null,
            created_at text not null, enabled integer not null default 1
        );
        create table rule_state (
            rule_id text primary key,
            enabled integer not null default 1,
            updated_at text not null
        );
        insert into rule_state(rule_id, enabled, updated_at) values('R1', 0, '2024-01-01');
    """)
    conn.commit(); conn.close()

    store = AutoSIEMStorage(db)

    # rule_state should have migrated: old row lands in 'default' tenant.
    assert store.rule_state_dict(tenant_id="default") == {"R1": False}
    # rule_state PK is now composite.
    rs = store.set_rule_enabled("R1", True, tenant_id="acme")
    assert rs["tenant_id"] == "acme" and rs["enabled"] is True
    # default tenant unaffected.
    assert store.rule_state_dict(tenant_id="default") == {"R1": False}

    # suppressions should have tenant_id too.
    s = store.add_suppression(rule_id="*", name="test", action="suppress", reason="r", tenant_id="acme")
    assert s["tenant_id"] == "acme"
    acme_sups = store.list_suppressions(tenant_id="acme")
    assert len(acme_sups) == 1


def test_source_stats(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    lines = (root / "examples" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    store = AutoSIEMStorage(tmp_path / "autosiem.db")
    store.save_pipeline_result(AutoSIEMPipeline(rules).process_lines(lines))

    stats = store.source_stats()
    assert stats
    assert sum(row["events"] for row in stats) == len(lines)
    assert all(row["source"] for row in stats)
    assert all(row["first_seen"] and row["last_seen"] for row in stats)

"""Isolation and fail-closed regressions from the PR #1 review.

Every case here is a defect that shipped to public main with a green suite.
The common shape: a control that looked present (a tenant_id column, an
operator loop, a category map) but did not actually constrain anything.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from autosiem.detection import _KNOWN_OPERATORS, UnknownOperatorError, evaluate_rule
from autosiem.normalization import normalize
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules, rule_from_dict
from autosiem.schemas import DetectionRule, Severity
from autosiem.storage import _TENANT_KEYED_TABLES, AutoSIEMStorage

ROOT = Path(__file__).resolve().parents[1]


def _event(user: str, event_id: str = "SHARED-1") -> str:
    return json.dumps({
        "event_id": event_id, "timestamp": "2026-09-15T10:00:00Z",
        "category": "authentication", "action": "login_success",
        "user": user, "src_ip": "10.0.0.1", "outcome": "success",
    })


@pytest.fixture
def store(tmp_path):
    return AutoSIEMStorage(tmp_path / "iso.db")


# -- tenant row isolation --------------------------------------------------

def test_two_tenants_may_share_an_upstream_event_id(store):
    """One tenant's INSERT OR REPLACE used to destroy the other's row."""
    pipe = AutoSIEMPipeline(load_rules(ROOT / "rules"))
    store.save_pipeline_result(pipe.process_lines([_event("alice-A")]), "tenant-a")
    store.save_pipeline_result(pipe.process_lines([_event("bob-B")]), "tenant-b")
    assert store.counts("tenant-a")["events"] == 1
    assert store.counts("tenant-b")["events"] == 1
    with store.connect() as conn:
        rows = {r["tenant_id"]: r["user"] for r in conn.execute("select tenant_id, user from events")}
    assert rows == {"tenant-a": "alice-A", "tenant-b": "bob-B"}


def test_every_tenant_keyed_table_has_a_composite_primary_key(store):
    with store.connect() as conn:
        for table, key in _TENANT_KEYED_TABLES:
            pk = sorted(r["name"] for r in conn.execute(f"pragma table_info({table})") if r["pk"])
            assert pk == sorted([key, "tenant_id"]), f"{table} primary key is {pk}"


def test_a_legacy_single_key_database_is_migrated_without_losing_rows(tmp_path):
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        create table events (event_id text primary key, timestamp text not null, category text not null,
          action text not null, user text, host text, src_ip text, severity text, data text not null,
          tenant_id text not null default 'default');
        insert into events values('E1','2026-01-01','authentication','login','alice','h','1.1.1.1','low','{}','tenant-a');
        create table audit_log (audit_id integer primary key autoincrement, timestamp text not null,
          actor text not null, action text not null, target text, details text not null);
        insert into audit_log(timestamp,actor,action,target,details) values('t','who','did','what','{}');
    """)
    conn.commit()
    conn.close()

    migrated = AutoSIEMStorage(db)
    with migrated.connect() as c:
        pk = sorted(r["name"] for r in c.execute("pragma table_info(events)") if r["pk"])
        assert pk == ["event_id", "tenant_id"]
        row = c.execute("select event_id, tenant_id, user from events").fetchone()
        assert (row["event_id"], row["tenant_id"], row["user"]) == ("E1", "tenant-a", "alice")
        assert "tenant_id" in [r["name"] for r in c.execute("pragma table_info(audit_log)")]
        assert c.execute("select count(*) as n from audit_log").fetchone()["n"] == 1


# -- audit tenancy ---------------------------------------------------------

def test_audit_reads_are_scoped_to_one_tenant(store):
    with store.connect() as conn:
        store.audit(conn, "admin-B", "proposal_approved", "host:secret-b", {}, tenant_id="tenant-b")
        store.audit(conn, "admin-A", "proposal_approved", "host:secret-a", {}, tenant_id="tenant-a")
    a_targets = {row["target"] for row in store.list_audit(tenant_id="tenant-a")}
    b_targets = {row["target"] for row in store.list_audit(tenant_id="tenant-b")}
    assert "host:secret-a" in a_targets and "host:secret-b" not in a_targets
    assert "host:secret-b" in b_targets and "host:secret-a" not in b_targets


def test_unscoped_audit_read_still_sees_everything_for_verification(store):
    with store.connect() as conn:
        store.audit(conn, "a", "x", "t1", {}, tenant_id="tenant-a")
        store.audit(conn, "b", "x", "t2", {}, tenant_id="tenant-b")
    assert len(store.list_audit()) == 2
    assert store.verify_audit_chain() == []


def test_the_audit_hash_chain_survives_the_tenant_column(store):
    """tenant_id is deliberately outside the hashed payload."""
    with store.connect() as conn:
        for i in range(5):
            store.audit(conn, f"actor{i}", "act", f"t{i}", {"i": i}, tenant_id=f"tenant-{i % 2}")
    assert store.verify_audit_chain() == []


# -- detection fails closed ------------------------------------------------

def _rule(selection):
    return DetectionRule(rule_id="X", name="t", description="", severity=Severity.HIGH,
                         risk_points=99, selection=selection, mitre_attack=[], tags=[])


@pytest.fixture
def benign():
    return normalize({"timestamp": "2026-09-15T10:00:00Z", "category": "process",
                      "action": "process_start", "user": "a", "host": "h",
                      "process_name": "notepad.exe", "command_line": "notepad.exe readme.txt"})


@pytest.mark.parametrize("selection", [
    {"command_line": {"contians": "mimikatz"}},   # typo
    {"bytes_sent": {"gt": 999999999}},            # documented as not implemented
    {"command_line": {"cidr": "10.0.0.0/8"}},     # Sigma modifier, not a native operator
])
def test_an_unknown_operator_raises_instead_of_matching_everything(benign, selection):
    with pytest.raises(UnknownOperatorError):
        evaluate_rule(benign, _rule(selection))


def test_an_empty_operator_map_matches_nothing(benign):
    assert evaluate_rule(benign, _rule({"command_line": {}})) is None


def test_bad_operators_are_rejected_when_the_rule_loads(benign):
    """Load time, not match time: one bad rule must not stop an ingest run."""
    for selection in ({"command_line": {"contians": "x"}}, {"b": {"gt": 1}}, {"c": {}}):
        with pytest.raises(ValueError, match="unknown operator|empty operator"):
            rule_from_dict({"id": "BAD", "name": "n", "severity": "high", "selection": selection})


def test_nested_boolean_nodes_are_validated_too():
    with pytest.raises(ValueError, match="unknown operator"):
        rule_from_dict({"id": "BAD", "name": "n", "severity": "high",
                        "selection": {"any_of": [{"command_line": {"contians": "x"}}]}})


def test_every_curated_rule_uses_only_implemented_operators():
    for rule in load_rules(ROOT / "rules"):
        for field, expected in rule.selection.items():
            if isinstance(expected, dict) and field not in ("any_of", "all_of", "not"):
                assert not set(expected) - _KNOWN_OPERATORS, f"{rule.rule_id}.{field}"

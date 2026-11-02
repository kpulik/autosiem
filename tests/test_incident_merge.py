"""New findings join stored open incidents, so a long attack stays one incident."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest

from autosiem.cli import main
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.risk import (
    DECISION_RISK_THRESHOLDS,
    MAX_INCIDENT_FINDINGS,
    StoredIncident,
    incident_from_findings,
    merge_into_stored,
)
from autosiem.rules import load_rules
from autosiem.schemas import DetectionRule, Finding, Incident, Severity
from autosiem.soc_runtime import AIAnalystRuntime, DecisionType
from autosiem.storage import AutoSIEMStorage

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


def _finding(entities, when=T0, risk=10, severity=Severity.MEDIUM, techniques=(), rule="R1", event=None):
    return Finding(
        finding_id=str(uuid4()),
        rule_id=rule,
        rule_name=rule,
        event_id=event or str(uuid4()),
        timestamp=when,
        severity=severity,
        risk_points=risk,
        entities=list(entities),
        mitre_attack=list(techniques),
        evidence={},
    )


def _stored(*findings):
    return StoredIncident(incident_from_findings(list(findings)), list(findings))


# --- matching ---


def test_shared_entity_inside_window_joins_the_stored_incident():
    stored = _stored(_finding(["user:alice"], risk=40))
    new = _finding(["user:alice"], when=T0 + HOUR, risk=25)
    fresh, merges = merge_into_stored([new], [stored])
    assert fresh == []
    merge = merges[0]
    assert merge.incident.incident_id == stored.incident.incident_id
    assert merge.incident.created_at == stored.incident.created_at
    assert merge.incident.risk_score == 65
    assert merge.new_finding_ids == [new.finding_id]
    assert new.finding_id in merge.incident.finding_ids


@pytest.mark.parametrize("gap,joins", [(timedelta(hours=24), True), (timedelta(hours=24, seconds=1), False)])
def test_window_boundary(gap, joins):
    stored = _stored(_finding(["user:alice"]))
    _, merges = merge_into_stored([_finding(["user:alice"], when=T0 + gap)], [stored])
    assert bool(merges) is joins


def test_late_arriving_finding_inside_the_window_still_joins():
    stored = _stored(_finding(["user:alice"], when=T0))
    _, merges = merge_into_stored([_finding(["user:alice"], when=T0 - HOUR)], [stored])
    assert merges


def test_window_is_per_entity_not_per_incident():
    # bob was last seen 30h before the new finding, though the incident's newest
    # finding (on alice) is recent. correlate_findings would not link these either.
    stored = _stored(
        _finding(["user:bob", "host:h1"], when=T0),
        _finding(["host:h1", "user:alice"], when=T0 + 20 * HOUR),
    )
    _, merges = merge_into_stored([_finding(["user:bob"], when=T0 + 30 * HOUR)], [stored])
    assert merges == []


def test_unrelated_entity_opens_a_new_incident():
    fresh, merges = merge_into_stored([_finding(["user:bob"])], [_stored(_finding(["user:alice"]))])
    assert len(fresh) == 1 and merges == []


def test_placeholder_entity_links_nothing():
    stored = _stored(_finding(["global:unknown"]))
    fresh, merges = merge_into_stored([_finding(["global:unknown"])], [stored])
    assert len(fresh) == 1 and merges == []


def test_two_clusters_linking_to_one_incident_become_one_merge():
    stored = _stored(_finding(["user:alice", "host:h1"]))
    fresh, merges = merge_into_stored(
        [_finding(["user:alice"], when=T0 + HOUR), _finding(["host:h1"], when=T0 + HOUR)], [stored]
    )
    assert fresh == [] and len(merges) == 1
    assert len(merges[0].new_finding_ids) == 2


def test_cluster_joins_the_highest_risk_incident_and_leaves_the_other_alone():
    low = _stored(_finding(["user:alice"], risk=10))
    high = _stored(_finding(["host:h1"], risk=90))
    _, merges = merge_into_stored([_finding(["user:alice", "host:h1"], when=T0 + HOUR)], [low, high])
    assert [merge.incident.incident_id for merge in merges] == [high.incident.incident_id]


def test_redelivered_finding_adds_no_risk():
    original = _finding(["user:alice"], risk=40, event="evt-1")
    stored = _stored(original)
    again = _finding(["user:alice"], risk=40, event="evt-1")
    fresh, merges = merge_into_stored([again], [stored])
    assert fresh == [] and merges == []
    # A different rule on the same event is new information.
    _, merges = merge_into_stored([_finding(["user:alice"], rule="R2", event="evt-1")], [stored])
    assert len(merges) == 1


def test_full_incident_takes_no_more_and_the_attack_continues_in_a_new_one():
    findings = [_finding(["user:alice"], risk=0) for _ in range(MAX_INCIDENT_FINDINGS)]
    fresh, merges = merge_into_stored([_finding(["user:alice"])], [_stored(*findings)])
    assert len(fresh) == 1 and merges == []


# --- what counts as a material change ---


def _merge(before, *added):
    stored = _stored(*before)
    _, merges = merge_into_stored(list(added), [stored])
    return merges[0]


def test_more_of_the_same_is_not_material():
    assert not _merge([_finding(["user:a"], risk=40)], _finding(["user:a"], when=T0 + HOUR, risk=1)).material


@pytest.mark.parametrize(
    "added",
    [
        {"entities": ["user:a", "host:new"]},
        {"entities": ["user:a"], "severity": Severity.HIGH},
        {"entities": ["user:a"], "techniques": ["T1110"]},
        {"entities": ["user:a"], "risk": 60},
    ],
)
def test_material_changes(added):
    assert _merge([_finding(["user:a"], risk=40)], _finding(when=T0 + HOUR, **added)).material


def test_thresholds_are_every_risk_at_which_the_runtime_changes_its_mind():
    """A threshold missing from the constant would skip a needed re-investigation."""
    runtime = AIAnalystRuntime()
    seen = []
    for risk in range(0, 1001):
        incident = Incident("i", "t", Severity.HIGH, risk, [], [], [], "s")
        confidence = runtime._estimate_confidence(incident, [])
        seen.append((runtime._make_decision(incident, [], confidence).decision_type, confidence))
    high = {risk for risk in range(1, 1001) if seen[risk] != seen[risk - 1]}
    seen = []
    for risk in range(0, 1001):
        incident = Incident("i", "t", Severity.LOW, risk, [], [], [], "s")
        confidence = runtime._estimate_confidence(incident, [])
        seen.append((runtime._make_decision(incident, [], confidence).decision_type, confidence))
    low = {risk for risk in range(1, 1001) if seen[risk] != seen[risk - 1]}
    assert high | low == set(DECISION_RISK_THRESHOLDS)


# --- through the pipeline and a real store ---


RULES = [
    DetectionRule("LOW", "low", "d", Severity.LOW, 20, {"action": "probe"}, []),
    DetectionRule("HIGH", "high", "d", Severity.HIGH, 120, {"action": "exploit"}, ["T1110"]),
]


def _event(action="probe", user="alice", hours=0.0, **extra):
    return json.dumps(
        {
            "timestamp": (T0 + timedelta(hours=hours)).isoformat(),
            "action": action,
            "category": "authentication",
            "user": user,
            **extra,
        }
    )


def _pipeline(store, tenant="default"):
    # A fresh pipeline per run, as the API does; no anomaly noise in the counts.
    pipeline = AutoSIEMPipeline(RULES, event_search=store, tenant_id=tenant, incident_store=store)
    pipeline.anomaly_detector.finding_for_event = lambda event: None
    return pipeline


def _run(store, lines, tenant="default"):
    result = _pipeline(store, tenant).process_lines(lines)
    store.save_pipeline_result(result, tenant_id=tenant)
    return result


def _bundle(store, tenant="default"):
    incidents = store.list_incidents(tenant_id=tenant)
    assert len(incidents) == 1
    return _bundle_of(store, incidents[0]["incident_id"], tenant)


def _bundle_of(store, incident_id, tenant="default"):
    bundle = store.get_incident_bundle(incident_id, tenant_id=tenant)
    assert bundle is not None
    return bundle


@pytest.fixture
def store(tmp_path):
    return AutoSIEMStorage(tmp_path / "merge.db")


def test_two_batches_are_one_incident(store):
    _run(store, [_event()])
    result = _run(store, [_event(hours=1)])
    assert len(result.merges) == 1
    bundle = _bundle(store)
    assert len(bundle["findings"]) == 2
    assert bundle["incident"]["risk_score"] == 40
    assert len(bundle["events"]) == 2
    assert store.verify_audit_chain() == []


def test_stored_finding_round_trips_through_its_document(store):
    original = _run(store, [_event("exploit")]).findings[0]
    stored = store.open_incidents_for_entities({"user:alice"})[0]["findings"][0]
    restored = Finding.from_dict(stored)
    # Evidence is stored JSON-safe (enums become names), so it is compared by its event.
    assert restored.evidence["event"] == original.evidence["event"]
    restored.evidence = original.evidence
    assert restored == original


def test_slow_attack_reaches_containment_across_batches(store):
    """Each batch alone stays below the risk 200 that containment requires."""
    first = _run(store, [_event("exploit")])
    only_investigation = next(iter(first.investigations.values()))
    assert only_investigation.decision.decision_type is not DecisionType.CONTAINMENT_PROPOSED
    second = _run(store, [_event("exploit", hours=1)])
    investigation = next(iter(second.investigations.values()))
    assert investigation.decision.decision_type is DecisionType.CONTAINMENT_PROPOSED
    assert any(p["action"] == "disable_user" for p in _bundle(store)["proposals"])


def test_investigation_of_a_merge_sees_the_stored_findings(store):
    _run(store, [_event("exploit")])
    result = _run(store, [_event("exploit", hours=1)])
    investigation = next(iter(result.investigations.values()))
    assert len([item for item in investigation.evidence if item.kind == "finding"]) == 2


def test_only_new_findings_are_returned_and_saved(store):
    _run(store, [_event()])
    result = _run(store, [_event(hours=1)])
    assert len(result.findings) == 1
    assert len(store.list_findings()) == 2


def test_more_of_the_same_writes_no_investigation_or_comment(store):
    _run(store, [_event()])
    # Crosses 30, so this one is material.
    _run(store, [_event(hours=1)])
    bundle = _bundle(store)
    comments = len(bundle["comments"])
    with store.connect() as conn:
        investigations = conn.execute("select count(*) as n from investigations").fetchone()["n"]
    result = _run(store, [_event(hours=2)])
    assert result.investigations == {} and result.reports == {}
    bundle = _bundle(store)
    assert bundle["incident"]["risk_score"] == 60
    assert len(bundle["comments"]) == comments
    with store.connect() as conn:
        assert conn.execute("select count(*) as n from investigations").fetchone()["n"] == investigations


def test_material_merge_keeps_one_of_each_live_proposal(store):
    _run(store, [_event("exploit"), _event("exploit", hours=1)])
    before = _bundle(store)["proposals"]
    assert before
    _run(store, [_event("exploit", hours=2, src_ip="203.0.113.9")])
    proposals = _bundle(store)["proposals"]
    keys = [(p["action"], p["target"]) for p in proposals]
    assert len(keys) == len(set(keys))
    assert ("block_indicator", "ip:203.0.113.9") in keys


def test_approved_proposal_is_not_raised_again_but_rejected_may_return(store):
    _run(store, [_event("exploit"), _event("exploit", hours=1)])
    proposals = _bundle(store)["proposals"]
    disable = next(p for p in proposals if p["action"] == "disable_user")
    store.decide_proposal(disable["proposal_id"], "rejected")
    _run(store, [_event("exploit", hours=2, src_ip="203.0.113.9")])
    disables = [p for p in _bundle(store)["proposals"] if p["action"] == "disable_user"]
    assert len(disables) == 2
    store.decide_proposal(disables[-1]["proposal_id"] if disables[-1]["status"] == "pending" else disables[0]["proposal_id"], "approved")
    _run(store, [_event("exploit", hours=3, src_ip="203.0.113.10")])
    assert len([p for p in _bundle(store)["proposals"] if p["action"] == "disable_user"]) == 2


def test_triage_survives_a_merge(store):
    _run(store, [_event()])
    incident_id = store.list_incidents()[0]["incident_id"]
    store.update_incident(incident_id, status="investigating", assignee="dana", note="looking")
    created_at = store.list_incidents()[0]["created_at"]
    _run(store, [_event(hours=1)])
    row = store.list_incidents()[0]
    assert (row["status"], row["assignee"], row["created_at"]) == ("investigating", "dana", created_at)
    assert row["updated_at"] is not None
    assert any(c["body"] == "looking" for c in _bundle_of(store, incident_id)["comments"])


@pytest.mark.parametrize("status", ["resolved", "closed"])
def test_analyst_verdict_stands_and_new_activity_opens_a_new_incident(store, status):
    _run(store, [_event()])
    closed_id = store.list_incidents()[0]["incident_id"]
    store.update_incident(closed_id, status=status)
    _run(store, [_event(hours=1)])
    incidents = store.list_incidents()
    assert len(incidents) == 2
    assert _bundle_of(store, closed_id)["incident"]["risk_score"] == 20
    assert _bundle_of(store, closed_id)["incident"]["status"] == status


def test_closed_between_read_and_save_keeps_every_new_finding(store):
    _run(store, [_event("exploit")])
    closed_id = store.list_incidents()[0]["incident_id"]
    result = _pipeline(store).process_lines([_event("exploit", hours=1)])
    assert closed_id in result.merges and closed_id in result.investigations
    store.update_incident(closed_id, status="closed")
    store.save_pipeline_result(result, tenant_id="default")

    assert _bundle_of(store, closed_id)["incident"]["risk_score"] == 120
    other = next(row for row in store.list_incidents() if row["incident_id"] != closed_id)
    bundle = _bundle_of(store, other["incident_id"])
    assert [f["finding_id"] for f in bundle["findings"]] == [result.findings[0].finding_id]
    assert bundle["investigation"]["incident_id"] == other["incident_id"]
    assert bundle["investigation"]["data"]["incident_id"] == other["incident_id"]
    assert store.verify_audit_chain() == []


def test_two_writers_merging_one_incident_keep_both_findings(store):
    _run(store, [_event()])
    one = _pipeline(store).process_lines([_event(hours=1)])
    two = _pipeline(store).process_lines([_event(hours=2)])
    store.save_pipeline_result(one, tenant_id="default")
    store.save_pipeline_result(two, tenant_id="default")
    bundle = _bundle(store)
    assert len(bundle["findings"]) == 3
    assert bundle["incident"]["risk_score"] == 60


def test_tenants_never_merge(store):
    _run(store, [_event()], tenant="acme")
    result = _run(store, [_event(hours=1)], tenant="globex")
    assert result.merges == {}
    assert len(store.list_incidents(tenant_id="acme")) == 1
    assert len(store.list_incidents(tenant_id="globex")) == 1
    assert store.open_incidents_for_entities({"user:alice"}, tenant_id="other") == []


def test_store_failure_costs_only_the_merge(caplog):
    class Broken:
        def open_incidents_for_entities(self, entities, tenant_id=None):
            raise RuntimeError("database is locked")

    result = AutoSIEMPipeline(RULES, incident_store=Broken()).process_lines([_event()])
    assert len(result.incidents) == 1 and result.merges == {}
    assert "Incident merge skipped (RuntimeError)" in caplog.text


def test_without_a_store_nothing_changes(store):
    pipeline = AutoSIEMPipeline(RULES, tenant_id="default")
    pipeline.anomaly_detector.finding_for_event = lambda event: None
    store.save_pipeline_result(pipeline.process_lines([_event()]), tenant_id="default")
    pipeline = AutoSIEMPipeline(RULES, tenant_id="default")
    pipeline.anomaly_detector.finding_for_event = lambda event: None
    store.save_pipeline_result(pipeline.process_lines([_event(hours=1)]), tenant_id="default")
    assert len(store.list_incidents()) == 2


def test_full_incident_is_not_loaded_for_every_later_batch(store, monkeypatch):
    monkeypatch.setattr("autosiem.storage.MAX_INCIDENT_FINDINGS", 2)
    _run(store, [_event(), _event(hours=1)])
    assert store.open_incidents_for_entities({"user:alice"}) == []


def test_scan_limit_prefers_recently_active_incidents(store):
    _run(store, [_event(user="old")])
    _run(store, [_event(user="newer")])
    assert store.open_incidents_for_entities({"user:old"}, scan_limit=1) == []
    assert store.open_incidents_for_entities({"user:newer"}, scan_limit=1)


# --- through the CLI ---


def _write(path, lines):
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def _cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["autosiem", *argv, "--rules", str(ROOT / "rules")])
    main()


def _cli_ingest(tmp_path, monkeypatch, capsys, db, lines, name):
    _cli(monkeypatch, "ingest", "--file", _write(tmp_path / name, lines), "--db", str(db))
    return capsys.readouterr().out


FAILED = {"category": "authentication", "action": "login", "outcome": "failure"}


def _failed_login(hours):
    return json.dumps({**FAILED, "user": "alice", "timestamp": (T0 + timedelta(hours=hours)).isoformat()})


def test_cli_ingest_twice_is_one_incident_and_says_so(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.db"
    _cli_ingest(tmp_path, monkeypatch, capsys, db, [_failed_login(0)], "one.jsonl")
    _cli_ingest(tmp_path, monkeypatch, capsys, db, [_failed_login(1)], "two.jsonl")
    out = _cli_ingest(tmp_path, monkeypatch, capsys, db, [_failed_login(2)], "three.jsonl")
    payload = json.JSONDecoder().raw_decode(out)[0]
    assert [item["merged_findings"] for item in payload["incidents"]][0] >= 1
    store = AutoSIEMStorage(db)
    assert len(store.list_incidents()) == 1
    assert len(_bundle_of(store, store.list_incidents()[0]["incident_id"])["findings"]) >= 3


def test_cli_prints_a_line_not_a_traceback_when_nothing_material_changed(tmp_path, monkeypatch, capsys):
    db = tmp_path / "cli.db"
    for index in range(6):
        out = _cli_ingest(tmp_path, monkeypatch, capsys, db, [_failed_login(index * 0.1)], f"{index}.jsonl")
    assert "no material change, not re-investigated" in out


def test_cli_demo_twice_stays_two_runs(tmp_path, monkeypatch, capsys):
    db = tmp_path / "demo.db"
    _cli(monkeypatch, "demo", "--db", str(db))
    _cli(monkeypatch, "demo", "--db", str(db))
    capsys.readouterr()
    assert len(AutoSIEMStorage(db).list_incidents()) == 2


@pytest.mark.skipif(not os.environ.get("AUTOSIEM_TEST_POSTGRES_DSN"), reason="needs local PostgreSQL")
def test_postgres_merge_keeps_triage_and_replaces_the_assessment():
    from autosiem import postgres

    driver = postgres._driver()
    base = os.environ["AUTOSIEM_TEST_POSTGRES_DSN"]
    name = "autosiem_test_" + uuid4().hex
    with driver.connect(base, autocommit=True) as admin:
        admin.execute(driver.sql.SQL("create database {}").format(driver.sql.Identifier(name)))
    dsn = f"{base} dbname={name}"
    try:
        postgres.migrate(dsn)
        store = postgres.PostgresStorage(dsn)
        _run(store, [_event("exploit")])
        incident_id = store.list_incidents(tenant_id="default")[0]["incident_id"]
        store.update_incident(incident_id, status="investigating", assignee="dana", tenant_id="default")
        result = _pipeline(store).process_lines([_event("exploit", hours=1)])
        result.decisions[incident_id] = cast(Any, {"provider": "first", "disposition": "review"})
        store.save_pipeline_result(result, tenant_id="default")
        result = _pipeline(store).process_lines([_event("exploit", hours=2, src_ip="203.0.113.9")])
        result.decisions[incident_id] = cast(Any, {"provider": "second", "disposition": "review"})
        store.save_pipeline_result(result, tenant_id="default")

        bundle = _bundle(store)
        assert bundle["incident"]["status"] == "investigating"
        assert bundle["incident"]["assignee"] == "dana"
        assert bundle["incident"]["risk_score"] == 360
        assert len(bundle["findings"]) == 3
        assert bundle["system_one"]["provider"] == "second"
        keys = [(p["action"], p["target"]) for p in bundle["proposals"]]
        assert len(keys) == len(set(keys))
        assert store.verify_audit_chain() == []
    finally:
        with driver.connect(base, autocommit=True) as admin:
            admin.execute(driver.sql.SQL("drop database {} with (force)").format(driver.sql.Identifier(name)))

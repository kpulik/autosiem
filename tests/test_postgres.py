"""Offline contracts plus explicitly enabled disposable PostgreSQL integration.

AUTOSIEM_TEST_POSTGRES_DSN must name a local maintenance database whose role
can CREATE DATABASE. Each test creates and drops only its own random database.
"""
from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from autosiem import postgres
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules
from autosiem.storage import AutoSIEMStorage, open_storage


def test_default_storage_has_no_postgres_dependency(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTOSIEM_STORAGE", raising=False)
    monkeypatch.setattr(postgres, "_driver", lambda: pytest.fail("SQLite imported PostgreSQL driver"))
    assert isinstance(open_storage(tmp_path / "local.db"), AutoSIEMStorage)


def test_configuration_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOSIEM_STORAGE", "postgres")
    monkeypatch.delenv("AUTOSIEM_POSTGRES_DSN", raising=False)
    with pytest.raises(ValueError, match="DSN"):
        open_storage(tmp_path / "must_not_exist.db")
    assert not (tmp_path / "must_not_exist.db").exists()
    monkeypatch.setenv("AUTOSIEM_STORAGE", "typo")
    with pytest.raises(ValueError, match="AUTOSIEM_STORAGE"):
        open_storage(tmp_path / "must_not_exist.db")


def test_bind_adapter_preserves_literals_identifiers_and_comments():
    sql = "select '?', \"?\", ? -- ?\n /* ? */ where x like '%?%' and n % 2 = ?"
    assert postgres._qmark_sql(sql) == "select '?', \"?\", %s -- ?\n /* ? */ where x like '%%?%%' and n %% 2 = %s"


def test_packaged_migrations_are_contiguous_and_history_is_checked():
    migrations = postgres._migrations()
    assert [row[0] for row in migrations] == list(range(1, len(migrations) + 1))
    history = [{"version": v, "checksum": h} for v, h, _ in migrations]
    assert postgres._validate_history(history, migrations) == len(migrations)
    with pytest.raises(RuntimeError, match="newer"):
        postgres._validate_history(
            history + [{"version": len(migrations) + 1, "checksum": "unknown"}], migrations)
    history[0]["checksum"] = "changed"
    with pytest.raises(RuntimeError, match="mismatch"):
        postgres._validate_history(history, migrations)


@pytest.fixture
def pg_dsn():
    base = os.environ.get("AUTOSIEM_TEST_POSTGRES_DSN")
    if not base:
        pytest.skip("set AUTOSIEM_TEST_POSTGRES_DSN for local PostgreSQL integration")
    driver = postgres._driver()
    info = driver.conninfo.conninfo_to_dict(base)
    host = info.get("host", "")
    if host not in {"", "localhost", "127.0.0.1", "::1"} and not host.startswith("/"):
        pytest.fail("PostgreSQL tests require a local disposable server")
    name = "autosiem_test_" + uuid4().hex
    with driver.connect(base, autocommit=True) as admin:
        admin.execute(driver.sql.SQL("create database {}").format(driver.sql.Identifier(name)))
    try:
        yield driver.conninfo.make_conninfo(base, dbname=name)
    finally:
        with driver.connect(base, autocommit=True) as admin:
            admin.execute(driver.sql.SQL("drop database {}").format(driver.sql.Identifier(name)))


@pytest.fixture
def pg(pg_dsn):
    postgres.migrate(pg_dsn)
    return postgres.PostgresStorage(pg_dsn)


@pytest.fixture
def result():
    root = Path(__file__).resolve().parents[1]
    return AutoSIEMPipeline(load_rules(root / "rules")).process_lines(
        (root / "examples/events.jsonl").read_text().splitlines())


def test_pg_explicit_migrations_and_no_startup_ddl(pg_dsn):
    with pytest.raises(RuntimeError, match="missing"):
        postgres.PostgresStorage(pg_dsn)
    expected = [version for version, _, _ in postgres._migrations()]
    assert postgres.migrate(pg_dsn) == expected
    assert postgres.migrate(pg_dsn) == []
    postgres.PostgresStorage(pg_dsn)


def test_pg_failed_migration_rolls_back(pg_dsn, monkeypatch):
    postgres.migrate(pg_dsn)
    migrations = postgres._migrations()
    monkeypatch.setattr(postgres, "_migrations", lambda: migrations + [(3, "test", "create table incomplete(id int); INVALID SQL;")])
    with pytest.raises(Exception):
        postgres.migrate(pg_dsn)
    with postgres._connection(pg_dsn) as conn:
        assert conn.execute("select to_regclass('autosiem.incomplete') as name").fetchone()["name"] is None
        assert conn.execute("select count(*) as n from schema_migrations").fetchone()["n"] == len(migrations)


def test_pg_tenant_collisions_and_replay_preserve_decisions(pg, result):
    pg.save_pipeline_result(result, "a")
    pg.save_pipeline_result(result, "b")
    incident_id = result.incidents[0].incident_id
    bundle = pg.get_incident_bundle(incident_id, "a")
    assert bundle and bundle["events"] and bundle["findings"] and bundle["proposals"]
    for group in ("events", "findings", "proposals", "comments"):
        assert all(row["tenant_id"] == "a" for row in bundle[group])
    proposal = bundle["proposals"][0]
    assert pg.decide_proposal(proposal["proposal_id"], "approved", tenant_id="missing") is None
    pg.decide_proposal(proposal["proposal_id"], "approved", tenant_id="a")
    pg.update_incident(incident_id, status="closed", assignee="alice", tenant_id="a")
    pg.save_pipeline_result(result, "a")
    again = pg.get_incident_bundle(incident_id, "a")
    assert again["incident"]["status"] == "closed"
    assert len(again["comments"]) == len(bundle["comments"])
    assert next(p for p in again["proposals"] if p["proposal_id"] == proposal["proposal_id"])["status"] == "approved"
    assert all(p["status"] == "pending" for p in pg.get_incident_bundle(incident_id, "b")["proposals"])
    with pytest.raises(ValueError, match="tenant_id"):
        pg.update_incident(incident_id, status="open")
    assert pg.counts("a")["events"] == len(result.events)
    assert pg.search_events(query="POWERSHELL", tenant_id="a")
    assert sum(row["events"] for row in pg.source_stats("a")) == len(result.events)
    assert pg.outbox_stats("sink")["pending"] == 2 * len(result.events)
    assert pg.verify_audit_chain() == []


def test_pg_conflicting_event_rolls_back_entire_result(pg, result):
    pg.save_pipeline_result(result)
    before = pg.counts()
    altered = deepcopy(result)
    altered.events[-1].action = "changed"
    with pytest.raises(ValueError, match="different content"):
        pg.save_pipeline_result(altered)
    assert pg.counts() == before
    assert pg.outbox_stats("sink")["pending"] == len(result.events)


def test_pg_failed_projection_replays_without_logical_duplicates(pg, result):
    pg.save_pipeline_result(result)
    projected = {}
    fail = True

    def deliver(tenant, event_id, document):
        nonlocal fail
        projected[(tenant, event_id)] = document
        if fail:
            fail = False
            raise RuntimeError("simulated crash after sink write before receipt")

    with pytest.raises(RuntimeError, match="simulated"):
        pg.drain_outbox("sink", deliver)
    assert pg.outbox_stats("sink")["pending"] == len(result.events)
    assert pg.drain_outbox("sink", deliver)["delivered"] == len(result.events)
    assert len(projected) == len(result.events)
    assert pg.drain_outbox("sink", deliver)["delivered"] == 0
    assert pg.outbox_stats("sink")["pending"] == 0
    assert pg.outbox_stats("new-destination")["pending"] == len(result.events)


def test_pg_concurrent_triage_and_audit(pg, result):
    pg.save_pipeline_result(result, "a")
    incident_id = result.incidents[0].incident_id
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(pg.update_incident, incident_id, assignee="owner", tenant_id="a"),
                   pool.submit(pg.update_incident, incident_id, resolution="checked", tenant_id="a")]
        for future in futures:
            assert future.result()
    row = pg.get_incident_bundle(incident_id, "a")["incident"]
    assert row["assignee"] == "owner" and row["resolution"] == "checked"
    assert pg.verify_audit_chain() == []


def test_pg_concurrent_final_decisions_and_approval_flags(pg, result):
    pg.save_pipeline_result(result)
    proposals = pg.get_incident_bundle(result.incidents[0].incident_id)["proposals"]
    proposal = next(p for p in proposals if p["approval_required"])
    def decide(decision):
        try:
            return pg.decide_proposal(proposal["proposal_id"], decision)
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        decisions = list(pool.map(decide, ["approved", "rejected"]))
    assert sum(row is not None for row in decisions) == 1
    winner = next(row for row in decisions if row)
    assert winner["approval_required"] == 1 and winner["executable_now"] == 0
    assert pg.verify_audit_chain() == []


def test_pg_concurrent_outbox_workers(pg, result):
    pg.save_pipeline_result(result)
    identities = []
    def deliver(tenant, event_id, doc):
        identities.append((tenant, event_id))
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(pg.drain_outbox, "sink", deliver) for _ in range(3)]
        for future in futures:
            future.result()
    assert len(set(identities)) == len(result.events)
    assert pg.outbox_stats("sink")["pending"] == 0


def test_pg_baseline_conflict_does_not_overwrite_newer_state(pg, pg_dsn):
    other = postgres.PostgresStorage(pg_dsn)
    assert pg.load_baseline("a") is None and other.load_baseline("a") is None
    pg.save_baseline({"new": 1}, "a")
    with pytest.raises(ValueError, match="concurrently"):
        other.save_baseline({"stale": 1}, "a")
    assert other.load_baseline("a") == {"new": 1}


def test_pg_immutable_events_and_audit(pg, result):
    pg.save_pipeline_result(result)
    for sql in ("delete from events", "update audit_log set actor = 'tamper'"):
        with pytest.raises(Exception, match="immutable"):
            with pg.connect() as conn:
                conn.execute(sql)
    assert pg.verify_audit_chain() == []


def test_pg_cli_ingest_and_replay_use_postgres_without_sqlite(pg, pg_dsn, monkeypatch, tmp_path, capsys):
    from autosiem.cli import main
    from autosiem.bus import DurableQueue
    from autosiem.distributed import DistributedPipeline
    monkeypatch.setenv("AUTOSIEM_STORAGE", "postgres")
    monkeypatch.setenv("AUTOSIEM_POSTGRES_DSN", pg_dsn)
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(tmp_path / "queue.db"))
    monkeypatch.setenv("AUTOSIEM_BACKEND", "opensearch")
    monkeypatch.setattr(DistributedPipeline, "_make_backend", lambda *_: pytest.fail("direct projection"))
    sqlite_path = tmp_path / "not_created.db"
    root = Path(__file__).resolve().parents[1]
    event_count = len((root / "examples/events.jsonl").read_text().splitlines())
    monkeypatch.setattr(sys, "argv", ["autosiem", "ingest", "--file", str(root / "examples/events.jsonl"), "--db", str(sqlite_path)])
    main()
    assert not sqlite_path.exists()
    assert pg.counts()["events"] == event_count
    queue = DurableQueue(str(tmp_path / "queue.db"))
    assert queue.pending() == 0
    queue.push("ingest", {"line": json.dumps({"event_id": "replay", "timestamp": "2026-08-04T10:00:00Z", "action": "login_success"})})
    monkeypatch.setattr(sys, "argv", ["autosiem", "distributed", "--replay", "--db", str(sqlite_path)])
    main()
    assert queue.pending() == 0
    assert pg.counts()["events"] == event_count + 1
    assert pg.outbox_stats("sink")["pending"] == event_count + 1
    assert pg.verify_audit_chain() == []


def test_pg_api_auth_approval_conflict_and_outbox_metrics(pg, pg_dsn, result, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from autosiem.web.api import app
    monkeypatch.setenv("AUTOSIEM_STORAGE", "postgres")
    monkeypatch.setenv("AUTOSIEM_POSTGRES_DSN", pg_dsn)
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "not_created.db"))
    monkeypatch.setenv("AUTOSIEM_BACKEND", "opensearch")
    monkeypatch.setenv("AUTOSIEM_BACKEND_URL", "https://example.invalid")
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [
        {"name": "analyst", "role": "analyst", "tenant": "a", "token": "local-test-analyst"},
        {"name": "viewer", "role": "viewer", "tenant": "a", "token": "local-test-viewer"},
        {"name": "other", "role": "analyst", "tenant": "b", "token": "local-test-other"},
    ]}))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", str(users))
    pg.save_pipeline_result(result, "a")
    proposal = next(p for p in pg.get_incident_bundle(result.incidents[0].incident_id, "a")["proposals"] if p["approval_required"])
    client = TestClient(app)
    approve = f"/api/proposals/{proposal['proposal_id']}/approve"
    assert client.post(approve).status_code == 401
    assert client.post(approve, headers={"Authorization": "Bearer local-test-viewer"}).status_code == 403
    assert client.post(approve, headers={"Authorization": "Bearer local-test-other"}).status_code == 404
    headers = {"Authorization": "Bearer local-test-analyst"}
    approved = client.post(approve, headers=headers)
    assert approved.status_code == 200 and approved.json()["executable_now"] == 0
    rejected = client.post(f"/api/proposals/{proposal['proposal_id']}/reject", headers=headers)
    assert rejected.status_code == 409
    metrics = client.get("/metrics", headers=headers)
    assert metrics.status_code == 200
    assert "autosiem_outbox_pending" in metrics.text
    assert not (tmp_path / "not_created.db").exists()


def test_pg_listener_persists_before_queue_ack(pg, pg_dsn, monkeypatch, tmp_path):
    from autosiem import cli
    from autosiem.bus import DurableQueue
    monkeypatch.setenv("AUTOSIEM_STORAGE", "postgres")
    monkeypatch.setenv("AUTOSIEM_POSTGRES_DSN", pg_dsn)
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(tmp_path / "queue.db"))
    monkeypatch.setenv("AUTOSIEM_BACKEND", "sqlite")
    class FakeServer:
        def __init__(self, handler, **kwargs):
            self.handler, self.port = handler, 5514
        def start(self):
            self.handler({"event_id": "syslog-test", "timestamp": "2026-08-04T10:00:00Z", "action": "login_success"})
            assert pg.counts()["events"] == 1
            assert DurableQueue(str(tmp_path / "queue.db")).pending() == 0
            raise KeyboardInterrupt
        def stop(self):
            pass
    monkeypatch.setattr(cli, "SyslogServer", FakeServer)
    monkeypatch.setattr(sys, "argv", ["autosiem", "listen", "--db", str(tmp_path / "not_created.db")])
    cli.main()
    assert pg.outbox_stats("sink")["pending"] == 1


def test_postgres_cli_reports_configuration_instead_of_a_traceback(monkeypatch, capsys):
    """`migrate`/`outbox` crashed with a raw traceback when the DSN was unset."""
    from autosiem.cli import main
    monkeypatch.delenv("AUTOSIEM_POSTGRES_DSN", raising=False)
    for command in ("migrate", "outbox"):
        monkeypatch.setattr(sys, "argv", ["autosiem", command])
        with pytest.raises(SystemExit) as exit_info:
            main()
        assert "AUTOSIEM_POSTGRES_DSN" in str(exit_info.value)
        assert exit_info.value.code != 0
        assert capsys.readouterr().out == ""
    monkeypatch.setenv("AUTOSIEM_POSTGRES_DSN", "dbname=configured")
    monkeypatch.setattr(postgres, "_driver", _no_driver)
    monkeypatch.setattr(sys, "argv", ["autosiem", "migrate"])
    with pytest.raises(SystemExit, match="postgres"):
        main()


def _no_driver():
    raise RuntimeError("PostgreSQL requires the optional autosiem[postgres] extra")


def test_pg_outbox_command_prints_one_document(pg, pg_dsn, result, monkeypatch, capsys):
    """--deliver printed the drain result and the backlog as two documents."""
    from autosiem.cli import main
    delivered: list[str] = []
    pg.save_pipeline_result(result)
    monkeypatch.setenv("AUTOSIEM_POSTGRES_DSN", pg_dsn)
    monkeypatch.setattr("autosiem.projections.projection_from_env",
                        lambda: _StubProjection(delivered))
    monkeypatch.setattr(sys, "argv", ["autosiem", "outbox", "--deliver"])
    main()
    report = json.loads(capsys.readouterr().out)
    assert report["delivered"] == len(delivered) == len(result.events)
    assert report["pending"] == 0


class _StubProjection:
    destination = "stub"

    def __init__(self, delivered: list[str]) -> None:
        self._delivered = delivered

    def deliver(self, tenant: str, event_id: str, document: dict) -> None:
        self._delivered.append(event_id)


def test_pg_text_columns_decode_on_a_sql_ascii_database(pg_dsn):
    """A SQL_ASCII database returned text as bytes, so checksums never matched."""
    driver = postgres._driver()
    base = os.environ["AUTOSIEM_TEST_POSTGRES_DSN"]
    name = "autosiem_ascii_" + uuid4().hex
    with driver.connect(base, autocommit=True) as admin:
        admin.execute(driver.sql.SQL(
            "create database {} encoding 'SQL_ASCII' template template0 lc_collate 'C' lc_ctype 'C'"
        ).format(driver.sql.Identifier(name)))
    try:
        ascii_dsn = driver.conninfo.make_conninfo(base, dbname=name)
        assert postgres.migrate(ascii_dsn) == [v for v, _, _ in postgres._migrations()]
        assert postgres.migrate(ascii_dsn) == []
        postgres.PostgresStorage(ascii_dsn)
    finally:
        with driver.connect(base, autocommit=True) as admin:
            admin.execute(driver.sql.SQL("drop database {}").format(driver.sql.Identifier(name)))


def test_pg_audit_is_tenant_scoped_and_the_chain_still_verifies(pg):
    """PostgresStorage.audit overrode the base signature and dropped tenant_id.

    Every audited write on this path raised TypeError, which the SQLite-only
    profile could not catch.
    """
    with pg.connect() as conn:
        pg.audit(conn, "admin-B", "proposal_approved", "host:secret-b", {}, tenant_id="tenant-b")
        pg.audit(conn, "admin-A", "proposal_approved", "host:secret-a", {}, tenant_id="tenant-a")

    a_targets = {row["target"] for row in pg.list_audit(tenant_id="tenant-a")}
    b_targets = {row["target"] for row in pg.list_audit(tenant_id="tenant-b")}
    assert "host:secret-a" in a_targets and "host:secret-b" not in a_targets
    assert "host:secret-b" in b_targets and "host:secret-a" not in b_targets
    assert len(pg.list_audit()) >= 2      # unscoped read still sees everything
    assert pg.verify_audit_chain() == []  # tenant_id is outside the hashed payload


def test_pg_saving_a_result_audits_without_a_signature_mismatch(pg, result):
    """The regression that broke CI: save_pipeline_result audits with a tenant."""
    pg.save_pipeline_result(result, "tenant-a")
    actions = {row["action"] for row in pg.list_audit(tenant_id="tenant-a")}
    assert "pipeline_result_saved" in actions
    assert pg.list_audit(tenant_id="tenant-b") == []

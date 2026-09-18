"""SEC-005: the audit chain is sealed with a key held outside the database.

The SHA-256 chain alone is tamper-evident, not tamper-proof: a writer with
database access can edit a row and recompute every later hash, and
``audit-verify`` still reports intact. These tests perform exactly that attack
and check that the HMAC seal catches it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import sys

import pytest

import autosiem.storage as storage_module
from autosiem.cli import main
from autosiem.storage import AUDIT_SECRET_ENV, AutoSIEMStorage

KEY = "a-key-that-lives-outside-the-database"


def _write_rows(store: AutoSIEMStorage, count: int, start: int = 0) -> None:
    for i in range(start, start + count):
        store.set_rule_enabled(f"AUTO-RULE-{i:03d}", enabled=bool(i % 2), actor="analyst")


def _rewrite_and_rechain(db_path, audit_id: int, new_actor: str) -> None:
    """The SEC-005 attack: edit one row, then recompute every later hash.

    This is what a database writer without the key can do. The SHA-256 chain
    alone cannot tell the difference afterwards.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("update audit_log set actor = ? where audit_id = ?", (new_actor, audit_id))
    previous = ""
    for row in conn.execute("select * from audit_log order by audit_id asc").fetchall():
        payload = f"{previous}|{row['timestamp']}|{row['actor']}|{row['action']}|{row['target'] or ''}|{row['details']}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        conn.execute("update audit_log set prev_hash = ?, hash = ? where audit_id = ?",
                     (previous, digest, row["audit_id"]))
        previous = digest
    conn.commit()
    conn.close()


def _reasons(mismatches: list[dict]) -> set[str]:
    return {m["reason"] for m in mismatches}


@pytest.fixture(autouse=True)
def _reset_warning_flag(monkeypatch):
    monkeypatch.setattr(storage_module, "_unsealed_warning_issued", False)


def test_rows_are_sealed_when_the_key_is_set(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(AUDIT_SECRET_ENV, KEY)
    store = AutoSIEMStorage(tmp_path / "a.db")
    _write_rows(store, 3)
    rows = store.list_audit()
    assert rows and all(row["mac"] for row in rows)
    assert store.verify_audit_chain() == []
    assert store.audit_seal_summary() == {
        "key_configured": True, "sealed_entries": 3, "unsealed_entries": 0,
    }


def test_the_unsealed_chain_cannot_detect_a_rechained_rewrite(monkeypatch, tmp_path) -> None:
    # The weakness being fixed, stated as a test so it cannot quietly regress
    # into a claim the plain chain does not support.
    monkeypatch.delenv(AUDIT_SECRET_ENV, raising=False)
    db = tmp_path / "b.db"
    store = AutoSIEMStorage(db)
    _write_rows(store, 4)
    _rewrite_and_rechain(db, audit_id=2, new_actor="attacker")
    assert store.verify_audit_chain() == []


def test_the_seal_catches_a_rechained_rewrite(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(AUDIT_SECRET_ENV, KEY)
    db = tmp_path / "c.db"
    store = AutoSIEMStorage(db)
    _write_rows(store, 4)
    _rewrite_and_rechain(db, audit_id=2, new_actor="attacker")
    mismatches = store.verify_audit_chain()
    assert _reasons(mismatches) == {"mac_mismatch"}
    # Row 2 and every row after it: their hashes changed, their MACs did not.
    assert [m["audit_id"] for m in mismatches] == [2, 3, 4]


def test_stripping_seals_from_the_tail_is_a_downgrade(monkeypatch, tmp_path) -> None:
    # A keyless attacker's other move: remove the MACs so rewritten rows look
    # like legacy history. Unsealed rows after a sealed one are refused.
    monkeypatch.setenv(AUDIT_SECRET_ENV, KEY)
    db = tmp_path / "d.db"
    store = AutoSIEMStorage(db)
    _write_rows(store, 4)
    conn = sqlite3.connect(db)
    conn.execute("update audit_log set mac = null where audit_id >= 3")
    conn.commit()
    conn.close()
    mismatches = store.verify_audit_chain()
    assert [(m["audit_id"], m["reason"]) for m in mismatches] == [
        (3, "unsigned_after_signed"), (4, "unsigned_after_signed"),
    ]


def test_legacy_history_is_protected_by_the_first_sealed_row(monkeypatch, tmp_path) -> None:
    # Existing databases keep verifying: unsealed rows written before the key
    # was configured are legal. And because each hash covers every row before
    # it, rewriting that legacy history breaks the first sealed row's MAC.
    monkeypatch.delenv(AUDIT_SECRET_ENV, raising=False)
    db = tmp_path / "e.db"
    store = AutoSIEMStorage(db)
    _write_rows(store, 2)
    monkeypatch.setenv(AUDIT_SECRET_ENV, KEY)
    _write_rows(store, 2, start=2)
    assert store.verify_audit_chain() == []
    assert store.audit_seal_summary()["sealed_entries"] == 2
    assert store.audit_seal_summary()["unsealed_entries"] == 2

    _rewrite_and_rechain(db, audit_id=1, new_actor="attacker")
    mismatches = store.verify_audit_chain()
    assert [(m["audit_id"], m["reason"]) for m in mismatches] == [
        (3, "mac_mismatch"), (4, "mac_mismatch"),
    ]


def test_the_wrong_key_fails_every_sealed_row(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(AUDIT_SECRET_ENV, KEY)
    store = AutoSIEMStorage(tmp_path / "f.db")
    _write_rows(store, 2)
    monkeypatch.setenv(AUDIT_SECRET_ENV, "some-other-key")
    assert _reasons(store.verify_audit_chain()) == {"mac_mismatch"}


def test_without_the_key_rows_are_unsealed_and_it_warns_once(monkeypatch, tmp_path, caplog) -> None:
    monkeypatch.delenv(AUDIT_SECRET_ENV, raising=False)
    store = AutoSIEMStorage(tmp_path / "g.db")
    with caplog.at_level(logging.WARNING, logger="autosiem.storage"):
        _write_rows(store, 3)
    warnings = [r for r in caplog.records if AUDIT_SECRET_ENV in r.getMessage()]
    assert len(warnings) == 1
    assert all(row["mac"] is None for row in store.list_audit())
    assert store.verify_audit_chain() == []
    assert store.audit_seal_summary()["key_configured"] is False


def test_sealed_rows_cannot_be_checked_without_the_key(monkeypatch, tmp_path) -> None:
    # Verification without the key still runs the hash chain, and does not
    # pretend to have checked the seals.
    monkeypatch.setenv(AUDIT_SECRET_ENV, KEY)
    store = AutoSIEMStorage(tmp_path / "h.db")
    _write_rows(store, 2)
    monkeypatch.delenv(AUDIT_SECRET_ENV)
    assert store.verify_audit_chain() == []
    assert store.audit_seal_summary()["key_configured"] is False


def test_an_old_database_gains_the_mac_column(tmp_path) -> None:
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "create table audit_log (audit_id integer primary key autoincrement, timestamp text not null, "
        "actor text not null, action text not null, target text, details text not null, "
        "prev_hash text, hash text)"
    )
    conn.commit()
    conn.close()
    AutoSIEMStorage(db)
    conn = sqlite3.connect(db)
    columns = {row[1] for row in conn.execute("pragma table_info(audit_log)")}
    conn.close()
    assert "mac" in columns


def test_cli_audit_verify_reports_whether_seals_were_checked(capsys, monkeypatch, tmp_path) -> None:
    db = tmp_path / "cli.db"
    monkeypatch.setenv(AUDIT_SECRET_ENV, KEY)
    _write_rows(AutoSIEMStorage(db), 2)

    monkeypatch.setattr(sys, "argv", ["autosiem", "audit-verify", "--db", str(db)])
    main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["intact"] is True
    assert payload["seals_checked"] is True
    assert payload["sealed_entries"] == 2 and payload["unsealed_entries"] == 0

    _rewrite_and_rechain(db, audit_id=1, new_actor="attacker")
    main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["intact"] is False
    assert {m["reason"] for m in payload["mismatches"]} == {"mac_mismatch"}

    # Without the key the same rewrite reads as intact, and the output says
    # the seals were not checked rather than implying they passed.
    monkeypatch.delenv(AUDIT_SECRET_ENV)
    main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["intact"] is True
    assert payload["seals_checked"] is False

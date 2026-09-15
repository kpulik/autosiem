from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

from autosiem.cli import _CONNECTOR_IDENTITY, _connector_config, main

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"


def _run_cli(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, *argv: str) -> str:
    monkeypatch.setattr(sys, "argv", ["autosiem", *argv])
    main()
    return capsys.readouterr().out


def _json(out: str) -> dict:
    # `demo` prints the JSON payload followed by human-readable investigation
    # sections; everything before the marker is pure JSON.
    return json.loads(out.split("\n=== AI Investigation Report ===")[0])


def test_rules_lists_all_rules(capsys, monkeypatch, tmp_path) -> None:
    out = _run_cli(capsys, monkeypatch, "rules", "--rules", str(RULES_DIR), "--db", str(tmp_path / "rules.db"))
    payload = _json(out)
    assert payload["total"] == 19
    rule_ids = {rule["rule_id"] for rule in payload["rules"]}
    assert {"AUTO-AUTH-001", "AUTO-CRED-002", "AUTO-IMPACT-001"} <= rule_ids
    assert all(rule["enabled"] for rule in payload["rules"])
    assert payload["overrides"] == []


def test_rules_disable_persists_state(capsys, monkeypatch, tmp_path) -> None:
    db = tmp_path / "rules.db"
    _run_cli(capsys, monkeypatch, "rules", "--disable", "AUTO-AUTH-001", "--db", str(db))

    out = _run_cli(capsys, monkeypatch, "rules", "--status", "disabled", "--rules", str(RULES_DIR), "--db", str(db))
    payload = _json(out)
    assert payload["total"] == 1
    assert payload["rules"][0]["rule_id"] == "AUTO-AUTH-001"
    assert payload["rules"][0]["enabled"] is False
    assert payload["overrides"][0]["rule_id"] == "AUTO-AUTH-001"

    re_enabled = _run_cli(capsys, monkeypatch, "rules", "--enable", "AUTO-AUTH-001", "--db", str(db))
    assert _json(re_enabled) == {"rule_id": "AUTO-AUTH-001", "enabled": True, "tenant_id": "default"}


def test_demo_respects_disabled_rule(capsys, monkeypatch, tmp_path) -> None:
    db = tmp_path / "demo.db"
    _run_cli(capsys, monkeypatch, "rules", "--disable", "AUTO-AUTH-001", "--db", str(db))
    out = _run_cli(capsys, monkeypatch, "demo", "--db", str(db), "--no-save")
    payload = _json(out)
    # Baseline demo: 15 events / 21 findings (15 detection + 6 anomaly).
    # Disabling AUTO-AUTH-001 removes its single detection finding -> 20.
    assert payload["events"] == 15
    assert payload["findings"] == 20
    assert payload["saved"] is False


def test_rule_new_writes_file_and_test_cases(capsys, monkeypatch, tmp_path) -> None:
    out_dir = tmp_path / "gen"
    db = tmp_path / "rules.db"
    out = _run_cli(
        capsys,
        monkeypatch,
        "rule-new",
        "--description",
        "detect credential dumping by a process",
        "--techniques",
        "T1003",
        "--out-dir",
        str(out_dir),
        "--db",
        str(db),
        "--test-cases",
    )
    payload = _json(out)
    rule = payload["rule"]
    assert rule["id"].startswith("AUTO-GEN-")
    assert rule["mitre_attack"] == ["T1003"]
    assert rule["enabled"] is True
    assert len(payload["test_cases"]) == 2
    written = Path(payload["path"])
    assert written.exists()
    assert json.loads(written.read_text(encoding="utf-8"))["id"] == rule["id"]


def test_search_nl_translates_query(capsys, monkeypatch, tmp_path) -> None:
    db = tmp_path / "search.db"
    out = _run_cli(capsys, monkeypatch, "search-nl", "failed logins by user alice last 24h", "--db", str(db))
    payload = _json(out)
    assert payload["translation"]["entity"] == "user:alice"
    assert payload["translation"]["timeframe"] == "24h"
    assert payload["target"] == "incidents"
    assert any("--entity=user:alice" in flag for flag in payload["cli"])


def test_update_reports_rules_and_coverage(capsys, monkeypatch, tmp_path) -> None:
    db = tmp_path / "update.db"
    out = _run_cli(capsys, monkeypatch, "update", "--rules", str(RULES_DIR), "--db", str(db))
    payload = _json(out)
    assert payload["rules_loaded"] == 19
    # Gaps are reported against the watchlist and alongside its size, so the
    # zero cannot be read as full ATT&CK coverage.
    assert payload["watchlist_gap_count"] == 0
    assert payload["watchlist_size"] == 15
    assert payload["unique_techniques"] >= 16
    assert payload["intel_refreshed"] is False


def test_metrics_exports_prometheus_text(capsys, monkeypatch, tmp_path) -> None:
    db = tmp_path / "metrics.db"
    out = _run_cli(capsys, monkeypatch, "metrics", "--db", str(db))
    assert "autosiem_events 0" in out
    assert "autosiem_findings 0" in out
    assert "autosiem_incidents 0" in out


def test_audit_verify_intact_on_fresh_db(capsys, monkeypatch, tmp_path) -> None:
    db = tmp_path / "audit.db"
    out = _run_cli(capsys, monkeypatch, "audit-verify", "--db", str(db))
    payload = _json(out)
    assert payload["intact"] is True
    assert payload["mismatches"] == []


def test_audit_verify_detects_rule_state_changes_as_intact_chain(capsys, monkeypatch, tmp_path) -> None:
    db = tmp_path / "audit.db"
    _run_cli(capsys, monkeypatch, "rules", "--disable", "AUTO-AUTH-001", "--db", str(db))
    out = _run_cli(capsys, monkeypatch, "audit-verify", "--db", str(db))
    payload = _json(out)
    assert payload["intact"] is True
    assert payload["entries"] >= 1


def test_users_add_lists_roles_and_removes(capsys, monkeypatch, tmp_path) -> None:
    users_file = tmp_path / "users.json"

    # Add a user with a plaintext token; only the hash should be persisted.
    out = _run_cli(capsys, monkeypatch, "users", "add", "--file", str(users_file), "--name", "alice", "--role", "analyst", "--tenant", "acme", "--token", "tok-123")
    payload = _json(out)
    assert payload["added"] == "alice"
    assert payload["token_hashed"] is True
    raw = users_file.read_text(encoding="utf-8")
    assert "tok-123" not in raw
    assert "token_sha256" in raw

    # List shows the user and reports RBAC as enabled.
    out = _run_cli(capsys, monkeypatch, "users", "list", "--file", str(users_file))
    payload = _json(out)
    assert payload["enabled"] is True
    assert payload["users"][0]["name"] == "alice"
    assert payload["users"][0]["tenant"] == "acme"

    # Describe roles.
    out = _run_cli(capsys, monkeypatch, "users", "roles")
    payload = _json(out)
    assert "analyst" in payload["roles"]
    assert "admin" in payload["roles"]

    # Remove persists too.
    out = _run_cli(capsys, monkeypatch, "users", "remove", "--file", str(users_file), "--name", "alice")
    payload = _json(out)
    assert payload["removed"] is True
    out = _run_cli(capsys, monkeypatch, "users", "list", "--file", str(users_file))
    assert _json(out)["enabled"] is False


def test_users_add_rejects_unknown_role(capsys, monkeypatch, tmp_path) -> None:
    users_file = tmp_path / "users.json"
    out = _run_cli(capsys, monkeypatch, "users", "add", "--file", str(users_file), "--name", "x", "--role", "boss", "--token", "t")
    payload = _json(out)
    assert "unknown role" in payload["error"]
    assert not users_file.exists()


# --- connector cursor isolation -------------------------------------------


def _poll_args(connector: str, **overrides: object) -> argparse.Namespace:
    args = argparse.Namespace(
        db="data/autosiem.db", connector=connector, path=None, url=None, org=None,
        token_env=None, since=None, limit=None, max_pages=None, state=None,
        tenant_id=None, client_id=None,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def test_each_remote_source_gets_its_own_cursor_file() -> None:
    """Two orgs sharing one --db shared a cursor AND a seen-id window.

    The second source resumed from the first's cursor and had its own records
    suppressed as already-delivered, which is silent event loss.
    """
    paths = [
        _connector_config(_poll_args("github-api", org="acme"))["state_path"],
        _connector_config(_poll_args("github-api", org="other-corp"))["state_path"],
        _connector_config(_poll_args("okta-api", url="https://a.okta.com"))["state_path"],
        _connector_config(_poll_args("okta-api", url="https://b.okta.com"))["state_path"],
        _connector_config(_poll_args("entra-api", tenant_id="t-1", client_id="c"))["state_path"],
        _connector_config(_poll_args("entra-api", tenant_id="t-2", client_id="c"))["state_path"],
    ]
    assert len(set(paths)) == len(paths)


def test_the_cursor_file_is_stable_for_the_same_source() -> None:
    """A changing filename would replay the lookback window on every poll."""
    first = _connector_config(_poll_args("github-api", org="acme"))["state_path"]
    second = _connector_config(_poll_args("github-api", org="acme"))["state_path"]
    assert first == second
    assert first.endswith("_cursor.json") and "github-api" in first


def test_an_explicit_state_flag_still_wins() -> None:
    config = _connector_config(_poll_args("github-api", org="acme", state="/tmp/mine.json"))
    assert config["state_path"] == "/tmp/mine.json"


def test_a_file_based_connector_gets_no_cursor_file() -> None:
    assert "state_path" not in _connector_config(_poll_args("file", path="/tmp/events.jsonl"))


def test_every_identity_flag_changes_the_cursor_file() -> None:
    """Adding an org/tenant-scoped connector means adding its flag to the key."""
    base_fields = {"org": "acme"}
    base = _connector_config(_poll_args("github-api", **base_fields))["state_path"]
    for field in _CONNECTOR_IDENTITY:
        fields = {**base_fields, field: "different"}
        changed = _connector_config(_poll_args("github-api", **fields))["state_path"]
        assert changed != base, f"{field} does not affect the cursor filename"

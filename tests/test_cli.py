from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from autosiem.cli import _CONNECTOR_IDENTITY, _connector_config, main
from autosiem.storage import open_storage

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
    assert payload["total"] == 29
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
    assert payload["rules_loaded"] == 29
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
    assert "token_hash" in raw
    assert "pbkdf2_sha256$" in raw

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


def test_users_rejects_a_plaintext_users_file_without_a_traceback(capsys, monkeypatch, tmp_path) -> None:
    """A users file carrying a plaintext token is operator configuration.

    The library raises ValueError (SEC-008); the CLI must turn that into a
    one-line message and exit 1, not print a Python traceback. Every earlier
    CLI defect on this project was found exactly here — the tests drove the
    library and never the command.
    """
    users_file = tmp_path / "users.json"
    users_file.write_text(
        json.dumps({"users": [{"name": "bad", "role": "admin", "token": "plain-tok"}]}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(capsys, monkeypatch, "users", "list", "--file", str(users_file))
    message = str(excinfo.value)
    assert "Traceback" not in message
    assert "plaintext" in message and "bad" in message
    assert "token_hash" in message


def test_users_add_writes_a_salted_verifier(capsys, monkeypatch, tmp_path) -> None:
    """`users add` must persist a salted PBKDF2 verifier, never a bare digest."""
    users_file = tmp_path / "users.json"
    _run_cli(capsys, monkeypatch, "users", "add", "--file", str(users_file), "--name", "bo", "--token", "bo-tok")
    raw = users_file.read_text(encoding="utf-8")
    assert "bo-tok" not in raw
    assert "pbkdf2_sha256$" in raw
    assert "token_sha256" not in raw
    # A second user with the SAME token must not share a stored verifier.
    _run_cli(capsys, monkeypatch, "users", "add", "--file", str(users_file), "--name", "cy", "--token", "bo-tok")
    stored = [u["token_hash"] for u in json.loads(users_file.read_text(encoding="utf-8"))["users"]]
    assert len(stored) == 2 and stored[0] != stored[1]


# --- a wedged alternate event backend -----------------------------------------
# urlopen had no timeout, so ingest hung for ever; with one, the failure reached
# the CLI as a BackendError traceback. It is operator configuration, not a crash.


@pytest.fixture
def wedged_backend(monkeypatch, silent_server) -> str:
    import autosiem.backends as backends

    monkeypatch.setattr(backends, "HTTP_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setenv("AUTOSIEM_BACKEND", "opensearch")
    monkeypatch.setenv("AUTOSIEM_BACKEND_URL", silent_server)
    return silent_server


def _one_line_backend_failure(excinfo: pytest.ExceptionInfo[SystemExit]) -> str:
    message = str(excinfo.value)
    assert "OpenSearch request failed: timed out" in message
    assert "\n" not in message and "Traceback" not in message
    return message


def test_ingest_reports_a_wedged_event_backend_in_one_line(capsys, monkeypatch, tmp_path, wedged_backend) -> None:
    db = tmp_path / "wedged.db"
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(capsys, monkeypatch, "ingest", "--file", str(ROOT / "examples" / "events.jsonl"), "--rules", str(RULES_DIR), "--db", str(db))
    message = _one_line_backend_failure(excinfo)
    assert "already saved to the primary database are kept" in message
    assert "queue" not in message, "no queue is configured, so the message must not mention one"
    # The primary store is written before the backend, so nothing was lost.
    assert len(open_storage(db).list_events(limit=100)) == 15


def test_a_no_save_ingest_does_not_claim_anything_was_saved(capsys, monkeypatch, tmp_path, wedged_backend) -> None:
    db = tmp_path / "unsaved.db"
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(capsys, monkeypatch, "ingest", "--no-save", "--file", str(ROOT / "examples" / "events.jsonl"), "--rules", str(RULES_DIR), "--db", str(db))
    message = _one_line_backend_failure(excinfo)
    assert "nothing was saved" in message and "re-ingest" in message
    assert "already saved" not in message
    assert not db.exists()


def test_a_wedged_backend_leaves_the_durable_queue_unacknowledged(capsys, monkeypatch, tmp_path, wedged_backend) -> None:
    from autosiem.bus import DurableQueue

    queue_path = tmp_path / "queue.db"
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(capsys, monkeypatch, "ingest", "--file", str(ROOT / "examples" / "events.jsonl"), "--rules", str(RULES_DIR), "--db", str(tmp_path / "q.db"))
    message = _one_line_backend_failure(excinfo)
    # Replay reprocesses the lines and mints fresh ids, so a retry is not free.
    assert "stay pending" in message and "saves their events and findings again" in message
    assert DurableQueue(str(queue_path)).pending() == 15


def _queue_with_one_pending_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from autosiem.bus import DurableQueue

    queue_path = tmp_path / "replay-queue.db"
    DurableQueue(str(queue_path)).push(
        topic="ingest", payload={"line": json.dumps({"user": "alice", "action": "login"}), "seq": 0}
    )
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))
    return queue_path


def test_distributed_replay_reports_a_wedged_backend_in_one_line(capsys, monkeypatch, tmp_path, wedged_backend) -> None:
    """A backend failure after the save used to leave the lines pending, so the
    next replay saved their events and findings a second time."""
    from autosiem.bus import DurableQueue

    queue_path = _queue_with_one_pending_line(tmp_path, monkeypatch)
    db = tmp_path / "r.db"
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(capsys, monkeypatch, "distributed", "--replay", "--rules", str(RULES_DIR), "--db", str(db))
    message = _one_line_backend_failure(excinfo)
    assert "1 replayed event(s) are in the primary store" in message and "saves nothing twice" in message
    assert DurableQueue(str(queue_path)).pending() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["replay"]["replayed"] == 1 and payload["replay"]["backend_undelivered"] == 1
    rerun = json.loads(_run_cli(capsys, monkeypatch, "distributed", "--replay", "--rules", str(RULES_DIR), "--db", str(db)))
    assert rerun["replay"]["replayed"] == 0, "nothing is pending, so nothing is saved twice"
    assert len(open_storage(db).list_events(limit=10)) == 1


def test_distributed_replay_is_not_capped_at_a_thousand_lines(capsys, monkeypatch, tmp_path) -> None:
    from autosiem.bus import DurableQueue

    queue_path = tmp_path / "big.db"
    queue = DurableQueue(str(queue_path))
    queue.push_many("ingest", [{"line": json.dumps({"user": f"u{i % 7}", "action": "login"}), "seq": i} for i in range(2500)])
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))
    db = tmp_path / "big-store.db"
    payload = json.loads(_run_cli(capsys, monkeypatch, "distributed", "--replay", "--rules", str(RULES_DIR), "--db", str(db)))
    assert payload["replay"]["replayed"] == 2500 and payload["stats"]["queue_pending"] == 0
    assert len(open_storage(db).list_events(limit=5000)) == 2500


def test_distributed_replay_stops_in_one_line_and_saves_nothing_twice(capsys, monkeypatch, tmp_path) -> None:
    from autosiem.bus import DurableQueue
    from autosiem.storage import AutoSIEMStorage

    queue_path = _queue_with_one_pending_line(tmp_path, monkeypatch)
    real_save = AutoSIEMStorage.save_pipeline_result

    def locked(self, result, *args, **kwargs):
        raise sqlite3.OperationalError("database is locked\nforged log line")

    monkeypatch.setattr(AutoSIEMStorage, "save_pipeline_result", locked)
    db = tmp_path / "stopped.db"
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(capsys, monkeypatch, "distributed", "--replay", "--rules", str(RULES_DIR), "--db", str(db))
    message = str(excinfo.value)
    assert message.startswith("replay stopped: OperationalError: database is locked")
    assert "\n" not in message and "1 line(s) still pending; nothing pending was saved" in message
    assert DurableQueue(str(queue_path)).pending() == 1
    monkeypatch.setattr(AutoSIEMStorage, "save_pipeline_result", real_save)
    payload = json.loads(_run_cli(capsys, monkeypatch, "distributed", "--replay", "--rules", str(RULES_DIR), "--db", str(db)))
    assert payload["replay"]["replayed"] == 1
    assert len(open_storage(db).list_events(limit=10)) == 1


def test_a_wedged_backend_does_not_stop_the_listener(capsys, monkeypatch, tmp_path, wedged_backend, caplog) -> None:
    """The backend holds a copy of events only. Aborting startup over it (or,
    later, failing every batch for 30 s) stopped detection for want of a copy."""
    import autosiem.cli as cli
    from autosiem.bus import DurableQueue

    queue_path = _queue_with_one_pending_line(tmp_path, monkeypatch)

    class _Started(_FakeSyslogServer):
        def start(self) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "SyslogServer", _Started)
    db = tmp_path / "l.db"
    with caplog.at_level("WARNING", logger="autosiem.distributed"):
        monkeypatch.setattr(sys, "argv", ["autosiem", "listen", "--port", "0", "--rules", str(RULES_DIR), "--db", str(db)])
        main()
    err = capsys.readouterr().err
    assert [event["user"] for event in open_storage(db).list_events(limit=10)] == ["alice"]
    assert DurableQueue(str(queue_path)).pending() == 0
    assert "event backend unavailable (BackendError)" in caplog.text
    assert "1 stored event(s) never reached the event backend; the primary store has them" in err


# --- cli listen: one pipeline, many worker threads ----------------------------


class _FakeSyslogServer:
    """Captures the handler and drives it from 4 threads, then stops the listener."""

    instances: list["_FakeSyslogServer"] = []

    def __init__(self, handler, host: str = "127.0.0.1", port: int = 0, batch_handler=None) -> None:
        self.handler, self.host, self.port = handler, host, port
        self.batch_handler = batch_handler
        self.failures = 0
        self.failures_by_stage: dict[str, int] = {"parse": 0, "process": 0}
        _FakeSyslogServer.instances.append(self)

    def record_failure(self, stage: str, source, exc: Exception, count: int = 1) -> None:
        self.failures += count
        self.failures_by_stage[stage] = self.failures_by_stage.get(stage, 0) + count

    def start(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        raws = [{"user": f"u{i}", "action": "login", "host": "h1"} for i in range(24)]
        # A queued listener hands bursts over from its receive thread; four
        # threads here make a race in that path show up too.
        burst = self.batch_handler
        deliver = self.handler if burst is None else (lambda raw: burst([raw]))
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(deliver, raws))
        raise KeyboardInterrupt  # what Ctrl+C does to the serve loop

    def stop(self) -> None:
        return None


@pytest.mark.parametrize("with_queue", [False, True], ids=["plain", "queue"])
def test_listener_never_runs_the_pipeline_concurrently(capsys, monkeypatch, tmp_path, with_queue: bool) -> None:
    """The pipeline's baseline, SOAR planner and baseline snapshot are shared
    mutable state; 4 concurrent workers lost about 1 event in 300. The queue
    case goes through DistributedPipeline.run, the path this fix is for."""
    import threading

    import autosiem.cli as cli

    queue_path = tmp_path / "listen-queue.db"
    if with_queue:
        monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))

    active = {"now": 0, "max": 0}
    guard = threading.Lock()
    original = cli.AutoSIEMPipeline.process_lines

    def tracking(self, lines):
        with guard:
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
        try:
            threading.Event().wait(0.01)  # widen the window a race would need
            return original(self, lines)
        finally:
            with guard:
                active["now"] -= 1

    monkeypatch.setattr(cli.AutoSIEMPipeline, "process_lines", tracking)
    monkeypatch.setattr(cli, "SyslogServer", _FakeSyslogServer)
    db = tmp_path / "listen.db"
    _run_cli(capsys, monkeypatch, "listen", "--port", "0", "--rules", str(RULES_DIR), "--db", str(db))
    assert active["max"] == 1
    assert len(open_storage(db).list_events(limit=100)) == 24
    if with_queue:
        from autosiem.bus import DurableQueue

        queue = DurableQueue(str(queue_path))
        assert len(queue) == 24 and queue.pending() == 0


def test_listener_reports_its_failure_count_on_exit(capsys, monkeypatch, tmp_path) -> None:
    import autosiem.cli as cli

    class _Failing(_FakeSyslogServer):
        def start(self) -> None:
            self.failures = 3
            self.failures_by_stage = {"parse": 2, "process": 1}
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "SyslogServer", _Failing)
    monkeypatch.setattr(sys, "argv", ["autosiem", "listen", "--port", "0", "--rules", str(RULES_DIR), "--db", str(tmp_path / "f.db")])
    main()
    err = capsys.readouterr().err
    assert "3 line(s) could not be parsed or processed (parse 2, process 1)" in err
    assert "not every one was logged" in err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_sigterm_stops_the_listener_cleanly_and_prints_the_summary(tmp_path) -> None:
    """docker stop and systemd send SIGTERM; its default skipped `finally`, so
    the listener exited mid-backlog with no failure summary."""
    import signal
    import socket
    import subprocess
    import time

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    import os

    import autosiem

    # Run the same autosiem the test imported, not whatever is on disk at ROOT.
    package_root = Path(autosiem.__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(package_root), "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "autosiem.cli", "listen", "--host", "127.0.0.1", "--port", str(port),
         "--rules", str(RULES_DIR), "--db", str(tmp_path / "term.db")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    )
    try:
        assert proc.stdout is not None
        deadline = time.monotonic() + 20
        while "Listening" not in proc.stdout.readline():
            assert time.monotonic() < deadline and proc.poll() is None, "listener did not start"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for _ in range(3):
                sender.sendto(b"<13>Oct 99 25:61:61 host x", ("127.0.0.1", port))
        time.sleep(1.0)
        proc.send_signal(signal.SIGTERM)
        _out, err = proc.communicate(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    assert proc.returncode == 0, err
    assert "3 line(s) could not be parsed or processed (parse 3)" in err


# --- cli listen: related events share an incident ------------------------------


class _BruteForceServer(_FakeSyslogServer):
    """Feeds one user's failed logins to the listener, then stops it."""

    count = 40

    def start(self) -> None:
        for i in range(self.count):
            self.handler({
                "timestamp": f"2026-08-04T10:{i // 60:02d}:{i % 60:02d}Z", "category": "authentication",
                "action": "login_failed", "outcome": "failure", "user": "mallory", "host": "vpn-1",
                "src_ip": "198.51.100.25",
            })
        raise KeyboardInterrupt


def _incident_count(db: Path) -> int:
    return len(open_storage(db).list_incidents(limit=1000))


def test_listener_correlates_a_burst_into_one_incident(capsys, monkeypatch, tmp_path) -> None:
    """One datagram per process_lines call meant one incident per datagram (1500
    failed logins for one user gave 1500 incidents)."""
    import autosiem.cli as cli

    monkeypatch.setattr(cli, "SyslogServer", _BruteForceServer)
    db = tmp_path / "batched.db"
    _run_cli(capsys, monkeypatch, "listen", "--port", "0", "--rules", str(RULES_DIR), "--db", str(db))
    assert len(open_storage(db).list_events(limit=1000)) == 40
    assert _incident_count(db) == 1


def test_batch_size_one_keeps_per_event_processing(capsys, monkeypatch, tmp_path) -> None:
    import autosiem.cli as cli

    monkeypatch.setattr(cli, "SyslogServer", _BruteForceServer)
    db = tmp_path / "per-event.db"
    _run_cli(capsys, monkeypatch, "listen", "--port", "0", "--batch-size", "1", "--rules", str(RULES_DIR), "--db", str(db))
    assert len(open_storage(db).list_events(limit=1000)) == 40
    # One save per event, and each one joins the incident the first event opened.
    with open_storage(db).connect() as conn:
        saves = conn.execute("select count(*) as n from audit_log where action = 'pipeline_result_saved'").fetchone()["n"]
    assert saves == 40
    assert _incident_count(db) == 1


def test_batch_size_one_without_a_store_has_nothing_to_merge_into(capsys, monkeypatch, tmp_path) -> None:
    import autosiem.cli as cli

    built = []
    real = cli.AutoSIEMPipeline

    def spy(*args, **kwargs):
        built.append(kwargs.get("incident_store"))
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "AutoSIEMPipeline", spy)
    monkeypatch.setattr(cli, "SyslogServer", _BruteForceServer)
    _run_cli(capsys, monkeypatch, "listen", "--port", "0", "--no-save", "--rules", str(RULES_DIR), "--db", str(tmp_path / "ns.db"))
    assert built == [None]



# --- the listener versus a bounded queue -------------------------------------
# With a queue, the receive thread queues each burst and one drainer thread
# processes the queue. A burst that finds the queue full while the drainer works
# waits for room; during an outage the queue's bound refuses lines, counted.


def _listen_with_queue(capsys, monkeypatch, tmp_path, *, max_pending: int, prefill: int = 0, extra: tuple[str, ...] = (), outage: bool = False):
    import sqlite3

    import autosiem.cli as cli
    from autosiem.bus import DurableQueue

    queue_path = tmp_path / "bounded.db"
    queue = DurableQueue(str(queue_path))
    for i in range(prefill):
        queue.push("ingest", {"line": "{}", "seq": i})
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))
    monkeypatch.setenv("AUTOSIEM_QUEUE_MAX_PENDING", str(max_pending))
    monkeypatch.setattr(cli, "SyslogServer", _BruteForceServer)
    if outage:
        def locked(self, *_args, **_kwargs):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(cli.DistributedPipeline, "drain_queue", locked)
    monkeypatch.setattr(sys, "argv", ["autosiem", "listen", "--port", "0", "--rules", str(RULES_DIR), "--db", str(tmp_path / "b.db"), *extra])
    main()
    captured = capsys.readouterr()
    return DurableQueue(str(queue_path)), captured.err, captured.out


def test_a_burst_larger_than_the_queue_limit_is_refused_counted_never_lost(capsys, monkeypatch, tmp_path) -> None:
    """The receive thread never waits for room: while it waited, the kernel
    dropped arriving datagrams with no count anywhere."""
    queue, err, _out = _listen_with_queue(capsys, monkeypatch, tmp_path, max_pending=15)
    stored = len(open_storage(tmp_path / "b.db").list_events(limit=1000))
    refused = 40 - stored
    assert stored >= 15 and queue.pending() == 0
    if refused:
        assert f"{refused} line(s) could not be parsed or processed (queue {refused})" in err


def test_a_full_queue_counts_every_refused_line_instead_of_losing_them_silently(capsys, monkeypatch, tmp_path) -> None:
    queue, err, _out = _listen_with_queue(capsys, monkeypatch, tmp_path, max_pending=5, prefill=5, outage=True)
    assert len(open_storage(tmp_path / "b.db").list_events(limit=1000)) == 0
    assert queue.pending() == 5, "the earlier pending messages are untouched"
    assert "40 line(s) could not be parsed or processed (queue 40)" in err
    assert "5 line(s) still queued; the next start processes them" in err


def test_no_save_with_a_full_queue_does_not_report_a_silent_success(capsys, monkeypatch, tmp_path) -> None:
    _queue, err, _out = _listen_with_queue(capsys, monkeypatch, tmp_path, max_pending=5, prefill=5, extra=("--no-save",), outage=True)
    assert "40 line(s) could not be parsed or processed (queue 40)" in err


def test_lines_queued_by_an_earlier_run_are_processed_at_startup(capsys, monkeypatch, tmp_path) -> None:
    queue, _err, out = _listen_with_queue(capsys, monkeypatch, tmp_path, max_pending=100, prefill=3)
    assert "Processing 3 line(s) queued by an earlier run" in out
    assert len(open_storage(tmp_path / "b.db").list_events(limit=1000)) == 43
    assert queue.pending() == 0


@pytest.mark.parametrize("value", ["inf", "-1", "nan", "1e400", "abc", "86400"])
def test_batch_wait_must_be_a_sane_duration(capsys, monkeypatch, tmp_path, value: str) -> None:
    import autosiem.cli as cli

    class _NeverStart(_FakeSyslogServer):
        def start(self) -> None:  # a regression would start a listener; fail instead of serving for ever
            raise AssertionError("listener started with an invalid argument")

    monkeypatch.setattr(cli, "SyslogServer", _NeverStart)
    monkeypatch.setattr(sys, "argv", ["autosiem", "listen", "--port", "0", "--batch-wait", value, "--db", str(tmp_path / "w.db")])
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 2
    assert "--batch-wait" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["0", "-5", "x"])
def test_batch_size_must_be_a_positive_integer(capsys, monkeypatch, tmp_path, value: str) -> None:
    import autosiem.cli as cli

    class _NeverStart(_FakeSyslogServer):
        def start(self) -> None:  # a regression would start a listener; fail instead of serving for ever
            raise AssertionError("listener started with an invalid argument")

    monkeypatch.setattr(cli, "SyslogServer", _NeverStart)
    monkeypatch.setattr(sys, "argv", ["autosiem", "listen", "--port", "0", "--batch-size", value, "--db", str(tmp_path / "s.db")])
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 2
    assert "--batch-size" in capsys.readouterr().err


def test_the_listener_recovers_from_an_outage_without_new_traffic(capsys, monkeypatch, tmp_path) -> None:
    """The wedge: lines left pending by an outage were never drained in-process,
    so once AUTOSIEM_QUEUE_MAX_PENDING had piled up every datagram was refused."""
    import functools
    import sqlite3

    import autosiem.cli as cli
    from autosiem.bus import DurableQueue

    queue_path = tmp_path / "outage.db"
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))
    monkeypatch.setattr(cli, "QueueDrainer", functools.partial(cli.QueueDrainer, retry_initial=0.02, retry_max=0.05))
    real_drain = cli.DistributedPipeline.drain_queue
    outage = {"left": 3}

    def drain(self, *args, **kwargs):
        if outage["left"]:
            outage["left"] -= 1
            raise sqlite3.OperationalError("database is locked")
        return real_drain(self, *args, **kwargs)

    monkeypatch.setattr(cli.DistributedPipeline, "drain_queue", drain)

    class _OneBurstThenQuiet(_FakeSyslogServer):
        def start(self) -> None:
            assert self.batch_handler is not None, "a queued listener hands over bursts"
            self.batch_handler([{"user": f"u{i}", "action": "login", "host": "h1"} for i in range(10)])
            deadline = time.monotonic() + 5
            while DurableQueue(str(queue_path)).pending() and time.monotonic() < deadline:
                time.sleep(0.02)
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "SyslogServer", _OneBurstThenQuiet)
    db = tmp_path / "outage-store.db"
    _run_cli(capsys, monkeypatch, "listen", "--port", "0", "--rules", str(RULES_DIR), "--db", str(db))
    assert outage["left"] == 0
    assert len(open_storage(db).list_events(limit=100)) == 10
    assert DurableQueue(str(queue_path)).pending() == 0


def test_distributed_requeues_dead_letters(capsys, monkeypatch, tmp_path) -> None:
    from autosiem.bus import DurableQueue

    queue_path = tmp_path / "dead.db"
    queue = DurableQueue(str(queue_path))
    queue.dead_letter(queue.push("ingest", {"line": json.dumps({"user": "alice", "action": "login"}), "seq": 0}))
    monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", str(queue_path))
    payload = json.loads(_run_cli(capsys, monkeypatch, "distributed", "--requeue-dead-letters", "--rules", str(RULES_DIR), "--db", str(tmp_path / "d.db")))
    assert payload["requeued"] == 1
    assert payload["stats"]["queue_pending"] == 1 and payload["stats"]["queue_dead_letters"] == 0


def test_distributed_replay_warns_when_a_saved_line_could_not_be_acknowledged(capsys, monkeypatch, tmp_path) -> None:
    from autosiem.bus import DurableQueue

    _queue_with_one_pending_line(tmp_path, monkeypatch)

    def failing_ack(self, offsets):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(DurableQueue, "ack_many", failing_ack)
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(capsys, monkeypatch, "distributed", "--replay", "--rules", str(RULES_DIR), "--db", str(tmp_path / "ack.db"))
    assert "1 of them were saved before the queue could acknowledge them, so replaying again saves those a second time" in str(excinfo.value)

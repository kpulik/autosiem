"""SEC-016 (b): files holding secrets or telemetry are owner-only (0600).

The users file carries PBKDF2 token verifiers, and the database, archive
journal and durable queue carry raw events (usernames, IPs, command lines).
Before the fix they were created with umask permissions, commonly 0644, so any
local account could read them.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from autosiem.archive import JournalFile
from autosiem.bus import DurableQueue
from autosiem.rbac import Rbac
from autosiem.storage import AutoSIEMStorage
from autosiem.threat_intel import StixIndicator, save_intel_state

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture(autouse=True)
def permissive_umask():
    """Run under the common 022 umask, which is what produced 0644 files."""
    previous = os.umask(0o022)
    yield
    os.umask(previous)


def test_users_file_is_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "users.json"
    rbac = Rbac()
    rbac.add_user("alice", role="admin", token="t0ken-for-alice")
    rbac.save(target)
    assert _mode(target) == 0o600


def test_rewriting_a_world_readable_users_file_tightens_it(tmp_path: Path) -> None:
    target = tmp_path / "users.json"
    target.write_text('{"users": []}\n', encoding="utf-8")
    target.chmod(0o644)
    rbac = Rbac()
    rbac.add_user("alice", role="admin", token="t0ken-for-alice")
    rbac.save(target)
    assert _mode(target) == 0o600
    assert Rbac.load(target).authenticate("t0ken-for-alice") is not None
    assert not list(tmp_path.glob("*.tmp")), "temporary file left behind"


def test_intel_state_is_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "siem.db.intel.json"
    save_intel_state(target, [StixIndicator(indicator_id="indicator--1", name="bad ip", pattern="[ipv4-addr:value = '203.0.113.9']")])
    assert _mode(target) == 0o600


def test_new_database_is_owner_only(tmp_path: Path) -> None:
    db = tmp_path / "data" / "autosiem.db"
    AutoSIEMStorage(db)
    assert _mode(db) == 0o600


def test_an_existing_database_keeps_the_operators_mode(tmp_path: Path) -> None:
    """Only files AutoSIEM creates are tightened; an operator's chmod stands."""
    db = tmp_path / "shared.db"
    AutoSIEMStorage(db)
    db.chmod(0o640)
    AutoSIEMStorage(db)
    assert _mode(db) == 0o640


def test_archive_journal_is_owner_only(tmp_path: Path) -> None:
    journal = tmp_path / "archive.jsonl"
    JournalFile(str(journal)).append({"user": "alice"})
    assert _mode(journal) == 0o600


def test_durable_queue_is_owner_only(tmp_path: Path) -> None:
    queue = tmp_path / "queue.db"
    DurableQueue(str(queue))
    assert _mode(queue) == 0o600


def test_in_memory_queue_still_works() -> None:
    DurableQueue(":memory:")

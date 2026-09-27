"""Identity roles: an account's normal job is turned down, never hidden.

The guard tests matter more than the happy path. A role is a label an operator
types into a file, and it must not be able to quiet credential theft,
ransomware, log clearing or data leaving the network - nor protect an account
that has been disabled, nor excuse anything the account does off its list.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from autosiem.enrichment import (
    NEVER_ROUTINE,
    ROLE_PROFILES,
    EnrichmentRegistry,
    IdentityEnricher,
)
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules
from autosiem.schemas import Severity

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "rules")


def _proc(user: str, name: str, cmd: str, ts: str = "2026-09-27T01:00:00Z") -> str:
    return json.dumps({"timestamp": ts, "category": "process", "action": "process_start", "user": user,
                       "host": "srv-01", "process_name": name, "command_line": cmd, "outcome": "success"})


SHADOW = "vssadmin create shadow /for=C:"
MIMIKATZ = "mimikatz.exe sekurlsa::logonpasswords"


def _run(identities: list[dict], lines: list[str]):
    registry = EnrichmentRegistry([IdentityEnricher(identities)])
    return AutoSIEMPipeline(RULES, enrichment=registry).process_lines(lines)


def _finding(result, rule_id: str):
    return next(f for f in result.findings if f.rule_id == rule_id)


# --- the job gets turned down --------------------------------------------------


def test_a_backup_account_creating_a_shadow_copy_is_turned_down_not_dropped() -> None:
    result = _run([{"username": "svc-backup", "role": "backup"}], [_proc("svc-backup", "vssadmin.exe", SHADOW)])
    finding = _finding(result, "AUTO-CRED-004")
    assert finding.severity == Severity.LOW
    assert finding.risk_points == 9  # 35 * 0.25, rounded
    expected = finding.evidence["expected_activity"]
    assert expected == {
        "entity": "user:svc-backup", "role": "backup", "rule_id": "AUTO-CRED-004",
        "original_severity": "medium", "original_risk_points": 35,
    }
    # Still there: an analyst can see it and why it was turned down.
    assert result.incidents


def test_without_a_role_nothing_changes() -> None:
    result = _run([{"username": "svc-backup"}], [_proc("svc-backup", "vssadmin.exe", SHADOW)])
    finding = _finding(result, "AUTO-CRED-004")
    assert finding.severity == Severity.MEDIUM
    assert finding.risk_points == 35
    assert "expected_activity" not in finding.evidence


def test_a_role_only_covers_the_account_it_is_on() -> None:
    result = _run(
        [{"username": "svc-backup", "role": "backup"}],
        [_proc("priya", "vssadmin.exe", SHADOW)],
    )
    assert _finding(result, "AUTO-CRED-004").severity == Severity.MEDIUM


def test_a_privileged_role_account_is_not_doubled_back_up() -> None:
    # Privileged identities get the critical x2.0 multiplier; routine activity
    # skips it, or a privileged backup account doing its backup would score
    # higher than an ordinary user.
    result = _run(
        [{"username": "svc-backup", "role": "backup", "privileged": True}],
        [_proc("svc-backup", "vssadmin.exe", SHADOW)],
    )
    assert _finding(result, "AUTO-CRED-004").risk_points == 9


def test_expected_rules_extend_a_role_per_account() -> None:
    result = _run(
        [{"username": "svc-inventory", "expected_rules": ["AUTO-DISCO-001"]}],
        [_proc("svc-inventory", "systeminfo.exe", "systeminfo")],
    )
    finding = _finding(result, "AUTO-DISCO-001")
    assert finding.severity == Severity.LOW
    assert finding.evidence["expected_activity"]["role"] == "custom"


# --- the guards ----------------------------------------------------------------


def test_anything_off_the_list_still_scores_in_full_and_escalates() -> None:
    # The point of roles over blanket allowlists: a compromised backup account
    # dumping credentials is not "doing backups".
    result = _run(
        [{"username": "svc-backup", "role": "backup"}],
        [_proc("svc-backup", "vssadmin.exe", SHADOW, "2026-09-27T01:00:00Z"),
         _proc("svc-backup", "mimikatz.exe", MIMIKATZ, "2026-09-27T01:05:00Z")],
    )
    dump = _finding(result, "AUTO-CRED-002")
    assert dump.severity == Severity.CRITICAL
    assert "expected_activity" not in dump.evidence
    assert result.incidents[0].severity == Severity.CRITICAL


def test_a_critical_rule_can_never_be_listed_away() -> None:
    result = _run(
        [{"username": "svc-backup", "role": "backup", "expected_rules": ["AUTO-CRED-003", "AUTO-CRED-002"]}],
        [_proc("svc-backup", "ntdsutil.exe", 'ntdsutil "ac i ntds" ifm "create full c:\\temp" q q')],
    )
    finding = _finding(result, "AUTO-CRED-003")
    assert finding.severity == Severity.CRITICAL
    assert "expected_activity" not in finding.evidence


@pytest.mark.parametrize("rule_id,cmd", [
    ("AUTO-DEFEV-002", "wevtutil cl security"),
    ("AUTO-DEFEV-004", "powershell Set-MpPreference -DisableRealtimeMonitoring $true"),
])
def test_never_routine_rules_ignore_expected_rules(rule_id: str, cmd: str) -> None:
    result = _run(
        [{"username": "it-marco", "role": "it-admin", "expected_rules": [rule_id]}],
        [_proc("it-marco", "cmd.exe", cmd)],
    )
    finding = _finding(result, rule_id)
    assert finding.severity > Severity.LOW
    assert "expected_activity" not in finding.evidence


def test_a_disabled_account_gets_no_role_benefit() -> None:
    result = _run(
        [{"username": "svc-backup", "role": "backup", "status": "disabled"}],
        [_proc("svc-backup", "vssadmin.exe", SHADOW)],
    )
    finding = _finding(result, "AUTO-CRED-004")
    assert "expected_activity" not in finding.evidence
    assert finding.severity == Severity.MEDIUM


def test_an_unknown_role_downgrades_nothing() -> None:
    # A typo ("backups") must not silently fall back to anything permissive.
    result = _run([{"username": "svc-backup", "role": "backups"}], [_proc("svc-backup", "vssadmin.exe", SHADOW)])
    assert _finding(result, "AUTO-CRED-004").severity == Severity.MEDIUM


# --- the profiles themselves --------------------------------------------------


def test_every_profile_names_real_non_critical_rules() -> None:
    # A renamed or deleted rule would otherwise leave a profile that silently
    # covers nothing, and a critical rule in a profile would be a hole.
    by_id = {rule.rule_id: rule for rule in RULES}
    for role, rules in ROLE_PROFILES.items():
        for rule_id in rules:
            assert rule_id in by_id, f"role {role!r} lists unknown rule {rule_id}"
            assert by_id[rule_id].severity < Severity.CRITICAL, f"role {role!r} lists critical rule {rule_id}"
            assert rule_id not in NEVER_ROUTINE, f"role {role!r} lists never-routine rule {rule_id}"


def test_the_role_is_visible_in_enrichment_context() -> None:
    registry = EnrichmentRegistry([IdentityEnricher([{"username": "gha-deploy", "role": "ci-deploy"}])])
    context = registry.context_for(["user:gha-deploy"])["user:gha-deploy"][0]
    assert context["attributes"]["role"] == "ci-deploy"

"""SigmaHQ rule sync.

The zip is built in-memory from rule text, so the suite stays offline. Field
names mirror the real bundle, verified against SigmaHQ r2026-07-01 on
2026-08-11: 1377 rules, 176 runnable, 71 unsupported syntax.
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from autosiem.rules import load_rules
from autosiem.schemas import DetectionRule, Severity
from autosiem.sigma_sync import (
    RELEASES_URL,
    SYNC_MANIFEST,
    SigmaRelease,
    classify_rule,
    default_sigma_dir,
    latest_release,
    load_synced_rules,
    matchable_fields,
    merge_rules,
    sync_rules,
)

ROOT = Path(__file__).resolve().parents[1]

RUNNABLE = """
title: Suspicious Encoded PowerShell
id: 11111111-1111-1111-1111-111111111111
status: stable
description: Encoded command line
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    condition: selection
"""

# Matches on a Windows field the normalized event model does not carry, so it
# would import cleanly and then never fire.
NOT_APPLICABLE = """
title: Registry Persistence
id: 22222222-2222-2222-2222-222222222222
level: high
tags:
    - attack.persistence
    - attack.t1547
logsource:
    category: registry_set
detection:
    selection:
        TargetObject|contains: '\\CurrentVersion\\Run'
        EventID: 13
    condition: selection
"""

# List-form selection: OR across different operators, which the subset parser
# does not read and the detection engine could not represent anyway.
UNSUPPORTED = """
title: Proxy Flash Download
id: 33333333-3333-3333-3333-333333333333
level: medium
tags:
    - attack.command-and-control
logsource:
    category: proxy
detection:
    selection:
        - c-uri|contains: '/flash_install.php'
        - c-uri|endswith: '/install_flash_player.exe'
    condition: selection
"""

SECOND_RUNNABLE = """
title: Credential Dumper Executed
id: 44444444-4444-4444-4444-444444444444
level: critical
tags:
    - attack.credential-access
    - attack.t1003
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\mimikatz.exe'
    condition: selection
"""

RELEASE_JSON = {
    "tag_name": "r2026-07-01",
    "published_at": "2026-07-09T00:00:00Z",
    "assets": [
        {"name": "sigma_core.zip", "browser_download_url": "https://example.test/sigma_core.zip"},
        {"name": "sigma_all_rules.zip", "browser_download_url": "https://example.test/sigma_all_rules.zip"},
    ],
}


def _zip_bytes(rules: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in rules.items():
            archive.writestr(name, text)
        archive.writestr("rules/README.md", "not a rule")
    return buffer.getvalue()


DEFAULT_BUNDLE = {
    "rules/windows/process_creation/enc_powershell.yml": RUNNABLE,
    "rules/windows/registry/persistence.yml": NOT_APPLICABLE,
    "rules/web/proxy/flash.yml": UNSUPPORTED,
    "rules/windows/process_creation/mimikatz.yml": SECOND_RUNNABLE,
}


def _fetch(bundle: dict[str, str] | None = None, calls: list[str] | None = None):
    payload = _zip_bytes(DEFAULT_BUNDLE if bundle is None else bundle)

    def fetch(url: str) -> bytes:
        if calls is not None:
            calls.append(url)
        if url == RELEASES_URL:
            return json.dumps(RELEASE_JSON).encode()
        if url.endswith(".zip"):
            return payload
        raise AssertionError(f"unexpected fetch: {url}")

    return fetch


# --------------------------------------------------------------------------
# applicability: the whole point
# --------------------------------------------------------------------------


def test_matchable_fields_come_from_the_event_model() -> None:
    fields = matchable_fields()
    assert {"process_name", "command_line", "user", "host", "src_ip"} <= fields
    # `raw` is handled by prefix, not as a top-level field.
    assert "raw" not in fields


def _rule(selection: dict) -> DetectionRule:
    return DetectionRule("R", "R", "", Severity.HIGH, 75, selection)


def test_rule_using_only_known_fields_is_applicable() -> None:
    applicable, missing = classify_rule(
        _rule({"process_name": {"endswith": ".exe"}, "user": "alice"}), matchable_fields()
    )
    assert applicable is True
    assert missing == set()


def test_rule_using_an_unknown_field_is_not_applicable() -> None:
    """This is the rule that would import cleanly and never fire."""
    applicable, missing = classify_rule(
        _rule({"process_name": "x.exe", "TargetObject": {"contains": "Run"}}), matchable_fields()
    )
    assert applicable is False
    assert missing == {"TargetObject"}


def test_raw_prefixed_fields_count_as_matchable() -> None:
    applicable, missing = classify_rule(_rule({"raw.message": {"contains": "x"}}), matchable_fields())
    assert applicable is True
    assert missing == set()


def test_rule_with_no_fields_is_not_applicable() -> None:
    applicable, _ = classify_rule(_rule({}), matchable_fields())
    assert applicable is False


# --------------------------------------------------------------------------
# release resolution
# --------------------------------------------------------------------------


def test_latest_release_resolves_the_requested_bundle() -> None:
    release = latest_release(fetch=_fetch())
    assert release.tag == "r2026-07-01"
    assert release.ruleset == "sigma_core.zip"
    assert release.url.startswith("https://")


def test_unknown_ruleset_is_an_explicit_error() -> None:
    with pytest.raises(ValueError, match="has no asset"):
        latest_release("sigma_nonexistent.zip", fetch=_fetch())


def test_sync_refuses_a_plaintext_bundle_url() -> None:
    payload = dict(RELEASE_JSON)
    payload["assets"] = [{"name": "sigma_core.zip", "browser_download_url": "http://example.test/x.zip"}]

    def fetch(url: str) -> bytes:
        assert url == RELEASES_URL
        return json.dumps(payload).encode()

    with pytest.raises(ValueError, match="non-HTTPS"):
        sync_rules("/tmp/unused-sigma", fetch=fetch)


# --------------------------------------------------------------------------
# sync
# --------------------------------------------------------------------------


def test_sync_sorts_rules_into_three_honest_buckets(tmp_path: Path) -> None:
    report = sync_rules(tmp_path / "synced", fetch=_fetch())
    assert report.candidates == 4
    assert report.imported == 2
    assert report.not_applicable == 1
    assert report.unsupported_syntax == 1
    assert report.candidates == report.imported + report.not_applicable + report.unsupported_syntax


def test_sync_reports_which_fields_blocked_import(tmp_path: Path) -> None:
    """Turns "why is coverage low" into a ranked list of normalizer work."""
    report = sync_rules(tmp_path / "synced", fetch=_fetch())
    # The Sigma parser lowercases field names on the way in.
    assert "targetobject" in report.missing_fields or "eventid" in report.missing_fields
    assert all(count >= 1 for count in report.missing_fields.values())


def test_sync_records_unsupported_syntax_with_a_sample(tmp_path: Path) -> None:
    report = sync_rules(tmp_path / "synced", fetch=_fetch())
    assert report.syntax_samples
    assert "flash.yml" in report.syntax_samples[0]


def test_synced_rules_round_trip_through_the_normal_loader(tmp_path: Path) -> None:
    """Written rules must load exactly like a curated rule file."""
    dest = tmp_path / "synced"
    sync_rules(dest, fetch=_fetch())
    errors: list[str] = []
    rules = load_synced_rules(dest, errors=errors)
    assert errors == []
    assert len(rules) == 2
    assert {rule.rule_id for rule in rules} == {
        "11111111-1111-1111-1111-111111111111",
        "44444444-4444-4444-4444-444444444444",
    }
    assert any("T1059.001" in rule.mitre_attack for rule in rules)


def test_manifest_is_written_and_not_loaded_as_a_rule(tmp_path: Path) -> None:
    dest = tmp_path / "synced"
    sync_rules(dest, fetch=_fetch())
    manifest = json.loads((dest / SYNC_MANIFEST).read_text())
    assert manifest["imported"] == 2
    assert manifest["release"] == "r2026-07-01"
    assert all(rule.rule_id != SYNC_MANIFEST for rule in load_synced_rules(dest))


def test_sync_replaces_previous_content(tmp_path: Path) -> None:
    """A stale rule from an earlier release must not linger."""
    dest = tmp_path / "synced"
    sync_rules(dest, fetch=_fetch())
    (dest / "stale-rule.json").write_text(
        json.dumps({"id": "STALE", "name": "Stale", "selection": {"user": "x"}}), encoding="utf-8"
    )
    assert len(load_synced_rules(dest)) == 3
    sync_rules(dest, fetch=_fetch())
    assert "STALE" not in {rule.rule_id for rule in load_synced_rules(dest)}


def test_limit_caps_writes_without_hiding_the_real_total(tmp_path: Path) -> None:
    """A cap must never masquerade as "that is all there was"."""
    report = sync_rules(tmp_path / "synced", fetch=_fetch(), limit=1)
    assert report.imported == 1
    assert report.candidates == 4
    assert report.not_applicable == 1


def test_corrupt_synced_file_is_reported_not_swallowed(tmp_path: Path) -> None:
    dest = tmp_path / "synced"
    sync_rules(dest, fetch=_fetch())
    (dest / "broken.json").write_text("{not json", encoding="utf-8")
    errors: list[str] = []
    rules = load_synced_rules(dest, errors=errors)
    assert len(rules) == 2
    assert len(errors) == 1
    assert "broken.json" in errors[0]


def test_missing_directory_is_empty_not_an_error(tmp_path: Path) -> None:
    assert load_synced_rules(tmp_path / "absent") == []
    assert load_synced_rules(None) == []


def test_default_sigma_dir_matches_the_state_file_convention() -> None:
    assert default_sigma_dir("/var/lib/autosiem/prod.db") == Path("/var/lib/autosiem/prod.sigma")


# --------------------------------------------------------------------------
# merge
# --------------------------------------------------------------------------


def test_curated_rules_win_on_a_rule_id_collision() -> None:
    """Third-party content never silently replaces a rule this project tested."""
    curated = _rule({"user": "curated"})
    synced = DetectionRule("R", "Synced", "", Severity.LOW, 10, {"user": "synced"})
    merged = merge_rules([curated], [synced])
    assert len(merged) == 1
    assert merged[0].name == "R"
    assert merged[0].selection == {"user": "curated"}


def test_merge_keeps_distinct_rules() -> None:
    curated = load_rules(ROOT / "rules")
    synced = [DetectionRule("SIGMA-1", "S", "", Severity.LOW, 10, {"user": "x"})]
    merged = merge_rules(curated, synced)
    assert len(merged) == len(curated) + 1


def test_synced_rules_actually_fire(tmp_path: Path) -> None:
    """The claim the whole applicability filter exists to make good on."""
    from autosiem.pipeline import AutoSIEMPipeline

    dest = tmp_path / "synced"
    sync_rules(dest, fetch=_fetch())
    synced = load_synced_rules(dest)
    event = json.dumps(
        {
            "timestamp": "2026-08-04T10:06:00Z",
            "category": "process",
            "action": "process_start",
            "user": "alice",
            "host": "ws-1",
            # Full path, as Sysmon's Image field supplies: the rule matches on
            # `endswith "\\powershell.exe"`, which is what SigmaHQ rules expect.
            "process_name": "C:\\Windows\\System32\\powershell.exe",
            "command_line": "powershell -enc SQBFAFgA",
        }
    )
    result = AutoSIEMPipeline(synced).process_lines([event])
    assert any(f.rule_id == "11111111-1111-1111-1111-111111111111" for f in result.findings)

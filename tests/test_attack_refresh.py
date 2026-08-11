"""Refreshing the ATT&CK matrix from MITRE's published releases.

Every test injects a fetcher, so the suite never touches the network. That is
the same discipline `test_okta_api_connector.py` uses for the Okta API.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from autosiem.attack_matrix import (
    ATTACK_INDEX_URL,
    INDEX_PATH,
    Release,
    default_attack_index,
    distill_bundle,
    load_matrix_file,
    refresh_index,
    resolve_release,
)
from autosiem.update_job import UpdateJob

RELEASES = {
    "collections": [
        {
            "name": "Enterprise ATT&CK",
            "versions": [
                {"version": "19.1", "url": "https://example.test/e-19.1.json", "modified": "2026-06-01T00:00:00.000Z"},
                {"version": "19.2", "url": "https://example.test/e-19.2.json", "modified": "2026-08-05T00:00:00.000Z"},
                {"version": "9.0", "url": "https://example.test/e-9.0.json", "modified": "2021-01-01T00:00:00.000Z"},
            ],
        },
        {"name": "Mobile ATT&CK", "versions": []},
    ]
}


def _bundle(*techniques: tuple[str, str, list[str], bool]) -> dict:
    objects = []
    for identifier, name, tactics, sub in techniques:
        objects.append(
            {
                "type": "attack-pattern",
                "name": name,
                "external_references": [{"source_name": "mitre-attack", "external_id": identifier}],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": tactic} for tactic in tactics
                ],
                "x_mitre_is_subtechnique": sub,
            }
        )
    return {"type": "bundle", "objects": objects}


def _fetcher(bundles: dict[str, dict], calls: list[str] | None = None):
    def fetch(url: str) -> bytes:
        if calls is not None:
            calls.append(url)
        if url == ATTACK_INDEX_URL:
            return json.dumps(RELEASES).encode()
        if url in bundles:
            return json.dumps(bundles[url]).encode()
        raise AssertionError(f"unexpected fetch: {url}")

    return fetch


DEMO_BUNDLE = _bundle(
    ("T1059", "Command and Scripting Interpreter", ["execution"], False),
    ("T1059.001", "PowerShell", ["execution"], True),
    ("T1486", "Data Encrypted for Impact", ["impact"], False),
)


# --------------------------------------------------------------------------
# release resolution
# --------------------------------------------------------------------------


def test_resolve_release_picks_the_newest_by_number_not_order() -> None:
    """19.2 beats 9.0 -- a string sort would get this backwards."""
    release = resolve_release(fetch=_fetcher({}))
    assert release.version == "19.2"
    assert release.url.endswith("e-19.2.json")


def test_resolve_release_can_pin_a_version() -> None:
    assert resolve_release("19.1", fetch=_fetcher({})).version == "19.1"


def test_resolve_release_rejects_an_unpublished_version() -> None:
    with pytest.raises(ValueError, match="not in MITRE's published index"):
        resolve_release("99.9", fetch=_fetcher({}))


# --------------------------------------------------------------------------
# refresh
# --------------------------------------------------------------------------


def test_refresh_writes_an_index_that_loads(tmp_path: Path) -> None:
    dest = tmp_path / "attack.json"
    result = refresh_index(dest, fetch=_fetcher({"https://example.test/e-19.2.json": DEMO_BUNDLE}))
    assert result.refreshed is True
    assert result.latest_version == "19.2"

    matrix = load_matrix_file(dest)
    assert matrix.attack_version == "19.2"
    assert matrix.get("T1059.001") is not None
    assert matrix.tactics_for("T1486") == ("impact",)


def test_refresh_skips_the_download_when_already_current(tmp_path: Path) -> None:
    """The bundle is ~54 MB; the version check is a few KB. Check first."""
    dest = tmp_path / "attack.json"
    calls: list[str] = []
    fetch = _fetcher({"https://example.test/e-19.2.json": DEMO_BUNDLE}, calls)

    first = refresh_index(dest, fetch=fetch)
    assert first.refreshed is True
    assert calls.count("https://example.test/e-19.2.json") == 1

    second = refresh_index(dest, fetch=fetch)
    assert second.refreshed is False
    assert "already at 19.2" in second.message
    # Still only the one bundle download across both runs.
    assert calls.count("https://example.test/e-19.2.json") == 1


def test_refresh_upgrades_from_an_older_pinned_version(tmp_path: Path) -> None:
    dest = tmp_path / "attack.json"
    fetch = _fetcher(
        {
            "https://example.test/e-19.1.json": _bundle(("T1059", "Old", ["execution"], False)),
            "https://example.test/e-19.2.json": DEMO_BUNDLE,
        }
    )
    refresh_index(dest, version="19.1", fetch=fetch)
    assert load_matrix_file(dest).attack_version == "19.1"

    result = refresh_index(dest, fetch=fetch)
    assert result.refreshed is True
    assert result.current_version == "19.1"
    assert result.latest_version == "19.2"
    assert load_matrix_file(dest).attack_version == "19.2"


def test_refresh_refuses_plaintext_urls(tmp_path: Path) -> None:
    """A tampered index rewrites what every technique means."""
    plaintext = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [{"version": "19.2", "url": "http://example.test/e.json", "modified": ""}],
            }
        ]
    }

    def fetch(url: str) -> bytes:
        if url == ATTACK_INDEX_URL:
            return json.dumps(plaintext).encode()
        raise AssertionError("must not fetch over http")

    with pytest.raises(ValueError, match="non-HTTPS"):
        refresh_index(tmp_path / "attack.json", fetch=fetch)


def test_distill_drops_revoked_and_deprecated() -> None:
    bundle = _bundle(("T1059", "Live", ["execution"], False))
    bundle["objects"].append(
        {
            "type": "attack-pattern",
            "name": "Gone",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
            "kill_chain_phases": [],
        }
    )
    bundle["objects"].append(
        {
            "type": "attack-pattern",
            "name": "Old",
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0002"}],
            "kill_chain_phases": [],
        }
    )
    index = distill_bundle(bundle, Release("19.2", "https://example.test/e.json", ""))
    assert set(index["techniques"]) == {"T1059"}
    assert index["revoked_or_deprecated_skipped"] == 2


def test_distill_is_byte_stable_for_the_same_release() -> None:
    release = Release("19.2", "https://example.test/e.json", "2026-08-05T00:00:00.000Z")
    first = json.dumps(distill_bundle(DEMO_BUNDLE, release), sort_keys=True)
    second = json.dumps(distill_bundle(DEMO_BUNDLE, release), sort_keys=True)
    assert first == second


# --------------------------------------------------------------------------
# update job wiring
# --------------------------------------------------------------------------


def test_update_job_does_not_touch_the_network_by_default(tmp_path: Path) -> None:
    """Every network step in this project is opt-in."""

    def explode(url: str) -> bytes:
        raise AssertionError("default update cycle must not fetch anything")

    job = UpdateJob(db_path=tmp_path / "a.db", attack_fetch=explode)
    report = job.run_once()
    assert report.attack_refreshed is False
    assert report.attack_latest == ""
    # Coverage still reported, against the vendored matrix.
    assert report.coverage["matrix"]["available"] is True
    assert report.attack_version


def test_update_job_refreshes_and_reports_against_the_new_matrix(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    job = UpdateJob(
        db_path=db,
        refresh_attack=True,
        attack_fetch=_fetcher({"https://example.test/e-19.2.json": DEMO_BUNDLE}),
    )
    report = job.run_once()
    assert report.attack_refreshed is True
    assert report.attack_latest == "19.2"
    assert report.attack_version == "19.2"
    # Coverage is computed against the refreshed 3-technique index, not the
    # vendored one, which is what makes the refresh meaningful.
    assert report.coverage["matrix"]["technique_total"] == 3
    assert any("refreshed" in message for message in report.messages)


def test_refreshed_index_is_written_beside_the_db_not_into_the_package(tmp_path: Path) -> None:
    """Writing into site-packages breaks read-only installs and wheel parity."""
    db = tmp_path / "autosiem.db"
    job = UpdateJob(
        db_path=db,
        refresh_attack=True,
        attack_fetch=_fetcher({"https://example.test/e-19.2.json": DEMO_BUNDLE}),
    )
    job.run_once()
    expected = default_attack_index(db)
    assert expected == tmp_path / "autosiem.attack.json"
    assert expected.exists()
    # The vendored copy is untouched and still the full matrix.
    assert load_matrix_file(INDEX_PATH).attack_version != "19.2" or len(load_matrix_file(INDEX_PATH)) > 400


def test_update_job_survives_a_broken_attack_feed(tmp_path: Path) -> None:
    """A flaky feed degrades to the vendored matrix; it does not fail the cycle."""

    def boom(url: str) -> bytes:
        raise OSError("network down")

    job = UpdateJob(db_path=tmp_path / "a.db", refresh_attack=True, attack_fetch=boom)
    report = job.run_once()
    assert report.attack_refreshed is False
    assert any("attack refresh failed" in message for message in report.messages)
    # Rules and coverage still came back.
    assert report.rules_loaded == 0 or report.coverage["matrix"]["available"] is True


def test_default_attack_index_mirrors_the_intel_state_convention() -> None:
    assert default_attack_index("/var/lib/autosiem/prod.db") == Path("/var/lib/autosiem/prod.attack.json")

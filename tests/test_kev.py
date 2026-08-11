"""CISA KEV catalogue and the vulnerability enricher.

The fixture mirrors the real feed's field names, verified against the published
catalogue on 2026-08-11 (catalogVersion 2026.08.11, 1662 entries). Every test
injects a fetcher, so the suite stays offline.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from autosiem.enrichment import EnrichmentRegistry, VulnerabilityEnricher, enrichment_from_env
from autosiem.kev import (
    EMPTY_CATALOG,
    KEV_URL,
    default_kev_state,
    distill_catalog,
    load_kev_state,
    normalize_cve,
    refresh_kev,
    save_kev_state,
)
from autosiem.update_job import UpdateJob

FEED = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.08.11",
    "dateReleased": "2026-08-11T18:02:53.3685Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-8037",
            "vendorProject": "Progress",
            "product": "LoadMaster",
            "vulnerabilityName": "Progress LoadMaster Command Injection Vulnerability",
            "dateAdded": "2026-08-07",
            "shortDescription": "long prose we do not keep",
            "requiredAction": "Apply mitigations",
            "dueDate": "2026-08-28",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "https://example.test",
            "cwes": ["CWE-77"],
        },
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "long prose we do not keep",
            "requiredAction": "Apply updates",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-502"],
        },
        {
            "cveID": "not-a-cve",
            "vendorProject": "Junk",
            "product": "Junk",
            "vulnerabilityName": "Malformed row",
            "dateAdded": "2026-01-01",
            "knownRansomwareCampaignUse": "",
        },
    ],
}


def _fetch(payload: dict | None = None, calls: list[str] | None = None):
    def fetch(url: str) -> bytes:
        if calls is not None:
            calls.append(url)
        assert url == KEV_URL
        return json.dumps(payload if payload is not None else FEED).encode()

    return fetch


def _catalog(tmp_path: Path):
    dest = tmp_path / "kev.json"
    refresh_kev(dest, fetch=_fetch())
    return load_kev_state(dest)


# --------------------------------------------------------------------------
# catalogue
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [("cve-2021-44228", "CVE-2021-44228"), (" CVE-2026-8037 ", "CVE-2026-8037"), ("CVE-2021-1", None), ("junk", None), (None, None)],
)
def test_normalize_cve(raw, expected) -> None:
    assert normalize_cve(raw) == expected


def test_distill_keeps_only_what_enrichment_uses() -> None:
    index = distill_catalog(FEED)
    assert index["catalog_version"] == "2026.08.11"
    assert set(index["vulnerabilities"]) == {"CVE-2026-8037", "CVE-2021-44228"}
    entry = index["vulnerabilities"]["CVE-2021-44228"]
    assert entry["ransomware"] is True
    assert entry["vendor"] == "Apache"
    # The prose fields are ~90% of the payload and are never displayed.
    assert "shortDescription" not in entry
    assert "requiredAction" not in entry
    assert index["ransomware_count"] == 1


def test_distill_is_stable_for_the_same_catalogue() -> None:
    assert json.dumps(distill_catalog(FEED), sort_keys=True) == json.dumps(
        distill_catalog(FEED), sort_keys=True
    )


def test_refresh_writes_a_loadable_catalogue(tmp_path: Path) -> None:
    result = refresh_kev(tmp_path / "kev.json", fetch=_fetch())
    assert result.refreshed is True
    assert result.catalog_version == "2026.08.11"
    assert result.count == 2

    catalog = load_kev_state(tmp_path / "kev.json")
    assert "CVE-2021-44228" in catalog
    assert catalog.is_ransomware("CVE-2021-44228") is True
    assert catalog.is_ransomware("CVE-2026-8037") is False
    assert catalog.get("nonsense") is None


def test_refresh_skips_the_write_when_the_version_is_unchanged(tmp_path: Path) -> None:
    dest = tmp_path / "kev.json"
    refresh_kev(dest, fetch=_fetch())
    second = refresh_kev(dest, fetch=_fetch())
    assert second.refreshed is False
    assert "already at 2026.08.11" in second.message


def test_missing_cache_is_empty_not_an_error(tmp_path: Path) -> None:
    """An empty catalogue says nothing; it must not imply "not exploited"."""
    catalog = load_kev_state(tmp_path / "absent.json")
    assert catalog is EMPTY_CATALOG or len(catalog) == 0
    assert "CVE-2021-44228" not in catalog


def test_corrupt_cache_is_empty_not_an_error(tmp_path: Path) -> None:
    broken = tmp_path / "kev.json"
    broken.write_text("{not json", encoding="utf-8")
    assert len(load_kev_state(broken)) == 0


def test_default_kev_state_matches_the_intel_convention() -> None:
    assert default_kev_state("/var/lib/autosiem/prod.db") == Path("/var/lib/autosiem/prod.kev.json")


def test_refresh_refuses_a_plaintext_url(monkeypatch, tmp_path: Path) -> None:
    import autosiem.kev as kev_module

    monkeypatch.setattr(kev_module, "KEV_URL", "http://cisa.example/kev.json")
    with pytest.raises(ValueError, match="non-HTTPS"):
        kev_module.refresh_kev(tmp_path / "kev.json")


# --------------------------------------------------------------------------
# enricher
# --------------------------------------------------------------------------


INVENTORY = [
    {"host": "web-01", "cves": ["CVE-2021-44228", "CVE-2019-0001"]},
    {"host": "app-02", "cves": ["CVE-2026-8037"]},
    {"host": "lab-03", "cves": ["CVE-2019-0001", "CVE-2018-1111"]},
    {"hostname": "alt-04", "cve_ids": [{"cveID": "CVE-2021-44228"}]},
]


def test_actively_exploited_ransomware_cve_makes_a_host_critical(tmp_path: Path) -> None:
    enricher = VulnerabilityEnricher(INVENTORY, catalog=_catalog(tmp_path))
    context = enricher.enrich("host:web-01")
    assert context is not None
    assert context.criticality == "critical"
    assert "ransomware-linked" in context.tags
    assert context.attributes["known_exploited"] == ["CVE-2021-44228"]
    assert context.attributes["cve_count"] == 2


def test_exploited_but_not_ransomware_is_high(tmp_path: Path) -> None:
    enricher = VulnerabilityEnricher(INVENTORY, catalog=_catalog(tmp_path))
    context = enricher.enrich("host:app-02")
    assert context is not None
    assert context.criticality == "high"
    assert "known-exploited" in context.tags
    assert "ransomware-linked" not in context.tags


def test_a_patch_backlog_alone_does_not_raise_priority(tmp_path: Path) -> None:
    """The whole point of KEV: unexploited CVEs are background noise.

    Otherwise every host with an unpatched box would outrank a clean
    crown-jewel server.
    """
    enricher = VulnerabilityEnricher(INVENTORY, catalog=_catalog(tmp_path))
    context = enricher.enrich("host:lab-03")
    assert context is not None
    assert context.criticality is None
    assert context.attributes["cve_count"] == 2
    assert context.attributes["known_exploited_count"] == 0


def test_nested_cve_records_are_accepted(tmp_path: Path) -> None:
    enricher = VulnerabilityEnricher(INVENTORY, catalog=_catalog(tmp_path))
    context = enricher.enrich("host:alt-04")
    assert context is not None
    assert context.attributes["known_exploited"] == ["CVE-2021-44228"]


def test_unknown_host_and_non_host_entities_get_nothing(tmp_path: Path) -> None:
    enricher = VulnerabilityEnricher(INVENTORY, catalog=_catalog(tmp_path))
    assert enricher.enrich("host:not-in-inventory") is None
    assert enricher.enrich("user:alice") is None
    assert enricher.enrich("ip:198.51.100.25") is None


def test_without_a_catalogue_it_reports_unknown_not_safe() -> None:
    """No KEV cache must not read as "nothing here is exploited"."""
    enricher = VulnerabilityEnricher(INVENTORY)
    context = enricher.enrich("host:web-01")
    assert context is not None
    assert context.criticality is None
    assert context.attributes["kev_catalog"] == "not loaded"
    assert context.attributes["known_exploited_count"] == 0


def test_exploited_host_risk_is_scaled_by_the_registry(tmp_path: Path) -> None:
    """End-to-end: KEV context reaches the risk multiplier."""
    registry = EnrichmentRegistry([VulnerabilityEnricher(INVENTORY, catalog=_catalog(tmp_path))])
    assert registry.adjusted_risk(50, ["host:web-01"]) == 100  # critical -> x2.0
    assert registry.adjusted_risk(50, ["host:app-02"]) == 75   # high -> x1.5
    assert registry.adjusted_risk(50, ["host:lab-03"]) == 50   # backlog only -> unchanged


def test_enrichment_from_env_wires_the_vulnerability_enricher(tmp_path: Path) -> None:
    inventory = tmp_path / "vulns.jsonl"
    inventory.write_text("\n".join(json.dumps(record) for record in INVENTORY), encoding="utf-8")
    kev_path = tmp_path / "kev.json"
    refresh_kev(kev_path, fetch=_fetch())

    registry = enrichment_from_env(
        {"AUTOSIEM_VULN_FILE": str(inventory), "AUTOSIEM_KEV_FILE": str(kev_path)}
    )
    contexts = registry.context_for(["host:web-01"])
    sources = {item["source"] for item in contexts["host:web-01"]}
    assert "vulnerability" in sources


def test_enrichment_from_env_skips_it_without_an_inventory() -> None:
    """A KEV cache alone says nothing about any particular host."""
    registry = enrichment_from_env({})
    assert not any(getattr(e, "name", "") == "vulnerability" for e in registry.enrichers)


# --------------------------------------------------------------------------
# update job wiring
# --------------------------------------------------------------------------


def test_update_job_does_not_fetch_kev_by_default(tmp_path: Path) -> None:
    def explode(url: str) -> bytes:
        raise AssertionError("KEV refresh must be opt-in")

    report = UpdateJob(db_path=tmp_path / "a.db", kev_fetch=explode).run_once()
    assert report.kev_refreshed is False
    assert report.kev_version == ""


def test_update_job_refreshes_kev_when_asked(tmp_path: Path) -> None:
    db = tmp_path / "autosiem.db"
    report = UpdateJob(db_path=db, refresh_kev_catalog=True, kev_fetch=_fetch()).run_once()
    assert report.kev_refreshed is True
    assert report.kev_version == "2026.08.11"
    assert default_kev_state(db).exists()
    assert any("KEV catalogue refreshed" in message for message in report.messages)


def test_update_job_survives_a_broken_kev_feed(tmp_path: Path) -> None:
    def boom(url: str) -> bytes:
        raise OSError("network down")

    report = UpdateJob(db_path=tmp_path / "a.db", refresh_kev_catalog=True, kev_fetch=boom).run_once()
    assert report.kev_refreshed is False
    assert any("kev refresh failed" in message for message in report.messages)
    # The rest of the cycle still ran.
    assert report.coverage["matrix"]["available"] is True

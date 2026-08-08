"""Tests for entity enrichment (asset, identity, network, threat intel)."""

from __future__ import annotations

import json

import pytest

from autosiem.enrichment import (
    CRITICALITY_MULTIPLIERS,
    MAX_RISK_MULTIPLIER,
    AssetEnricher,
    EnrichmentRegistry,
    IdentityEnricher,
    NetworkEnricher,
    ThreatIntelEnricher,
    enrichment_from_env,
    highest_criticality,
    load_records,
    normalize_criticality,
    split_entity,
)

ASSETS = [
    {"hostname": "web-01", "ip": "10.0.0.20", "criticality": "critical", "owner": "platform", "environment": "prod", "tags": ["pci"]},
    {"hostname": "ws-7", "ip": "10.0.0.7", "criticality": "low", "owner": "alice"},
]
IDENTITIES = [
    {"username": "alice", "department": "Finance", "title": "Controller", "status": "active"},
    {"username": "svc-backup", "privileged": True, "status": "active"},
    {"username": "ghost", "status": "disabled"},
]


# --- helpers ---------------------------------------------------------------


def test_split_entity() -> None:
    assert split_entity("user:alice") == ("user", "alice")
    assert split_entity("cloud_account:prod") == ("cloud_account", "prod")
    assert split_entity("bare") == ("", "bare")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("critical", "critical"),
        ("CRIT", "critical"),
        ("Tier0", "critical"),
        ("crown-jewel", "critical"),
        ("important", "high"),
        ("moderate", "medium"),
        ("minor", "low"),
        ("banana", None),
        (None, None),
        ("", None),
    ],
)
def test_normalize_criticality(value, expected) -> None:
    assert normalize_criticality(value) == expected


def test_highest_criticality_picks_the_most_severe() -> None:
    assert highest_criticality(["low", "critical", "medium"]) == "critical"
    assert highest_criticality([None, "medium"]) == "medium"
    assert highest_criticality([None, None]) is None


# --- record loading --------------------------------------------------------


def test_load_records_reads_a_json_array(tmp_path) -> None:
    path = tmp_path / "a.json"
    path.write_text(json.dumps(ASSETS))
    assert len(load_records(path)) == 2


def test_load_records_reads_jsonl(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    path.write_text("\n".join(json.dumps(item) for item in ASSETS))
    assert len(load_records(path)) == 2


def test_load_records_reads_a_records_wrapper(tmp_path) -> None:
    path = tmp_path / "a.json"
    path.write_text(json.dumps({"records": ASSETS}))
    assert len(load_records(path)) == 2


def test_load_records_never_raises_on_bad_input(tmp_path) -> None:
    """Enrichment is optional context and must not break ingest."""
    assert load_records(tmp_path / "missing.json") == []
    empty = tmp_path / "e.json"
    empty.write_text("")
    assert load_records(empty) == []
    broken = tmp_path / "b.json"
    broken.write_text("[not json")
    assert load_records(broken) == []


# --- asset -----------------------------------------------------------------


def test_asset_enricher_matches_host_and_ip() -> None:
    enricher = AssetEnricher(ASSETS)
    by_host = enricher.enrich("host:web-01")
    by_ip = enricher.enrich("ip:10.0.0.20")
    assert by_host is not None and by_host.criticality == "critical"
    assert by_ip is not None and by_ip.criticality == "critical"
    assert by_host.attributes["environment"] == "prod"
    assert "pci" in by_host.tags


def test_asset_enricher_is_case_insensitive() -> None:
    assert AssetEnricher(ASSETS).enrich("host:WEB-01") is not None


def test_asset_enricher_returns_none_for_unknown_and_wrong_kind() -> None:
    enricher = AssetEnricher(ASSETS)
    assert enricher.enrich("host:nope") is None
    assert enricher.enrich("user:alice") is None


def test_asset_enricher_loads_from_file(tmp_path) -> None:
    path = tmp_path / "assets.json"
    path.write_text(json.dumps(ASSETS))
    assert AssetEnricher.from_file(path).enrich("host:ws-7") is not None


# --- identity --------------------------------------------------------------


def test_identity_enricher_returns_directory_context() -> None:
    context = IdentityEnricher(IDENTITIES).enrich("user:alice")
    assert context is not None
    assert context.attributes["department"] == "Finance"
    assert context.criticality is None  # ordinary user, no bump


def test_a_privileged_account_is_critical() -> None:
    context = IdentityEnricher(IDENTITIES).enrich("user:svc-backup")
    assert context is not None
    assert context.criticality == "critical"
    assert "privileged" in context.tags


def test_a_disabled_account_is_critical() -> None:
    """Activity on a disabled account is never routine."""
    context = IdentityEnricher(IDENTITIES).enrich("user:ghost")
    assert context is not None
    assert context.criticality == "critical"
    assert "disabled-account" in context.tags


def test_identity_matches_the_local_part_of_an_email() -> None:
    enricher = IdentityEnricher([{"email": "dana@example.com", "department": "IT"}])
    assert enricher.enrich("user:dana") is not None
    assert enricher.enrich("user:dana@example.com") is not None


def test_identity_ignores_non_user_entities() -> None:
    assert IdentityEnricher(IDENTITIES).enrich("host:web-01") is None


# --- network ---------------------------------------------------------------


@pytest.mark.parametrize(
    "address,scope",
    [
        ("10.1.2.3", "private"),
        ("8.8.8.8", "public"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link-local"),
        ("224.0.0.1", "multicast"),
        # RFC 5737: Python calls these private, which would mislabel AutoSIEM's
        # own example telemetry.
        ("203.0.113.20", "documentation"),
        ("198.51.100.5", "documentation"),
    ],
)
def test_network_scope_labels(address, scope) -> None:
    context = NetworkEnricher().enrich(f"ip:{address}")
    assert context is not None
    assert context.attributes["scope"] == scope


def test_named_ranges_are_matched() -> None:
    enricher = NetworkEnricher({"corp-vpn": ["10.8.0.0/16"], "dmz": ["10.9.0.0/16"]})
    context = enricher.enrich("ip:10.8.4.5")
    assert context is not None
    assert context.attributes["ranges"] == ["corp-vpn"]
    assert "corp-vpn" in context.tags


def test_an_unmatched_public_address_is_tagged_unknown_external() -> None:
    context = NetworkEnricher({"corp-vpn": ["10.8.0.0/16"]}).enrich("ip:8.8.8.8")
    assert context is not None
    assert "unknown-external" in context.tags


def test_network_ignores_bad_addresses_and_other_kinds() -> None:
    enricher = NetworkEnricher()
    assert enricher.enrich("ip:not-an-ip") is None
    assert enricher.enrich("user:alice") is None


def test_network_never_sets_criticality() -> None:
    """It is on by default, so it must not be able to move any risk score."""
    context = NetworkEnricher().enrich("ip:8.8.8.8")
    assert context is not None
    assert context.criticality is None


def test_invalid_cidrs_are_skipped() -> None:
    enricher = NetworkEnricher({"bad": ["not-a-cidr"], "good": ["10.0.0.0/8"]})
    assert "bad" not in enricher.named_ranges
    assert "good" in enricher.named_ranges


def test_network_loads_named_ranges_from_file(tmp_path) -> None:
    path = tmp_path / "ranges.json"
    path.write_text(json.dumps({"corp-vpn": ["10.8.0.0/16"]}))
    context = NetworkEnricher.from_file(path).enrich("ip:10.8.0.1")
    assert context is not None and "corp-vpn" in context.tags


# --- threat intel ----------------------------------------------------------


class _Indicator:
    def __init__(self, value: str, name: str) -> None:
        self.clauses = [{"type": "ipv4-addr", "value": value}]
        self.name = name


def test_threat_intel_flags_a_known_indicator() -> None:
    enricher = ThreatIntelEnricher([_Indicator("203.0.113.99", "known-c2")])
    context = enricher.enrich("ip:203.0.113.99")
    assert context is not None
    assert context.criticality == "critical"
    assert "threat-intel-hit" in context.tags
    assert "known-c2" in context.attributes["indicators"]


def test_threat_intel_ignores_unknown_values() -> None:
    assert ThreatIntelEnricher([_Indicator("1.2.3.4", "x")]).enrich("ip:8.8.8.8") is None


# --- registry --------------------------------------------------------------


def _registry() -> EnrichmentRegistry:
    return EnrichmentRegistry([AssetEnricher(ASSETS), IdentityEnricher(IDENTITIES), NetworkEnricher()])


def test_registry_merges_every_enricher() -> None:
    contexts = _registry().enrich("ip:10.0.0.20")
    assert {context.source for context in contexts} == {"asset", "network"}


def test_criticality_takes_the_most_severe_across_sources() -> None:
    registry = EnrichmentRegistry(
        [AssetEnricher([{"hostname": "h", "criticality": "low"}]), ThreatIntelEnricher([_Indicator("h", "bad")])]
    )
    assert registry.criticality_for("host:h") == "critical"


def test_risk_multiplier_reflects_criticality() -> None:
    registry = _registry()
    assert registry.risk_multiplier(["host:web-01"]) == CRITICALITY_MULTIPLIERS["critical"]
    assert registry.risk_multiplier(["host:ws-7"]) == CRITICALITY_MULTIPLIERS["low"]


def test_an_unknown_entity_scores_exactly_as_before() -> None:
    """An unenriched deployment must not have its risk scores shifted."""
    assert _registry().risk_multiplier(["host:unknown"]) == 1.0
    assert EnrichmentRegistry().risk_multiplier(["host:web-01"]) == 1.0


def test_the_most_critical_entity_in_a_finding_wins() -> None:
    assert _registry().risk_multiplier(["host:ws-7", "host:web-01"]) == CRITICALITY_MULTIPLIERS["critical"]


def test_the_multiplier_is_capped() -> None:
    registry = EnrichmentRegistry([ThreatIntelEnricher([_Indicator("x", "bad")])])
    assert registry.risk_multiplier(["ip:x"]) <= MAX_RISK_MULTIPLIER


def test_adjusted_risk_scales_and_never_zeroes_a_positive_finding() -> None:
    registry = _registry()
    assert registry.adjusted_risk(75, ["host:web-01"]) == 150
    assert registry.adjusted_risk(75, ["host:ws-7"]) == 56
    assert registry.adjusted_risk(75, ["host:unknown"]) == 75
    assert registry.adjusted_risk(1, ["host:ws-7"]) == 1


def test_a_broken_enricher_does_not_lose_the_others() -> None:
    class Broken:
        name = "broken"

        def enrich(self, entity: str):
            raise RuntimeError("boom")

    registry = EnrichmentRegistry([Broken(), AssetEnricher(ASSETS)])
    contexts = registry.enrich("host:web-01")
    assert [context.source for context in contexts] == ["asset"]


def test_context_for_omits_entities_nothing_matched() -> None:
    context = _registry().context_for(["host:web-01", "host:nothing-knows-this"])
    assert "host:web-01" in context
    assert "host:nothing-knows-this" not in context


# --- env wiring ------------------------------------------------------------


def test_enrichment_from_env_is_network_only_by_default(monkeypatch) -> None:
    for key in ("AUTOSIEM_ASSET_FILE", "AUTOSIEM_IDENTITY_FILE", "AUTOSIEM_NETWORK_FILE", "AUTOSIEM_NETWORK_RANGES"):
        monkeypatch.delenv(key, raising=False)
    registry = enrichment_from_env()
    assert [enricher.name for enricher in registry.enrichers] == ["network"]


def test_enrichment_from_env_loads_configured_sources(tmp_path, monkeypatch) -> None:
    assets = tmp_path / "a.json"
    assets.write_text(json.dumps(ASSETS))
    identities = tmp_path / "i.json"
    identities.write_text(json.dumps(IDENTITIES))
    monkeypatch.setenv("AUTOSIEM_ASSET_FILE", str(assets))
    monkeypatch.setenv("AUTOSIEM_IDENTITY_FILE", str(identities))
    monkeypatch.setenv("AUTOSIEM_NETWORK_RANGES", json.dumps({"corp": ["10.0.0.0/8"]}))

    registry = enrichment_from_env()
    names = [enricher.name for enricher in registry.enrichers]
    assert names == ["asset", "identity", "network"]
    assert registry.criticality_for("host:web-01") == "critical"


def test_indicators_become_a_threat_intel_enricher(monkeypatch) -> None:
    monkeypatch.delenv("AUTOSIEM_ASSET_FILE", raising=False)
    registry = enrichment_from_env(env={}, indicators=[_Indicator("203.0.113.99", "c2")])
    assert "threat_intel" in [enricher.name for enricher in registry.enrichers]


def test_a_missing_asset_file_is_skipped_not_fatal(monkeypatch) -> None:
    registry = enrichment_from_env(env={"AUTOSIEM_ASSET_FILE": "/nope/missing.json"})
    assert [enricher.name for enricher in registry.enrichers] == ["network"]


def test_bad_inline_ranges_degrade_to_an_empty_network_enricher() -> None:
    registry = enrichment_from_env(env={"AUTOSIEM_NETWORK_RANGES": "{not json"})
    assert [enricher.name for enricher in registry.enrichers] == ["network"]


# --- pipeline and runtime integration --------------------------------------

WEB_EXPLOIT = json.dumps(
    {
        "timestamp": "2026-08-04T10:15:00Z",
        "category": "network",
        "action": "http_request",
        "user": "bob",
        "host": "web-01",
        "src_ip": "10.0.0.20",
        "url": "/index.php?page=../../../../etc/passwd",
    }
)


def _rules():
    from pathlib import Path

    from autosiem.rules import load_rules

    return load_rules(Path(__file__).resolve().parents[1] / "rules")


def test_pipeline_scales_finding_risk_by_asset_criticality() -> None:
    """Same detection, different asset: ranking must reflect what it hit."""
    from autosiem.pipeline import AutoSIEMPipeline

    rules = _rules()
    plain = AutoSIEMPipeline(rules).process_lines([WEB_EXPLOIT])
    enriched = AutoSIEMPipeline(rules, enrichment=EnrichmentRegistry([AssetEnricher(ASSETS)])).process_lines([WEB_EXPLOIT])

    base = next(f for f in plain.findings if f.rule_id == "AUTO-WEB-001")
    scaled = next(f for f in enriched.findings if f.rule_id == "AUTO-WEB-001")
    assert scaled.risk_points == base.risk_points * 2
    assert enriched.incidents[0].risk_score > plain.incidents[0].risk_score


def test_pipeline_without_enrichment_is_unchanged() -> None:
    from autosiem.pipeline import AutoSIEMPipeline

    rules = _rules()
    plain = AutoSIEMPipeline(rules).process_lines([WEB_EXPLOIT])
    empty = AutoSIEMPipeline(rules, enrichment=EnrichmentRegistry()).process_lines([WEB_EXPLOIT])
    assert [f.risk_points for f in plain.findings] == [f.risk_points for f in empty.findings]


def test_enrich_entities_task_reports_external_context() -> None:
    from autosiem.pipeline import AutoSIEMPipeline

    registry = EnrichmentRegistry([AssetEnricher(ASSETS), NetworkEnricher()])
    result = AutoSIEMPipeline(_rules(), enrichment=registry).process_lines([WEB_EXPLOIT])
    investigation = result.investigations[result.incidents[0].incident_id]

    task = next(item for item in investigation.tasks if item.action == "enrich_entities")
    assert task.result is not None
    assert "Enrichment matched" in task.result
    assert "critical" in task.result

    evidence = [item for item in investigation.evidence if item.kind == "entity_enrichment"]
    assert len(evidence) == 1
    assert "host:web-01" in evidence[0].data["context"]


def test_enrich_entities_says_so_when_nothing_is_configured() -> None:
    """With neither a store nor enrichers, say that plainly rather than imply work."""
    from autosiem.pipeline import AutoSIEMPipeline

    result = AutoSIEMPipeline(_rules()).process_lines([WEB_EXPLOIT])
    investigation = result.investigations[result.incidents[0].incident_id]
    task = next(item for item in investigation.tasks if item.action == "enrich_entities")
    assert task.result is not None
    assert "No event store configured" in task.result
    assert not [item for item in investigation.evidence if item.kind == "entity_enrichment"]


def test_enrichment_reports_even_without_an_event_store(tmp_path) -> None:
    """Asset context does not depend on local telemetry, so it still lands."""
    from autosiem.pipeline import AutoSIEMPipeline

    registry = EnrichmentRegistry([AssetEnricher(ASSETS)])
    result = AutoSIEMPipeline(_rules(), enrichment=registry).process_lines([WEB_EXPLOIT])
    investigation = result.investigations[result.incidents[0].incident_id]
    task = next(item for item in investigation.tasks if item.action == "enrich_entities")
    assert task.result is not None
    assert "Enrichment matched" in task.result

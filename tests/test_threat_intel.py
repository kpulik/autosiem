from __future__ import annotations

import json
from pathlib import Path

from autosiem.normalization import normalize, parse_raw_line
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules
from autosiem.threat_intel import (
    ThreatIntelMatcher,
    default_intel_state,
    load_intel_state,
    load_stix_bundle,
    save_intel_state,
)


def _bundle() -> dict:
    return {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "id": "indicator--1", "name": "Bad IP", "pattern": "[ipv4-addr:value = '203.0.113.66']"},
            {"type": "indicator", "id": "indicator--2", "name": "Malware domain", "pattern": "[domain-name:value = 'evil.example.com']"},
            {"type": "indicator", "id": "indicator--3", "name": "Bad URL", "pattern": "[url:value = 'http://198.51.100.25/payload.exe']"},
            {"type": "marking-definition", "id": "marking--x", "definition_type": "statement"},
        ],
    }


def test_load_stix_bundle_parses_indicators_and_skips_non_indicators(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(_bundle()), encoding="utf-8")
    indicators = load_stix_bundle(path)
    assert len(indicators) == 3
    assert all(len(ind.clauses) == 1 for ind in indicators)


def test_matcher_hits_ip_domain_and_url(tmp_path: Path) -> None:
    bundle_path = tmp_path / "b.json"
    bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
    matcher = ThreatIntelMatcher(load_stix_bundle(bundle_path))

    ip_event = normalize(parse_raw_line(json.dumps({"category": "network", "src_ip": "10.0.0.5", "dst_ip": "203.0.113.66", "action": "flow"})))
    assert [i.indicator_id for i in matcher.matches_for(ip_event)] == ["indicator--1"]

    url_event = normalize(parse_raw_line(json.dumps({"category": "network", "url": "http://198.51.100.25/payload.exe", "host": "evil.example.com"})))
    assert {i.indicator_id for i in matcher.matches_for(url_event)} == {"indicator--2", "indicator--3"}


def test_threat_intel_finding_flows_through_pipeline(tmp_path: Path) -> None:
    bundle_path = tmp_path / "b.json"
    bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
    matcher = ThreatIntelMatcher(load_stix_bundle(bundle_path))
    root = Path(__file__).resolve().parents[1]
    pipeline = AutoSIEMPipeline(load_rules(root / "rules"), threat_intel=matcher)
    result = pipeline.process_lines(
        [json.dumps({"category": "network", "src_ip": "10.0.0.5", "dst_ip": "203.0.113.66", "action": "flow"})]
    )
    assert any(f.rule_id == "AUTO-INTEL-001" for f in result.findings)
    # The match also produces an incident for the entity.
    assert result.incidents


def test_intel_state_round_trip(tmp_path: Path) -> None:
    bundle_path = tmp_path / "b.json"
    bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
    indicators = load_stix_bundle(bundle_path)
    state = default_intel_state(str(tmp_path / "siem.db"))
    assert str(state).endswith(".intel.json")
    save_intel_state(state, indicators)
    reloaded = load_intel_state(state)
    assert len(reloaded) == len(indicators)
    assert reloaded[0].pattern == indicators[0].pattern


def test_empty_intel_state_returns_empty() -> None:
    state = default_intel_state("/tmp/does-not-exist.db")
    assert load_intel_state(state) == []
    assert load_intel_state("/definitely/missing/intel.json") == []
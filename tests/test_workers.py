from __future__ import annotations

from pathlib import Path

from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules
from autosiem.schemas import NormalizedEvent
from autosiem.suppression import SuppressionEngine
from autosiem.workers import ParserWorkerPool, detect_event, normalize_line, process_lines, suppress_findings

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = REPO_ROOT / "rules"
EVENTS_FILE = REPO_ROOT / "examples" / "events.jsonl"


def _lines() -> list[str]:
    return EVENTS_FILE.read_text(encoding="utf-8").splitlines()


def test_normalize_line_returns_event() -> None:
    event = normalize_line(_lines()[0])
    assert isinstance(event, NormalizedEvent)
    assert event.action
    assert event.timestamp is not None


def test_pool_events_findings_incidents_and_serial_risk() -> None:
    lines = _lines()
    rules = load_rules(RULES_PATH)
    result = ParserWorkerPool(workers=4, rules=rules).process_lines(lines)

    assert len(result.events) == len(lines)
    assert result.findings, "parallel run should produce findings"
    assert result.incidents, "parallel run should produce incidents"

    serial = AutoSIEMPipeline(rules).process_lines(lines)
    assert result.incidents[0].risk_score == serial.incidents[0].risk_score


def test_pool_is_deterministic() -> None:
    lines = _lines()
    rules = load_rules(RULES_PATH)
    first = ParserWorkerPool(workers=4, rules=rules).process_lines(lines)
    second = ParserWorkerPool(workers=4, rules=rules).process_lines(lines)

    assert len(first.events) == len(second.events)
    assert len(first.findings) == len(second.findings)
    assert len(first.incidents) == len(second.incidents)
    assert len(first.reports) == len(second.reports)
    assert len(first.investigations) == len(second.investigations)
    assert [inc.risk_score for inc in first.incidents] == [inc.risk_score for inc in second.incidents]


def test_pool_merges_chunks_in_order() -> None:
    lines = _lines()[:6]
    rules = load_rules(RULES_PATH)
    result = ParserWorkerPool(workers=3, rules=rules).process_lines(lines)
    # event_id is a fresh uuid per run, so compare the deterministic raw parses.
    assert [ev.raw for ev in result.events] == [ev.raw for ev in AutoSIEMPipeline(rules).process_lines(lines).events]


def test_detect_event_helper() -> None:
    rules = load_rules(RULES_PATH)
    event = normalize_line('{"category":"authentication","action":"login_failed","user":"alice","outcome":"failure"}')
    findings = detect_event(event, rules)
    assert isinstance(findings, list)
    assert any(f.rule_id == "AUTO-AUTH-001" for f in findings)


def test_suppress_findings_helper() -> None:
    rules = load_rules(RULES_PATH)
    lines = _lines()
    result = AutoSIEMPipeline(rules).process_lines(lines)
    engine = SuppressionEngine()
    engine.add_suppression(rule_id="*", action="suppress")
    kept, suppressed = suppress_findings(result.findings, engine)
    assert len(kept) == 0
    assert len(suppressed) == len(result.findings)


def test_convenience_process_lines() -> None:
    lines = _lines()
    result = process_lines(lines, workers=2)
    assert len(result.events) == len(lines)
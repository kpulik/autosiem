from __future__ import annotations

from autosiem.querygen import QueryTranslator, to_cli_flags, translate_query


def test_entity_and_status_extraction() -> None:
    q = translate_query("find powershell events for user:alice status open")
    assert q["entity"] == "user:alice"
    assert q["status"] == "open"
    assert "powershell" in (q["query"] or "").lower()


def test_host_phrase_entity() -> None:
    q = translate_query("events on host workstation-01")
    assert q["entity"] == "host:workstation-01"


def test_source_and_timeframe() -> None:
    q = translate_query("events with powershell from sysmon last 24h")
    assert "powershell" in (q["query"] or "").lower()
    assert q["source"] == "sysmon"
    assert q["timeframe"] is not None


def test_rule_and_limit() -> None:
    q = translate_query("top 25 findings rule AUTO-AUTH-001")
    assert q["rule"] == "AUTO-AUTH-001"
    assert q["limit"] == 25


def test_empty_input() -> None:
    q = translate_query("")
    assert q["entity"] is None
    assert q["status"] is None


def test_to_cli_flags() -> None:
    q = translate_query("incidents for user:alice status open")
    flags = to_cli_flags(q)
    assert "--entity=user:alice" in flags
    assert "--status=open" in flags


def test_translator_wrapper() -> None:
    translator = QueryTranslator()
    q = translator.translate("host:vpn-1 resolved incidents")
    assert q["entity"] == "host:vpn-1"
    assert q["status"] == "resolved"
    assert translator.to_cli(query=q)
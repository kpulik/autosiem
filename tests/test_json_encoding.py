"""Stored JSON must not change when the encoder gets faster.

The audit chain hashes the text `_json` produces, and stored documents are
compared across versions, so the one-pass encoder is checked byte for byte
against the original asdict-based one on real pipeline output.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules
from autosiem.schemas import Severity
from autosiem.storage import _json, _to_jsonable

ROOT = Path(__file__).resolve().parents[1]


def _reference(value: Any) -> Any:
    """The encoder as it was before the one-pass rewrite."""
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _reference(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _reference(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_reference(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "name") and hasattr(value, "value"):
        return getattr(value, "name", str(value)).lower()
    return value


def _documents() -> list[Any]:
    rules = load_rules(ROOT / "rules")
    lines = (ROOT / "examples" / "events.jsonl").read_text().splitlines()
    lines += [json.dumps({"timestamp": f"2026-08-04T10:{i // 60:02d}:{i % 60:02d}Z", "user": f"u{i % 7}", "action": "login_failed",
                          "outcome": "failure", "category": "authentication", "src_ip": f"198.51.100.{i % 9}", "host": "vpn-1"})
              for i in range(400)]
    result = AutoSIEMPipeline(rules).process_lines(lines)
    docs: list[Any] = [*result.events, *result.findings, *result.incidents, *result.suppressed]
    docs += list(result.investigations) if hasattr(result, "investigations") else []
    docs += list(getattr(result, "proposals", []))
    return docs


def test_real_pipeline_documents_encode_byte_for_byte_as_before() -> None:
    docs = _documents()
    assert len(docs) > 800
    for doc in docs:
        assert _json(doc) == json.dumps(_reference(doc), sort_keys=True)


@dataclass
class _Inner:
    when: datetime
    severity: Severity


@dataclass
class _Outer:
    items: list[_Inner]
    pair: tuple[int, str]
    nested: dict[Any, Any] = field(default_factory=dict)


def test_edge_shapes_encode_as_before() -> None:
    when = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
    value = _Outer(
        items=[_Inner(when, Severity.HIGH), _Inner(when, Severity.INFORMATIONAL)],
        pair=(1, "a"),
        nested={1: [when, {"s": Severity.LOW}], "k": None, "f": 1.5, "b": True},
    )
    assert _json(value) == json.dumps(_reference(value), sort_keys=True)
    assert _json({"sev": Severity.CRITICAL, "n": 3}) == '{"n": 3, "sev": "critical"}'


def test_the_encoder_does_not_mutate_its_input() -> None:
    inner = _Inner(datetime(2026, 1, 1, tzinfo=timezone.utc), Severity.MEDIUM)
    before = repr(inner)
    _to_jsonable(_Outer(items=[inner], pair=(0, "x")))
    assert repr(inner) == before

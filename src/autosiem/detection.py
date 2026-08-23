from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any
from uuid import uuid4

from .schemas import DetectionRule, Finding, NormalizedEvent


def evaluate_rules(event: NormalizedEvent, rules: list[DetectionRule]) -> list[Finding]:
    return [finding for rule in rules if rule.enabled if (finding := evaluate_rule(event, rule))]


def evaluate_rule(event: NormalizedEvent, rule: DetectionRule) -> Finding | None:
    event_doc = event.to_dict()
    if not _matches_selection(event_doc, rule.selection):
        return None
    return Finding(
        finding_id=str(uuid4()),
        rule_id=rule.rule_id,
        rule_name=rule.name,
        event_id=event.event_id,
        timestamp=event.timestamp,
        severity=rule.severity,
        risk_points=rule.risk_points,
        entities=event.entity_keys(),
        mitre_attack=rule.mitre_attack,
        evidence={"event": event_doc, "rule": asdict(rule)},
    )


def _matches_selection(doc: dict[str, Any], selection: dict[str, Any]) -> bool:
    for field, expected in selection.items():
        actual = _get_dotted(doc, field)
        if isinstance(expected, dict):
            if not _match_operator(actual, expected):
                return False
        elif isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _match_operator(actual: Any, expected: dict[str, Any]) -> bool:
    text = "" if actual is None else str(actual)
    for operator, value in expected.items():
        if operator == "contains" and str(value).lower() not in text.lower():
            return False
        if operator == "contains_any" and not any(str(item).lower() in text.lower() for item in value):
            return False
        if operator == "not_contains" and str(value).lower() in text.lower():
            return False
        if operator == "not_contains_any" and any(str(item).lower() in text.lower() for item in value):
            return False
        if operator == "regex" and not re.search(str(value), text, flags=re.IGNORECASE):
            return False
        if operator == "not_regex" and re.search(str(value), text, flags=re.IGNORECASE):
            return False
        if operator == "equals" and text != str(value):
            return False
        if operator == "not_equals" and text == str(value):
            return False
        if operator == "startswith" and not text.lower().startswith(str(value).lower()):
            return False
        if operator == "not_startswith" and text.lower().startswith(str(value).lower()):
            return False
        if operator == "endswith" and not text.lower().endswith(str(value).lower()):
            return False
        if operator == "not_endswith" and text.lower().endswith(str(value).lower()):
            return False
        if operator == "startswith_any" and not any(text.lower().startswith(str(item).lower()) for item in value):
            return False
        if operator == "not_startswith_any" and any(text.lower().startswith(str(item).lower()) for item in value):
            return False
        if operator == "endswith_any" and not any(text.lower().endswith(str(item).lower()) for item in value):
            return False
        if operator == "not_endswith_any" and any(text.lower().endswith(str(item).lower()) for item in value):
            return False
        if operator == "in" and actual not in value:
            return False
        if operator == "not_in" and actual in value:
            return False
        if operator == "exists" and bool(value) != (actual is not None):
            return False
    return True


def _get_dotted(doc: dict[str, Any], field: str) -> Any:
    value: Any = doc
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value

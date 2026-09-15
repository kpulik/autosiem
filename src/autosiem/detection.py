from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any
from uuid import uuid4

from .schemas import DetectionRule, Finding, NormalizedEvent


class UnknownOperatorError(ValueError):
    """A rule selection named an operator the engine does not implement."""


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
        if field == "any_of":
            if not isinstance(expected, list) or not any(
                isinstance(branch, dict) and _matches_selection(doc, branch) for branch in expected
            ):
                return False
            continue
        if field == "all_of":
            if not isinstance(expected, list) or not all(
                isinstance(branch, dict) and _matches_selection(doc, branch) for branch in expected
            ):
                return False
            continue
        if field == "not":
            if not isinstance(expected, dict) or _matches_selection(doc, expected):
                return False
            continue
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


#: Every operator :func:`_match_operator` implements. A selection naming
#: anything else is a BUG IN THE RULE, and the engine fails closed on it:
#: the loop used to fall through to `return True`, so a typo
#: (`contians`), an empty `{}`, or an unimplemented operator (`gt`)
#: silently became an unconditional match - a rule that fires on every
#: event. Sigma import already fails closed on unsupported modifiers;
#: this is the same rule for native selections.
_KNOWN_OPERATORS = frozenset({
    "contains",
    "contains_all",
    "contains_any",
    "endswith",
    "endswith_all",
    "endswith_any",
    "equals",
    "exists",
    "in",
    "not_contains",
    "not_contains_all",
    "not_contains_any",
    "not_endswith",
    "not_endswith_all",
    "not_endswith_any",
    "not_equals",
    "not_in",
    "not_regex",
    "not_startswith",
    "not_startswith_all",
    "not_startswith_any",
    "regex",
    "startswith",
    "startswith_all",
    "startswith_any",
})


def _match_operator(actual: Any, expected: dict[str, Any]) -> bool:
    if not expected:
        # An empty operator map constrains nothing, so treating it as a
        # match made the whole field a wildcard.
        return False
    unknown = set(expected) - _KNOWN_OPERATORS
    if unknown:
        raise UnknownOperatorError(
            f"unknown selection operator(s) {sorted(unknown)}; "
            f"supported: {sorted(_KNOWN_OPERATORS)}"
        )
    text = "" if actual is None else str(actual)
    for operator, value in expected.items():
        if operator == "contains" and str(value).lower() not in text.lower():
            return False
        if operator == "contains_any" and not any(str(item).lower() in text.lower() for item in value):
            return False
        if operator == "contains_all" and not all(str(item).lower() in text.lower() for item in value):
            return False
        if operator == "not_contains" and str(value).lower() in text.lower():
            return False
        if operator == "not_contains_any" and any(str(item).lower() in text.lower() for item in value):
            return False
        if operator == "not_contains_all" and all(str(item).lower() in text.lower() for item in value):
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
        if operator == "startswith_all" and not all(text.lower().startswith(str(item).lower()) for item in value):
            return False
        if operator == "not_startswith_any" and any(text.lower().startswith(str(item).lower()) for item in value):
            return False
        if operator == "not_startswith_all" and all(text.lower().startswith(str(item).lower()) for item in value):
            return False
        if operator == "endswith_any" and not any(text.lower().endswith(str(item).lower()) for item in value):
            return False
        if operator == "endswith_all" and not all(text.lower().endswith(str(item).lower()) for item in value):
            return False
        if operator == "not_endswith_any" and any(text.lower().endswith(str(item).lower()) for item in value):
            return False
        if operator == "not_endswith_all" and all(text.lower().endswith(str(item).lower()) for item in value):
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

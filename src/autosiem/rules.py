from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .detection import _KNOWN_OPERATORS
from .schemas import DetectionRule, Severity


def strip_leading_comment_lines(text: str) -> str:
    """Strip leading //, #, and /* ... */ comments before json.loads.

    This intentionally supports readable JSONC-like files while using Python's
    standard json parser. Only leading comment lines/blocks are stripped so JSON
    content is not silently modified in surprising ways.
    """
    lines = text.splitlines()
    index = 0
    in_block = False
    while index < len(lines):
        stripped = lines[index].strip()
        if in_block:
            if "*/" in stripped:
                in_block = False
            index += 1
            continue
        if not stripped:
            index += 1
            continue
        if stripped.startswith("//") or stripped.startswith("#"):
            index += 1
            continue
        if stripped.startswith("/*"):
            in_block = "*/" not in stripped
            index += 1
            continue
        break
    return "\n".join(lines[index:])


def load_rule_file(path: str | Path) -> DetectionRule:
    raw_text = Path(path).read_text(encoding="utf-8")
    data = json.loads(strip_leading_comment_lines(raw_text))
    return rule_from_dict(data)


def load_rules(path: str | Path) -> list[DetectionRule]:
    target = Path(path)
    if target.is_file():
        return [_load_rule_file(target)]
    rules: list[DetectionRule] = []
    for rule_path in sorted(target.glob("*.json")) + sorted(target.glob("*.yaml")) + sorted(target.glob("*.yml")):
        rules.append(_load_rule_file(rule_path))
    return rules


def _load_rule_file(path: Path) -> DetectionRule:
    if path.suffix.lower() in {".yaml", ".yml"}:
        from .sigma import load_sigma_file

        return load_sigma_file(path)
    return load_rule_file(path)


def validate_selection(selection: dict[str, Any], rule_id: str) -> None:
    """Reject a selection naming an operator the engine cannot evaluate.

    Checked at LOAD time, not match time: a typo'd operator used to fall
    through to an unconditional match, and raising only during evaluation would
    stop a whole ingest run on one bad rule instead of naming it at startup.
    """
    for field, expected in selection.items():
        if field in ("any_of", "all_of", "not"):
            nodes = expected if isinstance(expected, list) else [expected]
            for node in nodes:
                if isinstance(node, dict):
                    validate_selection(node, rule_id)
        elif isinstance(expected, dict):
            unknown = set(expected) - _KNOWN_OPERATORS
            if unknown:
                raise ValueError(
                    f"rule {rule_id!r} field {field!r} uses unknown operator(s) "
                    f"{sorted(unknown)}; supported: {sorted(_KNOWN_OPERATORS)}"
                )
            if not expected:
                raise ValueError(f"rule {rule_id!r} field {field!r} has an empty operator map")


def rule_from_dict(data: dict[str, Any]) -> DetectionRule:
    rule_id = str(data["id"])
    validate_selection(dict(data.get("selection", {})), rule_id)
    return DetectionRule(
        rule_id=rule_id,
        name=str(data["name"]),
        description=str(data.get("description", "")),
        severity=Severity.from_value(data.get("severity")),
        risk_points=int(data.get("risk_points", Severity.from_value(data.get("severity")).value)),
        selection=dict(data.get("selection", {})),
        mitre_attack=list(data.get("mitre_attack", [])),
        tags=list(data.get("tags", [])),
        enabled=bool(data.get("enabled", True)),
    )


def apply_rule_state(rules: list[DetectionRule], state: dict[str, bool]) -> list[DetectionRule]:
    """Overlay enable/disable state (e.g. from ``AutoSIEMStorage.rule_state_dict``)
    onto a freshly loaded list of rules.

    Rules with a persisted override get ``enabled`` from the stored value; all
    others keep whatever their rule file defined. Returns a new list.
    """
    updated: list[DetectionRule] = []
    for rule in rules:
        if rule.rule_id in state:
            rule.enabled = bool(state[rule.rule_id])
        updated.append(rule)
    return updated

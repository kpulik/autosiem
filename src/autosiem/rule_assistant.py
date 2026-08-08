"""Deterministic, local (stdlib-only) rule-drafting assistant.

Turns a plain-English description of a detection need into a rule JSON dict
that matches the on-disk rule-file schema (see ``rules/*.json``). Everything is
heuristic and offline: no ML, no network. The goal is a fast first draft a
detection engineer can review and refine, not a production-grade rule.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from itertools import count
from pathlib import Path
from typing import Any

from .schemas import Severity

# Keyword -> normalized category. Order matters: first match wins.
_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "authentication": (
        "login",
        "logon",
        "authentication",
        "credential",
        "password",
        "sign-in",
        "signin",
        "account lockout",
    ),
    "email": ("email", "mail", "phish", "phishing", "attachment", "mailbox", "message"),
    "cloud": ("cloud", "aws", "azure", "gcp", "bucket", "s3", "kubernetes", "saas"),
    "file": ("file", "download", "archive", "dropper", "exe dropped"),
    "process": ("process", "executable", "run command", "spawn", "powershell", "cmd"),
    "network": ("network", "connection", "traffic", "flow", "port", "dns", "socket", "transfer"),
    "endpoint": ("endpoint", "edr", "host agent", "device"),
}

# Description word(s) -> action keyword. First match wins.
_ACTION_KEYWORDS: dict[str, tuple[str, ...]] = {
    "failed": ("fail", "denied", "rejected", "error", "unsuccessful"),
    "success": ("success", "succeeded", "approved"),
    "start": ("start", "launch", "spawn", "began", "executed"),
    "phish": ("phish", "phishing", "malicious_email", "malware_email"),
    "dump": ("dump", "extract_credential", "credential_extraction", "hash_dump"),
    "delete": ("delete", "cleared", "wiped", "removed_logs"),
    "transfer": ("transfer", "exfil", "exfiltration", "outbound"),
}

# Severity words -> canonical severity string. First match wins.
_SEVERITY_WORDS: dict[str, tuple[str, ...]] = {
    "critical": ("critical", "urgent", "ransomware", "catastrophic"),
    "high": ("high", "severe", "malicious", "active_threat"),
    "low": ("low", "minor", "informational", "noise"),
}

# entity -> the normalized event field it maps to.
_FIELD_KEYWORDS: dict[str, tuple[str, ...]] = {
    "user": ("user", "account", "username", "login as"),
    "host": ("host", "endpoint", "hostname", "device"),
    "process": ("process", "executable", "program", "binary"),
    "command": ("command", "command_line", "commandline", "powershell"),
    "url": ("url", "domain", "uri"),
}

# action -> (operator, value) emitted into the selection so a normalized event
# with that action will actually match.
_ACTION_SELECTOR: dict[str, tuple[str, Any]] = {
    "failed": ("startswith", "fail"),
    "success": ("startswith", "success"),
    "start": ("startswith", "start"),
    "phish": ("contains_any", ["phish", "malicious", "spam"]),
    "dump": ("contains_any", ["dump", "credential", "hash"]),
    "delete": ("contains_any", ["delete", "clear", "wipe"]),
    "transfer": ("contains_any", ["transfer", "exfil", "outbound"]),
}

_next_id = count(1)


def _next_rule_id() -> str:
    return f"AUTO-GEN-{next(_next_id)}"


@dataclass
class SuggestedRule:
    """A generated rule draft plus a little explainable metadata."""

    rule: dict[str, Any]
    category: str = "unknown"
    action: str = "unknown"
    fields: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.rule,
            "suggestion": {
                "category": self.category,
                "action": self.action,
                "fields": self.fields,
                "note": self.note,
            },
        }


def _detect_category(text: str) -> str:
    lower = text.lower()
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(keyword in lower for keyword in keywords):
            return category
    return "unknown"


def _detect_action(text: str) -> str:
    lower = text.lower()
    for action, keywords in _ACTION_KEYWORDS.items():
        if any(keyword in lower for keyword in keywords):
            return action
    return "unknown"


def _detect_severity(text: str) -> Severity:
    lower = text.lower()
    for severity, words in _SEVERITY_WORDS.items():
        if any(word in lower for word in words):
            return Severity.from_value(severity)
    # phishing implies initial access -> default to high.
    if "phish" in lower:
        return Severity.HIGH
    return Severity.MEDIUM


def _detect_fields(text: str) -> list[str]:
    lower = text.lower()
    fields: list[str] = []
    for key, keywords in _FIELD_KEYWORDS.items():
        if any(keyword in lower for keyword in keywords):
            fields.append(key)
    return fields


def _build_selection(category: str, action: str) -> dict[str, Any]:
    selection: dict[str, Any] = {"category": category}
    if action != "unknown":
        operator, value = _ACTION_SELECTOR.get(action, ("startswith", action))
        selection["action"] = {operator: value}
    return selection


def _build_name(category: str, action: str) -> str:
    if action == "unknown":
        action = "activity"
    return f"{action.title()} {category} detected"


def _matching_value(expected: Any) -> Any:
    """A value that satisfies a selection operator/equality check."""
    if isinstance(expected, dict):
        for operator, value in expected.items():
            if operator in ("startswith", "contains", "equals", "regex"):
                return value
            if operator == "endswith":
                return "prefix-" + str(value)
            if operator in ("startswith_any", "contains_any", "in", "endswith_any"):
                items = value if isinstance(value, list) else [value]
                if operator == "endswith_any":
                    return "prefix-" + str(items[0]) if items else "prefix"
                return items[0] if items else ""
            if operator == "not_in":
                return "zzz-not-in"
            if operator == "not_equals":
                return "not-" + str(value)
            if operator == "exists":
                return "present" if bool(value) else None
        return ""
    if isinstance(expected, list):
        return expected[0] if expected else ""
    return expected


def _non_matching_value(expected: Any) -> Any:
    """A value that does NOT satisfy a selection operator/equality check."""
    if isinstance(expected, dict):
        for operator, value in expected.items():
            if operator == "exists":
                return None if bool(value) else "present"
            if operator in ("not_in", "not_equals"):
                return value if not isinstance(value, list) else value[0]
            if operator == "in":
                return "zzz-not-in-list"
            return "zzz-nonmatch"
        return "zzz-nonmatch"
    if isinstance(expected, list):
        return "zzz-not-in-list"
    return "zzz-other"


class RuleAssistant:
    """Deterministic local rule generator (stdlib only, no side effects)."""

    def draft_rule(self, description: str, techniques: list[str] | None = None) -> dict[str, Any]:
        """Produce a rule JSON dict matching the on-disk rule-file schema."""
        category = _detect_category(description)
        action = _detect_action(description)
        severity = _detect_severity(description)

        rule: dict[str, Any] = {
            "id": _next_rule_id(),
            "name": _build_name(category, action),
            "description": description.strip(),
            "severity": severity.name.lower(),
            "risk_points": severity.value,
            "selection": _build_selection(category, action),
            "mitre_attack": list(techniques or []),
            "tags": [category, action] if action != "unknown" else [category],
            "enabled": True,
        }
        return rule

    def draft_from_text(self, description: str, techniques: list[str] | None = None) -> SuggestedRule:
        category = _detect_category(description)
        action = _detect_action(description)
        rule = self.draft_rule(description, techniques)
        note = f"Detected category '{category}', action '{action}' from description."
        return SuggestedRule(
            rule=rule,
            category=category,
            action=action,
            fields=_detect_fields(description),
            note=note,
        )

    def generate_test_cases(self, rule: dict[str, Any]) -> list[dict[str, Any]]:
        """Build a positive event (should match) and a negative event (should not)."""
        selection = rule.get("selection", {})
        positive: dict[str, Any] = {key: _matching_value(expected) for key, expected in selection.items()}
        negative: dict[str, Any] = {}
        for key, expected in selection.items():
            if key == "category":
                positive_category = positive.get(key)
                negative[key] = "network" if positive_category != "network" else "unknown"
            else:
                negative[key] = _non_matching_value(expected)
        positive["should_match"] = True
        negative["should_match"] = False
        return [positive, negative]

    def write_rule_file(self, rule: dict[str, Any], out_dir: str | Path) -> Path:
        """Write ``<id>.json`` under ``out_dir`` for the generated rule."""
        directory = Path(out_dir)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{rule['id']}.json"
        path.write_text(json.dumps(rule, indent=2), encoding="utf-8")
        return path

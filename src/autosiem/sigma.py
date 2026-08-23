"""Sigma rule import/export: convert Sigma YAML rules into AutoSIEM
DetectionRules and back.

Sigma (https://sigmahq.io) is an open signature format for log events. This
module parses the small, regular subset of YAML that Sigma rules use -- without
pulling in a full PyYAML dependency -- and maps each rule onto our native
``DetectionRule`` selection schema. ``rule_to_sigma`` reverses the mapping so
our rules can be shared back to the Sigma ecosystem.

What we support (the common Sigma rule anatomy)::

    title, id, description, level, tags, logsource, detection

Detection mapping notes
-----------------------
* ``field|contains: x``      -> ``{"<field>": {"contains": x}}``
* ``field|contains: [a, b]`` -> ``{"<field>": {"contains_any": [a, b]}}``
* ``field|startswith: x``    -> ``{"<field>": {"startswith": x}}``
* ``field|endswith: x``      -> ``{"<field>": {"endswith": x}}``
* ``field|re: r``            -> ``{"<field>": {"regex": r}}``
* ``field: x`` (scalar)      -> ``{"<field>": x}``  (exact match)
* ``field: [a, b]``          -> ``{"<field>": {"in": [a, b]}}``
* ``keywords: [...]``        -> ``{"raw.message": {"contains_any": [...]}}``
* ``condition: selection and not filter`` negates a single-field filter exactly.

Sigma fields like ``CommandLine`` are lowercased and, where a well-known alias
exists, mapped to our schema (``CommandLine`` -> ``command_line``).
"""

from __future__ import annotations

from datetime import date
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
from typing import Any

from .schemas import DetectionRule, Severity

# Map well-known Sigma/Windows field names onto our snake_case schema. Field
# names not listed here are lowercased as-is.
_FIELD_ALIASES = {
    "commandline": "command_line",
    "processname": "process_name",
    "image": "process_name",
    "username": "user",
    "accountname": "user",
    "computername": "host",
    "hostname": "host",
    "sourceip": "src_ip",
    "ipaddress": "src_ip",
    "destinationip": "dst_ip",
    "user": "user",
    "host": "host",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "cloud_account": "cloud_account",
    "resource": "resource",
    "category": "category",
    "action": "action",
    "outcome": "outcome",
    "source": "source",
    "eventid": "event_code",
    "originalfilename": "original_file_name",
    "parentimage": "parent_process_name",
    "parentcommandline": "parent_command_line",
    "targetobject": "target_object",
    "targetfilename": "target_file_name",
    "scriptblocktext": "script_block_text",
    "imageloaded": "image_loaded",
    "providername": "provider_name",
    "provider_name": "provider_name",
    "integritylevel": "integrity_level",
}

# Modifiers that take a single string value.
_SINGLE_VALUE_MODIFIERS = {"contains", "startswith", "endswith", "re", "equals", "exists"}
# Modifiers that can take a list of values (any-of semantics).
_ANY_VALUE_MODIFIERS = {"contains"}

_CONDITION_TOKEN = re.compile(
    r"(?:1|all)\s+of\s+(?:them|[a-z0-9_*.-]+)|and\b|or\b|not\b|[a-z0-9_.-]+|[()]",
    re.IGNORECASE,
)
_BOOLEAN_SELECTION_KEYS = {"any_of", "all_of", "not"}


# ---------------------------------------------------------------------------
# Tiny YAML-subset parser
# ---------------------------------------------------------------------------
class SigmaParseError(ValueError):
    """Raised when the YAML-subset parser cannot understand a rule."""


def load_sigma_file(path: str | Path) -> DetectionRule:
    """Load a .yaml/.yml Sigma rule file and convert it to a DetectionRule."""
    text = Path(path).read_text(encoding="utf-8")
    data = parse_sigma_yaml(text)
    return sigma_to_rule(data)


def parse_sigma_yaml(text: str) -> dict[str, Any]:
    """Parse a Sigma YAML document into a plain dict.

    Indentation-sensitive, covering the mapping/list/scalar constructs Sigma
    uses. Throws ``SigmaParseError`` on input we cannot handle.
    """
    lines = _strip_comment_lines(text.splitlines())
    obj, _index = _parse_yaml_value(lines, 0, -1)
    if not isinstance(obj, dict):
        raise SigmaParseError("Sigma rule does not start with a mapping")
    return obj


def sigma_to_rule(data: dict[str, Any]) -> DetectionRule:
    """Convert a parsed Sigma mapping into our DetectionRule schema."""
    rule_id = str(data.get("id") or data.get("title") or "sigma-rule")
    name = str(data.get("title") or rule_id)
    description = str(data.get("description", ""))
    severity = Severity.from_value(str(data.get("level", "informational")))
    tags = _as_list(data.get("tags"))
    mitre_attack = _extract_mitre_attack(tags)

    detection = dict(data.get("detection") or {})
    selection = _sigma_detection_to_selection(detection)
    logsource_selection = _sigma_logsource_to_selection(dict(data.get("logsource") or {}))
    if logsource_selection:
        selection = _selection_all([logsource_selection, selection])

    return DetectionRule(
        rule_id=rule_id,
        name=name,
        description=description,
        severity=severity,
        risk_points=severity.value,
        selection=selection,
        mitre_attack=mitre_attack,
        tags=tags,
        enabled=True,
    )


def _sigma_logsource_to_selection(logsource: dict[str, Any]) -> dict[str, Any]:
    """Preserve Sigma product/service scope as normalized event predicates."""
    selection: dict[str, Any] = {}
    product = str(logsource.get("product") or "").strip().lower()
    service = str(logsource.get("service") or "").strip().lower()
    if product:
        selection["log_product"] = product
    if service:
        selection["log_service"] = service
    category = str(logsource.get("category") or "").strip().lower()
    category_aliases = {
        "process_creation": "process",
        "network_connection": "network",
        "dns_query": "dns",
        "file_event": "file",
        "file_change": "file",
        "file_delete": "file",
        "image_load": "process",
        "ps_script": "process",
    }
    if category in category_aliases:
        selection["category"] = category_aliases[category]
    return selection


# ---------------------------------------------------------------------------
# YAML-subset parser internals
# ---------------------------------------------------------------------------
def _strip_comment_lines(lines: list[str]) -> list[str]:
    """Drop full-line comments and blank lines; trim trailing comments."""
    cleaned: list[str] = []
    for line in lines:
        stripped = _strip_trailing_comment(line).rstrip()
        if not stripped:
            continue
        cleaned.append(stripped)
    return cleaned


def _strip_trailing_comment(line: str) -> str:
    in_quotes: str | None = None
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if in_quotes == '"' and ch == "\\":
            escaped = True
            continue
        if ch in ('"', "'"):
            if in_quotes is None:
                in_quotes = ch
            elif in_quotes == ch:
                in_quotes = None
        elif ch == "#" and in_quotes is None:
            return line[:i]
    return line


def _parse_yaml_value(lines: list[str], i: int, parent_indent: int) -> tuple[Any, int]:
    """Dispatch the next construct starting at index ``i``."""
    if i >= len(lines):
        return None, i
    line = lines[i]
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    if indent <= parent_indent:
        return None, i
    if stripped.startswith("- "):
        return _parse_yaml_list(lines, i, indent)
    key, _val = _split_mapping(stripped)
    if key and key != stripped:
        # A colon was found outside quotes -> this line opens a mapping.
        return _parse_yaml_dict(lines, i, indent)
    # A bare scalar on its own line (rare at rule top level).
    return _parse_scalar(stripped), i + 1


def _parse_yaml_dict(lines: list[str], i: int, base_indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped:
            i += 1
            continue
        indent = len(line) - len(stripped)
        if indent < base_indent:
            break
        if indent > base_indent:
            # Continuation of a multi-line scalar -- not expected in Sigma.
            i += 1
            continue

        key, val = _split_mapping(stripped)
        if val == "":
            next_indent = _peek_content_indent(lines, i + 1)
            if next_indent > base_indent:
                nested, i = _parse_yaml_value(lines, i + 1, base_indent)
                result[key] = nested
            else:
                result[key] = None
                i += 1
        else:
            result[key] = _parse_scalar(val)
            i += 1
    return result, i


def _parse_yaml_list(lines: list[str], i: int, base_indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped:
            i += 1
            continue
        indent = len(line) - len(stripped)
        if indent < base_indent:
            break
        if indent > base_indent or not stripped.startswith("- "):
            break

        content = stripped[2:].strip()
        if content == "":
            next_indent = _peek_content_indent(lines, i + 1)
            if next_indent > base_indent:
                nested, i = _parse_yaml_value(lines, i + 1, base_indent)
                result.append(nested)
            else:
                result.append(None)
                i += 1
            continue

        key, val = _split_mapping(content)
        if key and key != content:
            item_dict: dict[str, Any] = {}
            if val == "":
                next_indent = _peek_content_indent(lines, i + 1)
                if next_indent > base_indent:
                    nested, i = _parse_yaml_value(lines, i + 1, base_indent)
                    item_dict[key] = nested
                else:
                    item_dict[key] = None
                    i += 1
            else:
                item_dict[key] = _parse_scalar(val)
                i += 1
            # Collect sibling keys belonging to the same list-item mapping.
            item_dict = _collect_sibling_keys(lines, i, base_indent, item_dict)
            result.append(item_dict)
        else:
            result.append(_parse_scalar(content))
            i += 1
    return result, i


def _collect_sibling_keys(lines: list[str], i: int, base_indent: int, item: dict[str, Any]) -> dict[str, Any]:
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped:
            i += 1
            continue
        indent = len(line) - len(stripped)
        if indent <= base_indent:
            break
        if indent == base_indent and stripped.startswith("- "):
            break
        key, val = _split_mapping(stripped)
        if key and key != stripped:
            if val == "":
                next_indent = _peek_content_indent(lines, i + 1)
                if next_indent > indent:
                    nested, i = _parse_yaml_value(lines, i + 1, indent)
                    item[key] = nested
                else:
                    item[key] = None
                    i += 1
            else:
                item[key] = _parse_scalar(val)
                i += 1
        else:
            i += 1
    return item


def _peek_content_indent(lines: list[str], start: int) -> int:
    for j in range(start, len(lines)):
        stripped = lines[j].lstrip()
        if stripped:
            return len(lines[j]) - len(stripped)
    return 0


def _split_mapping(text: str) -> tuple[str, str]:
    """Split ``key: value`` on the first colon outside quotes."""
    in_quotes: str | None = None
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if in_quotes == '"' and ch == "\\":
            escaped = True
            continue
        if ch in ('"', "'"):
            if in_quotes is None:
                in_quotes = ch
            elif in_quotes == ch:
                in_quotes = None
        elif ch == ":" and in_quotes is None:
            return text[:i].strip(), text[i + 1 :].strip()
    return text.strip(), ""


def _parse_scalar(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text[1:-1]
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1].replace("''", "'")
    if text.startswith("[") and text.endswith("]"):
        return _parse_inline_list(text)
    lower = text.lower()
    if lower in {"true", "yes"}:
        return True
    if lower in {"false", "no"}:
        return False
    if lower in {"null", "~", "none"}:
        return None
    # Numeric detection (int or float), keeping Sigma-ish plain values as strings.
    try:
        if text.isdigit():
            return int(text)
        if _is_float(text):
            return float(text)
    except ValueError:
        pass
    return text


def _is_float(text: str) -> bool:
    try:
        float(text)
        return any(c in text for c in ".eE")
    except ValueError:
        return False


def _parse_inline_list(text: str) -> list[Any]:
    inner = text[1:-1]
    items: list[str] = []
    current = ""
    in_quotes: str | None = None
    escaped = False
    for ch in inner:
        if escaped:
            current += ch
            escaped = False
            continue
        if in_quotes == '"' and ch == "\\":
            current += ch
            escaped = True
            continue
        if ch in ('"', "'"):
            if in_quotes is None:
                in_quotes = ch
            elif in_quotes == ch:
                in_quotes = None
            current += ch
        elif ch == "," and in_quotes is None:
            items.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        items.append(current.strip())
    return [_parse_scalar(item) for item in items]


# ---------------------------------------------------------------------------
# Sigma detection -> our selection
# ---------------------------------------------------------------------------
def _sigma_detection_to_selection(detection: dict[str, Any]) -> dict[str, Any]:
    """Convert a Sigma ``detection`` block into our selection map.

    Supports named blocks, parentheses, ``not``/``and``/``or``, and Sigma's
    ``1 of``/``all of`` wildcard quantifiers. The result is a recursive
    selection using ``any_of``/``all_of``/``not`` where a flat map cannot
    preserve the condition exactly.
    """
    if not detection:
        return {}
    condition = str(detection.get("condition", "selection"))
    return _ConditionParser(detection, condition).parse()


class _ConditionParser:
    """Recursive-descent parser for the Boolean subset used by Sigma rules."""

    def __init__(self, detection: dict[str, Any], condition: str) -> None:
        self.detection = detection
        self.tokens = _tokenize_condition(condition)
        self.index = 0

    def parse(self) -> dict[str, Any]:
        if not self.tokens:
            raise SigmaParseError("Sigma detection condition is empty")
        selection = self._parse_or()
        if self.index != len(self.tokens):
            raise SigmaParseError(f"unexpected condition token {self.tokens[self.index]!r}")
        return selection

    def _parse_or(self) -> dict[str, Any]:
        parts = [self._parse_and()]
        while self._peek() == "or":
            self.index += 1
            parts.append(self._parse_and())
        return _selection_any(parts)

    def _parse_and(self) -> dict[str, Any]:
        parts = [self._parse_not()]
        while self._peek() == "and":
            self.index += 1
            parts.append(self._parse_not())
        return _selection_all(parts)

    def _parse_not(self) -> dict[str, Any]:
        if self._peek() == "not":
            self.index += 1
            return _selection_not(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> dict[str, Any]:
        token = self._take()
        if token == "(":
            selection = self._parse_or()
            if self._take() != ")":
                raise SigmaParseError("unclosed parenthesis in Sigma condition")
            return selection
        if token == ")":
            raise SigmaParseError("unexpected closing parenthesis in Sigma condition")
        if token.startswith("1 of ") or token.startswith("all of "):
            quantifier, pattern = token.split(" of ", 1)
            selections = [self._block(name) for name in self._matching_blocks(pattern)]
            return _selection_any(selections) if quantifier == "1" else _selection_all(selections)
        return self._block(token)

    def _matching_blocks(self, pattern: str) -> list[str]:
        candidates = [
            str(name)
            for name, value in self.detection.items()
            if str(name).lower() not in {"condition", "timeframe"} and value is not None
        ]
        if pattern == "them":
            matches = candidates
        else:
            matches = [name for name in candidates if fnmatchcase(name.lower(), pattern)]
        if not matches:
            raise SigmaParseError(f"condition pattern {pattern!r} matched no detection blocks")
        return matches

    def _block(self, requested: str) -> dict[str, Any]:
        requested_key = requested.lower()
        names = {str(name).lower(): str(name) for name in self.detection}
        if requested_key not in names or requested_key in {"condition", "timeframe"}:
            raise SigmaParseError(f"condition references unknown detection block {requested!r}")
        name = names[requested_key]
        value = self.detection[name]
        if requested_key == "keywords":
            if isinstance(value, dict):
                return _sigma_fields_to_selection(value)
            return _sigma_fields_to_selection({"keywords": value})
        if value is None and requested_key == "selection":
            return {}
        if isinstance(value, list):
            if all(not isinstance(item, dict) for item in value):
                return {"raw.message": {"contains_any": _as_strings(value)}}
            branches: list[dict[str, Any]] = []
            for item in value:
                if not isinstance(item, dict):
                    raise SigmaParseError(f"detection block {name!r} has a non-mapping alternative")
                branches.append(_sigma_fields_to_selection(item))
            if not branches:
                raise SigmaParseError(f"detection block {name!r} has no alternatives")
            return _selection_any(branches)
        if not isinstance(value, dict):
            raise SigmaParseError(f"detection block {name!r} is not a field mapping")
        return _sigma_fields_to_selection(value)

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise SigmaParseError("unexpected end of Sigma condition")
        self.index += 1
        return token


def _tokenize_condition(condition: str) -> list[str]:
    normalized = condition.lower().strip()
    tokens: list[str] = []
    position = 0
    for match in _CONDITION_TOKEN.finditer(normalized):
        if normalized[position : match.start()].strip():
            raise SigmaParseError(f"unsupported Sigma condition syntax near {normalized[position:]!r}")
        tokens.append(" ".join(match.group(0).split()))
        position = match.end()
    if normalized[position:].strip():
        raise SigmaParseError(f"unsupported Sigma condition syntax near {normalized[position:]!r}")
    return tokens


def _selection_any(parts: list[dict[str, Any]]) -> dict[str, Any]:
    flattened: list[dict[str, Any]] = []
    for part in parts:
        if set(part) == {"any_of"} and isinstance(part["any_of"], list):
            flattened.extend(part["any_of"])
        else:
            flattened.append(part)
    return flattened[0] if len(flattened) == 1 else {"any_of": flattened}


def _selection_all(parts: list[dict[str, Any]]) -> dict[str, Any]:
    flattened: list[dict[str, Any]] = []
    for part in parts:
        if set(part) == {"all_of"} and isinstance(part["all_of"], list):
            flattened.extend(part["all_of"])
        else:
            flattened.append(part)
    if len(flattened) == 1:
        return flattened[0]
    if all(not _BOOLEAN_SELECTION_KEYS.intersection(part) for part in flattened):
        merged: dict[str, Any] = {}
        try:
            for part in flattened:
                for field, expected in part.items():
                    _merge_selection_predicate(merged, field, expected)
        except SigmaParseError:
            pass
        else:
            return merged
    return {"all_of": flattened}


def _selection_not(selection: dict[str, Any]) -> dict[str, Any]:
    if set(selection) == {"not"} and isinstance(selection["not"], dict):
        return selection["not"]
    if not _BOOLEAN_SELECTION_KEYS.intersection(selection) and len(selection) == 1:
        (field, expected), = selection.items()
        return {field: _negate_expected(expected)}
    return {"not": selection}


def _merge_selection_predicate(selection: dict[str, Any], field: str, expected: Any) -> None:
    """AND one field predicate into a flat selection without overwriting it."""
    if field not in selection:
        selection[field] = expected
        return

    current = selection[field]
    current_operators = current if isinstance(current, dict) else {"equals": current}
    new_operators = expected if isinstance(expected, dict) else {"equals": expected}
    duplicate = set(current_operators).intersection(new_operators)
    if duplicate:
        names = ", ".join(sorted(duplicate))
        raise SigmaParseError(f"multiple {names} predicates for field {field!r} cannot be represented")
    selection[field] = {**current_operators, **new_operators}


def _negate_expected(expected: Any) -> dict[str, Any]:
    """Express a single-field ``not <filter value>`` exactly."""
    if isinstance(expected, dict):
        if len(expected) != 1:
            raise SigmaParseError(f"multi-operator filter cannot be negated exactly: {expected!r}")
        (operator, value), = expected.items()
        opposites = {
            "equals": "not_equals",
            "in": "not_in",
            "contains": "not_contains",
            "contains_any": "not_contains_any",
            "contains_all": "not_contains_all",
            "startswith": "not_startswith",
            "startswith_any": "not_startswith_any",
            "startswith_all": "not_startswith_all",
            "endswith": "not_endswith",
            "endswith_any": "not_endswith_any",
            "endswith_all": "not_endswith_all",
            "regex": "not_regex",
            "not_equals": "equals",
            "not_in": "in",
            "not_contains": "contains",
            "not_contains_any": "contains_any",
            "not_contains_all": "contains_all",
            "not_startswith": "startswith",
            "not_startswith_any": "startswith_any",
            "not_startswith_all": "startswith_all",
            "not_endswith": "endswith",
            "not_endswith_any": "endswith_any",
            "not_endswith_all": "endswith_all",
            "not_regex": "regex",
        }
        if operator == "exists":
            return {"exists": not bool(value)}
        if operator not in opposites:
            raise SigmaParseError(f"filter operator {operator!r} cannot be negated exactly")
        return {opposites[operator]: value}
    return {"not_equals": expected}


def _sigma_fields_to_selection(fields: dict[str, Any]) -> dict[str, Any]:
    selection: dict[str, Any] = {}
    for raw_key, value in fields.items():
        if raw_key == "keywords":
            selection["raw.message"] = {"contains_any": _as_list(value)}
            continue
        field, modifier = _parse_field_key(raw_key)
        selection[field] = _map_field_value(value, modifier)
    return selection


def _parse_field_key(raw_key: str) -> tuple[str, str | None]:
    key = raw_key.strip()
    if len(key) >= 2 and key[0] == key[-1] and key[0] in {"'", '"'}:
        key = key[1:-1]
    parts = [part.strip().lower() for part in key.split("|")]
    field = _normalize_field_name(parts[0])
    modifiers = parts[1:]
    supported_modifiers = _SINGLE_VALUE_MODIFIERS | {"all"}
    unsupported = [item for item in modifiers if item and item not in supported_modifiers]
    if unsupported:
        raise SigmaParseError(
            f"unsupported modifier(s) {', '.join(unsupported)} on Sigma field {parts[0]!r}"
        )
    modifier = next((item for item in modifiers if item in _SINGLE_VALUE_MODIFIERS), None)
    if not field and "all" in modifiers:
        modifier = "contains_all"
    elif modifier in {"contains", "startswith", "endswith"} and "all" in modifiers:
        modifier += "_all"
    elif "all" in modifiers:
        raise SigmaParseError(f"modifier 'all' needs contains/startswith/endswith on field {field!r}")
    if not field:
        field = "raw.message"
    return field, modifier


def _map_field_value(value: Any, modifier: str | None) -> Any:
    if modifier == "contains":
        if isinstance(value, list):
            return {"contains_any": _as_strings(value)}
        return {"contains": str(value)}
    if modifier == "contains_all":
        return {"contains_all": _as_strings(_as_list(value))}
    if modifier == "startswith":
        if isinstance(value, list):
            return {"startswith_any": _as_strings(value)}
        return {"startswith": str(value)}
    if modifier == "startswith_all":
        return {"startswith_all": _as_strings(_as_list(value))}
    if modifier == "endswith":
        if isinstance(value, list):
            return {"endswith_any": _as_strings(value)}
        return {"endswith": str(value)}
    if modifier == "endswith_all":
        return {"endswith_all": _as_strings(_as_list(value))}
    if modifier == "re":
        return {"regex": str(value)}
    if modifier == "equals":
        return str(value)
    if modifier == "exists":
        return {"exists": bool(value)}
    if isinstance(value, list):
        return {"in": _as_list(value)}
    return value


def _normalize_field_name(name: str) -> str:
    lowered = name.strip().lower()
    return _FIELD_ALIASES.get(lowered, lowered)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_strings(values: list[Any]) -> list[str]:
    return [str(v) for v in values]


def _extract_mitre_attack(tags: list[Any]) -> list[str]:
    result: list[str] = []
    for tag in tags:
        text = str(tag).strip().lower()
        if text.startswith("attack.t"):
            technique = text[len("attack.t") :].upper()
            result.append(f"T{technique}")
    return result


# ---------------------------------------------------------------------------
# Sigma rule export
# ---------------------------------------------------------------------------
def rule_to_sigma(rule: DetectionRule) -> str:
    """Serialize a DetectionRule as a Sigma YAML rule.

    Round-trips through :func:`sigma_to_rule` for the supported operator set,
    except ``tags``/``risk_points``: Sigma has no risk field, so import derives
    ``risk_points`` from the level (lossy by design). Negated predicates are
    emitted as a ``filter`` group with
    ``condition: selection and not filter``.
    """
    lines: list[str] = [
        f"title: {_yaml_scalar(rule.name)}",
        f"id: {_yaml_scalar(rule.rule_id)}",
        "status: stable",
        f"description: {_yaml_scalar(rule.description)}",
        "author: AutoSIEM",
        f"date: {date.today().strftime('%Y/%m/%d')}",
        "logsource:",
        "  category: unspecified",
        "detection:",
    ]
    if _requires_structured_export(rule.selection):
        blocks, condition = _export_boolean_detection(rule.selection)
        for block_name, fields in blocks:
            lines.append(f"  {block_name}:")
            for field, expected in fields.items():
                lines.append(_export_field(field, expected, "  "))
        lines.append(f"  condition: {condition}")
    else:
        selection, filters = _split_selection(rule.selection)
        lines.append("  selection:")
        for field, expected in selection.items():
            lines.append(_export_field(field, expected, "  "))
        if filters:
            filter_names = (
                ["filter"]
                if len(filters) == 1
                else [f"filter_{index}" for index in range(1, len(filters) + 1)]
            )
            for filter_name, (field, expected) in zip(filter_names, filters.items()):
                lines.append(f"  {filter_name}:")
                lines.append(_export_field(field, expected, "  "))
            condition = " and ".join(["selection", *(f"not {name}" for name in filter_names)])
            lines.append(f"  condition: {condition}")
        else:
            lines.append("  condition: selection")
    lines.append(f"level: {rule.severity.name.lower()}")
    tags = _sigma_tags(rule)
    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"  - {_yaml_scalar(tag)}")
    return "\n".join(lines) + "\n"


def _contains_boolean_selection(selection: Any) -> bool:
    if isinstance(selection, dict):
        if _BOOLEAN_SELECTION_KEYS.intersection(selection):
            return True
        return any(_contains_boolean_selection(value) for value in selection.values())
    if isinstance(selection, list):
        return any(_contains_boolean_selection(value) for value in selection)
    return False


def _requires_structured_export(selection: Any) -> bool:
    if _contains_boolean_selection(selection):
        return True
    if isinstance(selection, dict):
        return any(isinstance(value, dict) and len(value) > 1 for value in selection.values())
    return False


def _export_boolean_detection(
    selection: dict[str, Any],
) -> tuple[list[tuple[str, dict[str, Any]]], str]:
    """Turn a Boolean selection tree into named Sigma detection blocks."""
    blocks: list[tuple[str, dict[str, Any]]] = []
    selection_index = 0
    filter_index = 0

    def add_block(prefix: str, fields: dict[str, Any]) -> str:
        nonlocal selection_index, filter_index
        if prefix == "selection":
            selection_index += 1
            name = f"selection_{selection_index}"
        else:
            filter_index += 1
            name = f"filter_{filter_index}"
        blocks.append((name, fields))
        return name

    def emit(node: dict[str, Any]) -> str:
        terms: list[str] = []
        fields = {key: value for key, value in node.items() if key not in _BOOLEAN_SELECTION_KEYS}
        if fields:
            include, filters = _split_selection(fields)
            simple_include: dict[str, Any] = {}
            for field, expected in include.items():
                if isinstance(expected, dict) and len(expected) > 1:
                    for operator, value in expected.items():
                        terms.append(add_block("selection", {field: {operator: value}}))
                else:
                    simple_include[field] = expected
            if simple_include:
                terms.append(add_block("selection", simple_include))
            for field, expected in filters.items():
                if isinstance(expected, dict) and len(expected) > 1:
                    for operator, value in expected.items():
                        terms.append(f"not {add_block('filter', {field: {operator: value}})}")
                else:
                    terms.append(f"not {add_block('filter', {field: expected})}")
        any_of = node.get("any_of")
        if any_of is not None:
            if not isinstance(any_of, list) or not all(isinstance(item, dict) for item in any_of):
                raise ValueError("any_of must contain selection mappings")
            terms.append("(" + " or ".join(emit(item) for item in any_of) + ")")
        all_of = node.get("all_of")
        if all_of is not None:
            if not isinstance(all_of, list) or not all(isinstance(item, dict) for item in all_of):
                raise ValueError("all_of must contain selection mappings")
            terms.append("(" + " and ".join(emit(item) for item in all_of) + ")")
        negated = node.get("not")
        if negated is not None:
            if not isinstance(negated, dict):
                raise ValueError("not must contain a selection mapping")
            terms.append(f"not ({emit(negated)})")
        if not terms:
            raise ValueError("cannot export an empty Boolean selection")
        return terms[0] if len(terms) == 1 else "(" + " and ".join(terms) + ")"

    return blocks, emit(selection)


def export_rules(rules: list[DetectionRule], out_dir: str | Path) -> list[Path]:
    """Write each rule as ``<rule_id>.yaml`` under ``out_dir`` (created if needed)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for rule in rules:
        path = out / f"{rule.rule_id}.yaml"
        path.write_text(rule_to_sigma(rule), encoding="utf-8")
        written.append(path)
    return written


def _split_selection(selection: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Partition selection into an include map and a Sigma ``filter`` map.

    Negative operators become their positive equivalents in a negated filter
    group so the emitted rule reads ``condition: selection and not filter``.
    """
    negative_to_positive = {
        "not_equals": "equals",
        "not_in": "in",
        "not_contains": "contains",
        "not_contains_any": "contains_any",
        "not_contains_all": "contains_all",
        "not_startswith": "startswith",
        "not_startswith_any": "startswith_any",
        "not_startswith_all": "startswith_all",
        "not_endswith": "endswith",
        "not_endswith_any": "endswith_any",
        "not_endswith_all": "endswith_all",
        "not_regex": "regex",
    }
    include: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    for field, expected in selection.items():
        if not isinstance(expected, dict):
            include[field] = expected
            continue

        include_operators: dict[str, Any] = {}
        filter_operators: dict[str, Any] = {}
        for operator, value in expected.items():
            if operator in negative_to_positive:
                filter_operators[negative_to_positive[operator]] = value
            elif operator == "exists" and value is False:
                filter_operators["exists"] = True
            else:
                include_operators[operator] = value
        if include_operators:
            include[field] = include_operators
        if filter_operators:
            filters[field] = filter_operators
    return include, filters


def _sigma_tags(rule: DetectionRule) -> list[str]:
    """Sigma tags for a rule: its own tags (minus already-emitted ATT&CK ones)."""
    tags = [str(t) for t in rule.tags if not str(t).strip().lower().startswith("attack.t")]
    for technique in rule.mitre_attack:
        tags.append(f"attack.t{str(technique).lower().removeprefix('t')}")
    return tags


def _export_field(field: str, expected: Any, base_indent: str) -> str:
    """Emit one ``<field>: <value>`` line (or block) for a selection/filter entry."""
    indent = base_indent + "  "
    if field == "raw.message" and isinstance(expected, dict) and len(expected) == 1 and "contains_any" in expected:
        return f"{indent}keywords:\n{_block_list(_as_list(expected['contains_any']), indent + '  ')}"
    if field == "raw.message" and isinstance(expected, dict) and len(expected) == 1 and "contains_all" in expected:
        return f"{indent}'|all':\n{_block_list(_as_list(expected['contains_all']), indent + '  ')}"
    if isinstance(expected, dict):
        if len(expected) != 1:
            raise ValueError(f"cannot export multi-operator selection for {field!r}: {expected!r}")
        (operator, value), = expected.items()
        if operator == "contains_any":
            return f"{indent}{field}|contains:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "contains":
            return f"{indent}{field}|contains: {_yaml_scalar(value)}"
        if operator == "contains_all":
            return f"{indent}{field}|contains|all:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "startswith_any":
            return f"{indent}{field}|startswith:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "startswith":
            return f"{indent}{field}|startswith: {_yaml_scalar(value)}"
        if operator == "startswith_all":
            return f"{indent}{field}|startswith|all:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "endswith_any":
            return f"{indent}{field}|endswith:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "endswith":
            return f"{indent}{field}|endswith: {_yaml_scalar(value)}"
        if operator == "endswith_all":
            return f"{indent}{field}|endswith|all:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "regex":
            return f"{indent}{field}|re: {_yaml_scalar(value)}"
        if operator == "in":
            return f"{indent}{field}:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "equals":
            return f"{indent}{field}: {_yaml_scalar(value)}"
        if operator == "exists":
            return f"{indent}{field}|exists: {_yaml_scalar(value)}"
        raise ValueError(f"cannot export selection operator {operator!r} for field {field!r}")
    if isinstance(expected, list):
        return f"{indent}{field}:\n{_block_list(_as_list(expected), indent + '  ')}"
    return f"{indent}{field}: {_yaml_scalar(expected)}"


def _block_list(values: list[Any], indent: str) -> str:
    return "\n".join(f"{indent}- {_yaml_scalar(v)}" for v in values)


def _needs_quoting(text: str) -> bool:
    """True when the scalar must be quoted to survive a YAML round-trip."""
    if not text:
        return True
    if text != text.strip():  # the parser strips surrounding whitespace
        return True
    if text.isdigit() or _is_float(text):  # else "3389" re-imports as an int
        return True
    if text.lower() in {"true", "false", "yes", "no", "null", "none", "~"}:
        return True
    if text[0] in "-?[]{}#&*!|>'\"%@\\":
        return True
    if ":" in text or "#" in text:
        return True
    if "[]" in text or "{}" in text:
        return True
    return False


def _yaml_scalar(value: Any) -> str:
    """Render a scalar so a round-trip through our YAML-subset parser is lossless.

    Backslash-heavy strings (Windows paths) are single-quoted -- our parser
    strips quotes without unescaping, so double-quoted ``\\p`` would not survive.
    Everything else that needs quoting uses double quotes with backslash and
    double-quote escaping, which is valid for external Sigma consumers.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    text = str(value)
    if not _needs_quoting(text):
        return text
    if "\\" in text and "'" not in text:
        return "'" + text + "'"
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

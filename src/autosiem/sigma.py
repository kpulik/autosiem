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
* ``condition: selection and not filter`` negates the filter fields.

Sigma fields like ``CommandLine`` are lowercased and, where a well-known alias
exists, mapped to our schema (``CommandLine`` -> ``command_line``).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
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
}

# Modifiers that take a single string value.
_SINGLE_VALUE_MODIFIERS = {"contains", "startswith", "endswith", "re", "equals"}
# Modifiers that can take a list of values (any-of semantics).
_ANY_VALUE_MODIFIERS = {"contains"}


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
    for i, ch in enumerate(line):
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
    for i, ch in enumerate(text):
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
        return text[1:-1]
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1]
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
    for ch in inner:
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

    Handles the AND-chain conditions used by most rules: ``selection``,
    ``selection and filter``, ``selection and not filter``, and
    ``selection and keywords``. OR-style conditions (``1 of selection*``,
    ``selection or filter``) are approximated using the plain selection block.
    """
    condition = str(detection.get("condition", "selection"))
    normalized = condition.lower().strip().replace("  ", " ")

    if " or " in normalized or " of " in normalized:
        # OR-across-selections / correlation counts are not supported yet;
        # approximate with just the selection block.
        return _sigma_fields_to_selection(dict(detection.get("selection") or {}))

    sel: dict[str, Any] = {}
    for token in (part.strip() for part in normalized.split(" and ")):
        negate = False
        block = token
        if token.startswith("not "):
            negate = True
            block = token[4:].strip()
        if block == "keywords":
            sel.update(_sigma_fields_to_selection({"keywords": detection.get("keywords")}))
            continue
        mapped = _sigma_fields_to_selection(dict(detection.get(block) or {}))
        if negate:
            for field, expected in mapped.items():
                sel[field] = _negate_expected(expected)
        else:
            sel.update(mapped)
    return sel


def _negate_expected(expected: Any) -> dict[str, Any]:
    """Express ``not <filter value>`` using our selection operators.

    Handles exact-match and in-list filters cleanly; falls back to a best-effort
    ``not_equals`` on the serialized value for operator-style filters.
    """
    if isinstance(expected, dict):
        if "equals" in expected:
            return {"not_equals": expected["equals"]}
        if "in" in expected:
            return {"not_in": list(expected["in"])}
        return {"not_equals": str(expected)}
    return {"not_equals": str(expected)}


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
    parts = [part.strip() for part in raw_key.split("|")]
    field = _normalize_field_name(parts[0])
    modifier = parts[1] if len(parts) > 1 else None
    # Keep only the last modifier if multiple are stacked; main ones we know.
    if modifier and modifier not in _SINGLE_VALUE_MODIFIERS and modifier not in _ANY_VALUE_MODIFIERS and modifier not in {"re"}:
        modifier = None
    return field, modifier


def _map_field_value(value: Any, modifier: str | None) -> Any:
    if modifier == "contains":
        if isinstance(value, list):
            return {"contains_any": _as_strings(value)}
        return {"contains": str(value)}
    if modifier == "startswith":
        if isinstance(value, list):
            return {"startswith_any": _as_strings(value)}
        return {"startswith": str(value)}
    if modifier == "endswith":
        if isinstance(value, list):
            return {"endswith_any": _as_strings(value)}
        return {"endswith": str(value)}
    if modifier == "re":
        return {"regex": str(value)}
    if modifier == "equals":
        return str(value)
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
    ``risk_points`` from the level (lossy by design). Negated predicates
    (``not_equals``/``not_in``/``exists: False``) are emitted as a ``filter``
    group with ``condition: selection and not filter``.
    """
    selection, filters = _split_selection(rule.selection)
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
        "  selection:",
    ]
    for field, expected in selection.items():
        lines.append(_export_field(field, expected, "  "))
    if filters:
        lines.append("  filter:")
        for field, expected in filters.items():
            lines.append(_export_field(field, expected, "  "))
        lines.append("  condition: selection and not filter")
    else:
        lines.append("  condition: selection")
    lines.append(f"level: {rule.severity.name.lower()}")
    tags = _sigma_tags(rule)
    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"  - {_yaml_scalar(tag)}")
    return "\n".join(lines) + "\n"


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

    ``not_equals``/``not_in``/``exists: False`` become a negated filter group so
    the emitted rule reads ``condition: selection and not filter``.
    """
    include: dict[str, Any] = {}
    filters: dict[str, Any] = {}
    for field, expected in selection.items():
        if isinstance(expected, dict) and len(expected) == 1:
            (operator, value), = expected.items()
            if operator == "not_equals":
                filters[field] = value
                continue
            if operator == "not_in":
                filters[field] = value
                continue
            if operator == "exists" and value is False:
                filters[field] = False
                continue
        include[field] = expected
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
    if isinstance(expected, dict):
        if len(expected) != 1:
            raise ValueError(f"cannot export multi-operator selection for {field!r}: {expected!r}")
        (operator, value), = expected.items()
        if operator == "contains_any":
            return f"{indent}{field}|contains:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "contains":
            return f"{indent}{field}|contains: {_yaml_scalar(value)}"
        if operator == "startswith_any":
            return f"{indent}{field}|startswith:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "startswith":
            return f"{indent}{field}|startswith: {_yaml_scalar(value)}"
        if operator == "endswith_any":
            return f"{indent}{field}|endswith:\n{_block_list(_as_list(value), indent + '  ')}"
        if operator == "endswith":
            return f"{indent}{field}|endswith: {_yaml_scalar(value)}"
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
    if text[0] in "-?[]{}#&*!|>'\"%@\\":
        return True
    if text[-1] == ":" or ": " in text or " #" in text:
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
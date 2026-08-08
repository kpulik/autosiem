"""Natural-language → search DSL translation (zero runtime dependencies).

A deterministic translator that maps analyst phrases onto the existing search
DSL used by the CLI (``--query``, ``--entity``, ``--status``) and the API.
An LLM-assisted path can pre-process free text and then call :func:`translate_query`
to normalize it into the same canonical shape.
"""

from __future__ import annotations

import re
from typing import Any

_ENTITY_RE = re.compile(
    r"\b(?:user|host|ip)\s*[:=]?\s*([\w@.\-]+)",
    re.IGNORECASE,
)
_USER_RE = re.compile(r"\buser\s+([\w@.\-]+)\b", re.IGNORECASE)
_HOST_RE = re.compile(r"\bhost\s+([\w.\-]+)\b", re.IGNORECASE)
_IP_RE = re.compile(r"\bip\s+([\d.:a-fA-F]+)\b", re.IGNORECASE)
_STATUS_WORDS = {
    "open": "open",
    "opened": "open",
    "investigating": "investigating",
    "in progress": "investigating",
    "resolved": "resolved",
    "closed": "closed",
    "done": "closed",
}
_RULE_RE = re.compile(r"\brule\s+([A-Za-z0-9\-]+)\b", re.IGNORECASE)
_SOURCE_RE = re.compile(r"\b(?:from|source\s*[:=])\s*([\w\-]+)\b", re.IGNORECASE)
_TIMEFRAME_RE = re.compile(
    r"\b(?:last\s+)?(\d+)\s*(hours?|hrs?|h|days?|d|weeks?|wks?|months?)\b|\btoday\b",
    re.IGNORECASE,
)
_LIMIT_RE = re.compile(r"\b(?:top|limit)\s+(\d+)\b", re.IGNORECASE)

_STATUS_TRIGGERS = ("status", "open", "investigating", "resolved", "closed")


def translate_query(text: str) -> dict[str, Any]:
    """Translate a natural-language query into the canonical search DSL dict."""
    result: dict[str, Any] = {
        "query": None,
        "entity": None,
        "status": None,
        "rule": None,
        "source": None,
        "limit": None,
        "timeframe": None,
    }
    if not text:
        return result

    lowered = text.lower()

    # Entity: prefer explicit `user:alice`-style tokens, then phrase forms.
    for match in _ENTITY_RE.finditer(text):
        token = match.group(1)
        prefix = match.group(0).lower().lstrip()
        if prefix.startswith("user") or "user" in prefix[:6]:
            result["entity"] = f"user:{token}"
            break
        if prefix.startswith("host") or "host" in prefix[:6]:
            result["entity"] = f"host:{token}"
            break
        if prefix.startswith("ip") or "ip" in prefix[:4]:
            result["entity"] = f"ip:{token}"
            break
    if result["entity"] is None:
        user = _USER_RE.search(text)
        host = _HOST_RE.search(text)
        ip = _IP_RE.search(text)
        if user:
            result["entity"] = f"user:{user.group(1)}"
        elif host:
            result["entity"] = f"host:{host.group(1)}"
        elif ip:
            result["entity"] = f"ip:{ip.group(1)}"

    for word, canonical in _STATUS_WORDS.items():
        if word in lowered and ("status" in lowered or word in lowered):
            result["status"] = canonical
            break

    rule = _RULE_RE.search(text)
    if rule:
        result["rule"] = rule.group(1)

    source = _SOURCE_RE.search(text)
    if source:
        result["source"] = source.group(1)

    timeframe = _TIMEFRAME_RE.search(lowered)
    if timeframe:
        if timeframe.group(0) == "today":
            result["timeframe"] = "today"
        else:
            result["timeframe"] = f"{timeframe.group(1)}{timeframe.group(2)}"

    limit = _LIMIT_RE.search(text)
    if limit:
        result["limit"] = int(limit.group(1))

    # Remaining free text becomes the `--query` filter. Strip recognized phrases.
    remainder = text
    if result["entity"]:
        remainder = _ENTITY_RE.sub("", remainder)
    if result["rule"]:
        remainder = _RULE_RE.sub("", remainder)
    if result["source"]:
        remainder = _SOURCE_RE.sub("", remainder)
    remainder = re.sub(r"\b(?:status|open|investigating|resolved|closed|incidents|events|show|list|all|for|with)\b", " ", remainder, flags=re.IGNORECASE)
    remainder = re.sub(r"\s{2,}", " ", remainder).strip(" ,;:-")
    if remainder:
        result["query"] = remainder
    return result


def to_cli_flags(query: dict[str, Any]) -> list[str]:
    """Convert a canonical DSL dict into CLI flag list (``--entity=...``)."""
    flags: list[str] = []
    if query.get("entity"):
        flags.append(f"--entity={query['entity']}")
    if query.get("query"):
        flags.append(f"--query={query['query']}")
    if query.get("status"):
        flags.append(f"--status={query['status']}")
    if query.get("rule"):
        flags.append(f"--rule={query['rule']}")
    if query.get("source"):
        flags.append(f"--source={query['source']}")
    if query.get("limit"):
        flags.append(f"--limit={query['limit']}")
    return flags


class QueryTranslator:
    """Convenience wrapper around the NL → DSL translation helpers."""

    def translate(self, text: str) -> dict[str, Any]:
        return translate_query(text)

    def to_cli(self, text: str | None = None, query: dict[str, Any] | None = None) -> list[str]:
        q = query or (translate_query(text) if text else {})
        return to_cli_flags(q)

"""Entity enrichment: asset, identity, network, threat-intel and vulnerability context.

Findings say *what* happened. Enrichment says *what it happened to*, which is
what decides whether an analyst cares: the same failed login means one thing on
a lab box and another on a domain controller owned by finance.

Every source here is local and free - an asset inventory export, an identity
export, CIDR definitions, the STIX indicators AutoSIEM already loads, and a
vulnerability export crossed with CISA's public known-exploited catalogue. No
commercial reputation API and no API keys, so enrichment never costs money and
never leaks entity names to a third party. Standard library only.

Enrichers may report a ``criticality`` for an entity. The registry takes the
highest one seen and turns it into a risk multiplier, so a finding on a critical
asset outranks the same finding on a spare laptop.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

from .kev import EMPTY_CATALOG, load_kev_state, normalize_cve

# --- criticality -----------------------------------------------------------
CRITICALITY_LEVELS = ("low", "medium", "high", "critical")

#: Risk multiplier applied to findings touching an entity of each criticality.
#: medium is 1.0 so an ordinary asset scores exactly as it does today.
CRITICALITY_MULTIPLIERS: dict[str, float] = {
    "low": 0.75,
    "medium": 1.0,
    "high": 1.5,
    "critical": 2.0,
}

#: Upper bound on the combined multiplier, so enrichment can sharpen ranking
#: without letting one label swamp the detection content of a score.
MAX_RISK_MULTIPLIER = 2.0


def normalize_criticality(value: Any) -> str | None:
    """Coerce assorted spellings onto the four supported levels."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    aliases = {
        "crit": "critical",
        "sev1": "critical",
        "tier0": "critical",
        "tier-0": "critical",
        "crown-jewel": "critical",
        "very high": "critical",
        "important": "high",
        "sev2": "high",
        "moderate": "medium",
        "normal": "medium",
        "standard": "medium",
        "minor": "low",
        "none": "low",
    }
    text = aliases.get(text, text)
    return text if text in CRITICALITY_LEVELS else None


def _rank(level: str | None) -> int:
    return CRITICALITY_LEVELS.index(level) if level in CRITICALITY_LEVELS else -1


def highest_criticality(levels: Iterable[str | None]) -> str | None:
    """The most severe criticality in ``levels`` (None when there is none)."""
    best: str | None = None
    for level in levels:
        if _rank(level) > _rank(best):
            best = level
    return best


# --- entity helpers --------------------------------------------------------
def split_entity(entity: str) -> tuple[str, str]:
    """``host:ws-1`` -> ``("host", "ws-1")``. Unprefixed values get kind ""."""
    kind, separator, value = entity.partition(":")
    if not separator:
        return "", entity
    return kind, value


# --- context ---------------------------------------------------------------
@dataclass(slots=True)
class EntityContext:
    """One enricher's view of one entity."""

    entity: str
    source: str
    attributes: dict[str, Any] = field(default_factory=dict)
    criticality: str | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "source": self.source,
            "attributes": self.attributes,
            "criticality": self.criticality,
            "tags": self.tags,
        }


@runtime_checkable
class Enricher(Protocol):
    """Adds context to a single entity key, or returns None if it knows nothing."""

    name: str

    def enrich(self, entity: str) -> EntityContext | None: ...


# --- record loading --------------------------------------------------------
def load_records(path: str | Path) -> list[dict[str, Any]]:
    """Read a JSON array, a JSONL file, or a ``{"records": [...]}`` wrapper.

    Returns an empty list for a missing or unreadable file: enrichment is
    optional context and must never be the reason ingest fails.
    """
    file_path = Path(path)
    if not file_path.exists():
        return []
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError:
        return []
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except ValueError:
            return []
        return [item for item in data if isinstance(item, dict)]
    if stripped.startswith("{") and "\n" not in stripped.strip("\n"):
        try:
            data = json.loads(stripped)
        except ValueError:
            return []
        if isinstance(data, dict):
            for key in ("records", "assets", "identities", "users"):
                if isinstance(data.get(key), list):
                    return [item for item in data[key] if isinstance(item, dict)]
            return [data]
        return []
    records: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            records.append(item)
        elif isinstance(item, list):
            records.extend(entry for entry in item if isinstance(entry, dict))
    return records


def _first(record: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


# --- asset -----------------------------------------------------------------
class AssetEnricher:
    """Asset inventory: criticality, owner, environment, OS.

    Accepts the same record shape as the ``asset`` connector, so one export
    feeds both ingestion and enrichment.
    """

    name = "asset"

    def __init__(self, records: Iterable[Mapping[str, Any]] = ()) -> None:
        self._by_host: dict[str, dict[str, Any]] = {}
        self._by_ip: dict[str, dict[str, Any]] = {}
        for record in records:
            self.add(record)

    def add(self, record: Mapping[str, Any]) -> None:
        data = dict(record)
        host = _first(data, "hostname", "fqdn", "name", "host")
        address = _first(data, "ip", "ip_address", "address")
        if host:
            self._by_host[str(host).strip().lower()] = data
        if address:
            self._by_ip[str(address).strip().lower()] = data

    @classmethod
    def from_file(cls, path: str | Path) -> "AssetEnricher":
        return cls(load_records(path))

    def __len__(self) -> int:
        return len(self._by_host) + len(self._by_ip)

    def enrich(self, entity: str) -> EntityContext | None:
        kind, value = split_entity(entity)
        key = value.strip().lower()
        if kind == "host":
            record = self._by_host.get(key)
        elif kind == "ip":
            record = self._by_ip.get(key)
        else:
            return None
        if record is None:
            return None
        criticality = normalize_criticality(
            _first(record, "criticality", "business_criticality", "importance", "tier")
        )
        attributes = {
            "hostname": _first(record, "hostname", "fqdn", "name", "host"),
            "ip": _first(record, "ip", "ip_address", "address"),
            "owner": _first(record, "owner", "responsible_owner"),
            "environment": _first(record, "environment", "env"),
            "os": _first(record, "os", "os_version"),
            "location": _first(record, "location", "site"),
        }
        tags = [str(tag) for tag in (record.get("tags") or []) if str(tag)]
        return EntityContext(
            entity=entity,
            source=self.name,
            attributes={k: v for k, v in attributes.items() if v is not None},
            criticality=criticality,
            tags=tags,
        )


# --- identity --------------------------------------------------------------
class IdentityEnricher:
    """Identity directory export: department, title, privileged, status.

    A privileged or disabled account is treated as critical: activity on a
    disabled account should never be routine.
    """

    name = "identity"

    def __init__(self, records: Iterable[Mapping[str, Any]] = ()) -> None:
        self._by_user: dict[str, dict[str, Any]] = {}
        for record in records:
            self.add(record)

    def add(self, record: Mapping[str, Any]) -> None:
        data = dict(record)
        for key in ("username", "user", "name", "sam_account_name", "upn", "email"):
            value = data.get(key)
            if value:
                self._by_user[str(value).strip().lower()] = data
                local = str(value).split("@")[0].strip().lower()
                self._by_user.setdefault(local, data)

    @classmethod
    def from_file(cls, path: str | Path) -> "IdentityEnricher":
        return cls(load_records(path))

    def __len__(self) -> int:
        return len(self._by_user)

    def enrich(self, entity: str) -> EntityContext | None:
        kind, value = split_entity(entity)
        if kind != "user":
            return None
        record = self._by_user.get(value.strip().lower())
        if record is None:
            return None
        privileged = _as_bool(_first(record, "privileged", "is_admin", "admin") or False)
        status = str(_first(record, "status", "account_status") or "").strip().lower()
        disabled = status in {"disabled", "inactive", "terminated", "suspended"}
        criticality = normalize_criticality(_first(record, "criticality", "importance"))
        if privileged or disabled:
            criticality = highest_criticality([criticality, "critical"])
        attributes = {
            "username": _first(record, "username", "user", "name", "sam_account_name"),
            "display_name": _first(record, "display_name", "full_name"),
            "email": _first(record, "email", "upn"),
            "department": _first(record, "department", "team"),
            "title": _first(record, "title", "job_title"),
            "manager": record.get("manager"),
            "privileged": privileged,
            "status": status or None,
        }
        tags = [str(tag) for tag in (record.get("tags") or []) if str(tag)]
        if privileged:
            tags.append("privileged")
        if disabled:
            tags.append("disabled-account")
        return EntityContext(
            entity=entity,
            source=self.name,
            attributes={k: v for k, v in attributes.items() if v is not None},
            criticality=criticality,
            tags=tags,
        )


# --- network ---------------------------------------------------------------
#: RFC 5737 / RFC 3849 documentation ranges. Python's ``is_private`` reports
#: True for these, which would label AutoSIEM's own example telemetry
#: "private" when it is really reserved-for-documentation and routable nowhere.
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _ip_scope(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """A label an analyst can act on, more precise than private/public."""
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return "documentation"
    if address.is_global:
        return "public"
    if address.is_private:
        return "private"
    return "reserved"


class NetworkEnricher:
    """Classifies an IP with the stdlib, plus operator-named CIDR ranges.

    "external, not in any known range" versus "corporate VPN pool" is often the
    single most useful fact about a source address, and it needs no data feed.
    """

    name = "network"

    def __init__(self, named_ranges: Mapping[str, Iterable[str]] | None = None) -> None:
        self.named_ranges: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
        for label, cidrs in (named_ranges or {}).items():
            networks = []
            for cidr in cidrs:
                try:
                    networks.append(ipaddress.ip_network(str(cidr), strict=False))
                except ValueError:
                    continue
            if networks:
                self.named_ranges[label] = networks

    @classmethod
    def from_file(cls, path: str | Path) -> "NetworkEnricher":
        """Load ``{"corp-vpn": ["10.8.0.0/16"], ...}`` from a JSON file."""
        records = load_records(path)
        merged: dict[str, list[str]] = {}
        for record in records:
            for label, cidrs in record.items():
                if isinstance(cidrs, str):
                    merged.setdefault(label, []).append(cidrs)
                elif isinstance(cidrs, list):
                    merged.setdefault(label, []).extend(str(item) for item in cidrs)
        return cls(merged)

    def enrich(self, entity: str) -> EntityContext | None:
        kind, value = split_entity(entity)
        if kind != "ip":
            return None
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return None
        scope = _ip_scope(address)
        attributes: dict[str, Any] = {
            "address": str(address),
            "version": address.version,
            "scope": scope,
            "is_private": address.is_private,
            "is_global": address.is_global,
            "is_loopback": address.is_loopback,
            "is_link_local": address.is_link_local,
            "is_multicast": address.is_multicast,
        }
        tags = [scope]
        matched = [
            label
            for label, networks in self.named_ranges.items()
            if any(address in network for network in networks)
        ]
        if matched:
            attributes["ranges"] = sorted(matched)
            tags.extend(sorted(matched))
        elif scope == "public":
            tags.append("unknown-external")
        return EntityContext(entity=entity, source=self.name, attributes=attributes, tags=tags)


# --- threat intel ----------------------------------------------------------
class ThreatIntelEnricher:
    """Flags entities that appear in the loaded STIX indicator set.

    Reuses indicators AutoSIEM already ingests, so this costs nothing extra.
    A confirmed-malicious indicator marks the entity critical.
    """

    name = "threat_intel"

    def __init__(self, indicators: Iterable[Any] = ()) -> None:
        self._values: dict[str, list[Any]] = {}
        for indicator in indicators:
            for clause in getattr(indicator, "clauses", None) or []:
                value = str(clause.get("value") or "").strip().lower()
                if value:
                    self._values.setdefault(value, []).append(indicator)

    def __len__(self) -> int:
        return len(self._values)

    def enrich(self, entity: str) -> EntityContext | None:
        _kind, value = split_entity(entity)
        hits = self._values.get(value.strip().lower())
        if not hits:
            return None
        names = []
        for indicator in hits:
            label = getattr(indicator, "name", None) or getattr(indicator, "indicator_id", None)
            if label and str(label) not in names:
                names.append(str(label))
        return EntityContext(
            entity=entity,
            source=self.name,
            attributes={"indicator_count": len(hits), "indicators": names[:10]},
            criticality="critical",
            tags=["threat-intel-hit"],
        )


# --- vulnerability ---------------------------------------------------------
class VulnerabilityEnricher:
    """Vulnerability inventory crossed with CISA's known-exploited catalogue.

    A host having open CVEs is background noise; a host having a CVE that is
    *being exploited right now* is the thing an analyst should look at first.
    That is the whole point of KEV, and it is why criticality is only raised for
    the KEV subset. A host with fifty unexploited CVEs stays where it was.

    The inventory is a local export (same loader as the asset connector) with
    records like::

        {"host": "web-01", "cves": ["CVE-2026-8037", "CVE-2021-44228"]}

    Accepted keys: ``host``/``hostname``/``asset_id``/``name`` for the host, and
    ``cves``/``cve_ids``/``vulnerabilities`` for the list.
    """

    name = "vulnerability"

    def __init__(self, records: Iterable[Mapping[str, Any]] = (), catalog: Any | None = None) -> None:
        self._by_host: dict[str, list[str]] = {}
        for record in records:
            host = _first(record, "host", "hostname", "asset_id", "name")
            if not host:
                continue
            raw = _first(record, "cves", "cve_ids", "vulnerabilities") or []
            if isinstance(raw, str):
                raw = [raw]
            cves: list[str] = []
            for item in raw:
                # Accept a bare ID or a nested record with one.
                value = item.get("cve") or item.get("cveID") or item.get("id") if isinstance(item, Mapping) else item
                cve = normalize_cve(value)
                if cve and cve not in cves:
                    cves.append(cve)
            if cves:
                self._by_host[str(host).strip().lower()] = cves
        self._catalog = catalog if catalog is not None else EMPTY_CATALOG

    @classmethod
    def from_file(cls, path: str | Path, catalog: Any | None = None) -> "VulnerabilityEnricher":
        return cls(load_records(path), catalog=catalog)

    def __len__(self) -> int:
        return len(self._by_host)

    def enrich(self, entity: str) -> EntityContext | None:
        kind, value = split_entity(entity)
        if kind != "host":
            return None
        cves = self._by_host.get(value.strip().lower())
        if not cves:
            return None

        exploited = [cve for cve in cves if cve in self._catalog]
        ransomware = [cve for cve in exploited if self._catalog.is_ransomware(cve)]

        attributes: dict[str, Any] = {
            "cve_count": len(cves),
            "known_exploited_count": len(exploited),
            "known_exploited": exploited[:10],
        }
        if self._catalog.catalog_version:
            attributes["kev_catalog_version"] = self._catalog.catalog_version
        if ransomware:
            attributes["ransomware_linked"] = ransomware[:10]

        tags = ["vulnerable"]
        criticality: str | None = None
        if exploited:
            # Only actively-exploited CVEs move priority. Otherwise every host
            # with a patch backlog would outrank a clean crown-jewel server.
            tags.append("known-exploited")
            criticality = "high"
        if ransomware:
            tags.append("ransomware-linked")
            criticality = "critical"
        if not self._catalog.catalog_version:
            # Say so rather than implying "nothing exploited" from an empty cache.
            attributes["kev_catalog"] = "not loaded"

        return EntityContext(
            entity=entity,
            source=self.name,
            attributes=attributes,
            criticality=criticality,
            tags=tags,
        )


# --- registry --------------------------------------------------------------
class EnrichmentRegistry:
    """Runs every configured enricher and merges what they return."""

    def __init__(self, enrichers: Iterable[Enricher] = ()) -> None:
        self.enrichers = list(enrichers)

    def __bool__(self) -> bool:
        return bool(self.enrichers)

    def __len__(self) -> int:
        return len(self.enrichers)

    def enrich(self, entity: str) -> list[EntityContext]:
        contexts: list[EntityContext] = []
        for enricher in self.enrichers:
            try:
                context = enricher.enrich(entity)
            except Exception:
                # One bad enricher must not lose the others' context.
                continue
            if context is not None:
                contexts.append(context)
        return contexts

    def context_for(self, entities: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
        """Serializable context per entity, omitting entities nothing matched."""
        result: dict[str, list[dict[str, Any]]] = {}
        for entity in entities:
            contexts = self.enrich(entity)
            if contexts:
                result[entity] = [context.to_dict() for context in contexts]
        return result

    def criticality_for(self, entity: str) -> str | None:
        return highest_criticality(context.criticality for context in self.enrich(entity))

    def tags_for(self, entity: str) -> list[str]:
        tags: list[str] = []
        for context in self.enrich(entity):
            for tag in context.tags:
                if tag not in tags:
                    tags.append(tag)
        return tags

    def risk_multiplier(self, entities: Iterable[str]) -> float:
        """Multiplier for a finding touching ``entities``.

        Driven by the most critical entity involved and capped at
        :data:`MAX_RISK_MULTIPLIER`. Returns 1.0 when nothing is known, so an
        unenriched deployment scores exactly as it does today.
        """
        level = highest_criticality(self.criticality_for(entity) for entity in entities)
        if level is None:
            return 1.0
        return min(CRITICALITY_MULTIPLIERS.get(level, 1.0), MAX_RISK_MULTIPLIER)

    def adjusted_risk(self, risk_points: int, entities: Iterable[str]) -> int:
        """Apply the multiplier to a finding's risk, never below 1 when positive."""
        multiplier = self.risk_multiplier(entities)
        if multiplier == 1.0:
            return risk_points
        adjusted = int(round(risk_points * multiplier))
        if risk_points > 0:
            return max(1, adjusted)
        return adjusted


def enrichment_from_env(env: Mapping[str, str] | None = None, indicators: Iterable[Any] = ()) -> EnrichmentRegistry:
    """Build the registry from ``AUTOSIEM_*`` paths; empty when none are set.

    ``AUTOSIEM_ASSET_FILE``    asset inventory (JSON array or JSONL)
    ``AUTOSIEM_IDENTITY_FILE`` identity directory export
    ``AUTOSIEM_NETWORK_FILE``  ``{"corp-vpn": ["10.8.0.0/16"]}``
    ``AUTOSIEM_NETWORK_RANGES`` the same mapping inline as JSON
    ``AUTOSIEM_VULN_FILE``     host -> CVE inventory export
    ``AUTOSIEM_KEV_FILE``      cached CISA KEV catalogue (``<db>.kev.json``)
    """
    values = dict(os.environ) if env is None else dict(env)
    enrichers: list[Enricher] = []

    asset_path = values.get("AUTOSIEM_ASSET_FILE")
    if asset_path:
        asset = AssetEnricher.from_file(asset_path)
        if len(asset):
            enrichers.append(asset)

    identity_path = values.get("AUTOSIEM_IDENTITY_FILE")
    if identity_path:
        identity = IdentityEnricher.from_file(identity_path)
        if len(identity):
            enrichers.append(identity)

    # Network classification is always on: it needs no data feed, costs nothing,
    # and "external address in no known range" is useful on its own. Named
    # ranges are optional and simply make it more specific. It never sets a
    # criticality, so enabling it by default cannot change any risk score.
    network_path = values.get("AUTOSIEM_NETWORK_FILE")
    inline_ranges = values.get("AUTOSIEM_NETWORK_RANGES")
    if network_path:
        enrichers.append(NetworkEnricher.from_file(network_path))
    elif inline_ranges:
        try:
            parsed = json.loads(inline_ranges)
        except ValueError:
            parsed = {}
        enrichers.append(NetworkEnricher(parsed if isinstance(parsed, dict) else {}))
    else:
        enrichers.append(NetworkEnricher())

    intel = ThreatIntelEnricher(indicators)
    if len(intel):
        enrichers.append(intel)

    # Vulnerability context is only meaningful with an inventory to read; the
    # KEV cache on its own says nothing about any particular host.
    vuln_path = values.get("AUTOSIEM_VULN_FILE")
    if vuln_path:
        catalog = load_kev_state(values.get("AUTOSIEM_KEV_FILE"))
        vulnerability = VulnerabilityEnricher.from_file(vuln_path, catalog=catalog)
        if len(vulnerability):
            enrichers.append(vulnerability)

    return EnrichmentRegistry(enrichers)

"""CISA Known Exploited Vulnerabilities (KEV) catalogue.

KEV is the authoritative free answer to "is this CVE actually being exploited in
the wild", which is a different and far more actionable question than a CVSS
score. It is public JSON, needs no API key, and is the input that turns a
vulnerability inventory into a priority ordering.

Unlike the ATT&CK matrix this is **not vendored**. ATT&CK moves a few times a
year and is semantic, so a copy in the package is a reasonable default. KEV
gains entries weekly and a stale copy is actively misleading -- it would report
"not known exploited" for something added last Tuesday. So it is fetched on
demand and cached beside the database as ``<db>.kev.json``, the same shape as
the threat-intel state file.

    PYTHONPATH=src python -m autosiem.cli update --refresh-kev --db data/autosiem.db

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (public
domain, US government work).
"""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .net import require_https

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "autosiem-kev"
FETCH_TIMEOUT_SECONDS = 120

#: Injectable so the suite stays offline.
Fetcher = Callable[[str], bytes]

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def normalize_cve(value: Any) -> str | None:
    """Canonical upper-case CVE ID, or None if it is not one."""
    text = str(value or "").strip().upper()
    return text if CVE_PATTERN.match(text) else None


def default_kev_state(db_path: str | Path) -> Path:
    """``<db>.kev.json``, matching ``threat_intel.default_intel_state``."""
    path = Path(db_path)
    return path.with_name(path.stem + ".kev.json")


@dataclass(frozen=True, slots=True)
class KevCatalog:
    catalog_version: str
    date_released: str
    entries: dict[str, dict[str, Any]]

    def __contains__(self, cve: str) -> bool:
        normalized = normalize_cve(cve)
        return normalized is not None and normalized in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, cve: str) -> dict[str, Any] | None:
        normalized = normalize_cve(cve)
        return self.entries.get(normalized) if normalized else None

    def is_ransomware(self, cve: str) -> bool:
        entry = self.get(cve)
        return bool(entry and entry.get("ransomware"))


EMPTY_CATALOG = KevCatalog(catalog_version="", date_released="", entries={})


def _default_fetch(url: str) -> bytes:
    request = urllib.request.Request(
        require_https(url, what="the KEV catalogue"), headers={"User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
        return bytes(response.read())


def distill_catalog(payload: dict[str, Any]) -> dict[str, Any]:
    """Reduce the published catalogue to what enrichment needs.

    Drops the long prose fields (``shortDescription``, ``requiredAction``,
    ``notes``) which are ~90% of the ~1.5 MB payload and which AutoSIEM never
    displays. Output is sorted and carries no timestamps of its own, so the same
    catalogue version distils identically every time.
    """
    entries: dict[str, dict[str, Any]] = {}
    for item in payload.get("vulnerabilities", []):
        cve = normalize_cve(item.get("cveID"))
        if cve is None:
            continue
        entries[cve] = {
            "name": str(item.get("vulnerabilityName", "")),
            "vendor": str(item.get("vendorProject", "")),
            "product": str(item.get("product", "")),
            "added": str(item.get("dateAdded", "")),
            "due": str(item.get("dueDate", "")),
            # CISA writes "Known" / "Unknown" / "" here.
            "ransomware": str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
        }
    return {
        "spec_version": "1",
        "catalog_version": str(payload.get("catalogVersion", "")),
        "date_released": str(payload.get("dateReleased", "")),
        "source_url": KEV_URL,
        "count": len(entries),
        "ransomware_count": sum(1 for entry in entries.values() if entry["ransomware"]),
        "vulnerabilities": dict(sorted(entries.items())),
    }


def save_kev_state(path: str | Path, payload: dict[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return target


def load_kev_state(path: str | Path | None) -> KevCatalog:
    """Read a cached catalogue.

    Returns an empty catalogue when there is nothing cached: KEV is optional
    context, and a missing cache must never be the reason ingest fails. An empty
    catalogue makes the enricher say nothing rather than say "not exploited",
    which would be a claim it cannot support.
    """
    if path is None:
        return EMPTY_CATALOG
    target = Path(path)
    if not target.exists():
        return EMPTY_CATALOG
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return EMPTY_CATALOG
    raw = payload.get("vulnerabilities")
    if not isinstance(raw, dict):
        return EMPTY_CATALOG
    return KevCatalog(
        catalog_version=str(payload.get("catalog_version", "")),
        date_released=str(payload.get("date_released", "")),
        entries={str(k).upper(): v for k, v in raw.items() if isinstance(v, dict)},
    )


@dataclass(frozen=True, slots=True)
class KevRefreshResult:
    refreshed: bool
    catalog_version: str
    count: int
    message: str
    path: Path | None = None


def refresh_kev(
    dest: str | Path,
    fetch: Fetcher | None = None,
    current_version: str | None = None,
) -> KevRefreshResult:
    """Fetch the published catalogue and cache it at ``dest``.

    The feed is ~1.5 MB with no cheap version endpoint, so unlike the ATT&CK
    refresh there is nothing to check first; the whole thing is fetched and the
    version comparison happens after. Still skips the *write* when unchanged, so
    the cache mtime stays meaningful.
    """
    fetcher = fetch or _default_fetch
    if current_version is None:
        current_version = load_kev_state(dest).catalog_version

    payload = distill_catalog(json.loads(fetcher(KEV_URL)))
    version = payload["catalog_version"]
    if current_version and current_version == version:
        return KevRefreshResult(
            refreshed=False,
            catalog_version=version,
            count=int(payload["count"]),
            message=f"KEV catalogue already at {version}; cache left unchanged",
            path=Path(dest),
        )
    path = save_kev_state(dest, payload)
    return KevRefreshResult(
        refreshed=True,
        catalog_version=version,
        count=int(payload["count"]),
        message=(
            f"KEV catalogue refreshed {current_version or 'none'} -> {version} "
            f"({payload['count']} CVEs, {payload['ransomware_count']} ransomware-linked) at {path}"
        ),
        path=path,
    )

"""The MITRE ATT&CK Enterprise matrix, distilled and vendored.

``attack_enterprise_index.json`` next to this module holds every current
Enterprise technique with its name and tactics, generated from MITRE's published
STIX bundle by ``scripts/build_attack_index.py``. The bundle itself is ~54 MB and
almost entirely prose AutoSIEM never reads; the distilled index is ~80 KB, so
coverage reporting works offline, deterministically, with no network call and no
third-party dependency.

This is the authoritative source for what a technique is called and which
tactics it belongs to. Hand-maintained tactic tables drift: ATT&CK 19 replaced
``defense-evasion`` with ``stealth`` and ``defense-impairment``, which is exactly
the kind of change a local copy silently misses.

Regenerate after an ATT&CK release::

    python3 scripts/build_attack_index.py

MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation.
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from .net import require_https

#: The index that ships inside the package. Treated as read-only: a refresh
#: writes elsewhere, so an installed wheel never diverges from what was built
#: and read-only installs keep working.
INDEX_PATH = Path(__file__).with_name("attack_enterprise_index.json")

#: Points at a refreshed index; takes precedence over the vendored one.
INDEX_ENV_VAR = "AUTOSIEM_ATTACK_INDEX"

ATTACK_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
COLLECTION_NAME = "Enterprise ATT&CK"
SPEC_VERSION = "1"
USER_AGENT = "autosiem-attack-index"
FETCH_TIMEOUT_SECONDS = 300

#: Injectable so every test in this project stays offline.
Fetcher = Callable[[str], bytes]


class AttackMatrixUnavailable(RuntimeError):
    """The vendored index is missing or unreadable.

    Raised rather than returning an empty matrix: a silent empty matrix would
    report 0 techniques and 0% coverage, which is a wrong number rather than a
    missing one.
    """


@dataclass(frozen=True, slots=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    is_subtechnique: bool

    @property
    def parent_id(self) -> str:
        """``T1059.001`` -> ``T1059``; a parent technique returns itself."""
        return self.technique_id.split(".", 1)[0]


@dataclass(frozen=True, slots=True)
class AttackMatrix:
    attack_version: str
    source_url: str
    source_modified: str
    techniques: dict[str, Technique]
    tactics: tuple[str, ...]

    def __contains__(self, technique_id: str) -> bool:
        return technique_id.strip().upper() in self.techniques

    def __len__(self) -> int:
        return len(self.techniques)

    def get(self, technique_id: str) -> Technique | None:
        """Exact lookup, case-insensitive."""
        return self.techniques.get(technique_id.strip().upper())

    def resolve(self, technique_id: str) -> Technique | None:
        """Exact lookup, falling back to the parent technique.

        A rule tagged with a sub-technique MITRE has not published still resolves
        to its parent, which is enough to name a tactic.
        """
        exact = self.get(technique_id)
        if exact is not None:
            return exact
        base = technique_id.strip().upper().split(".", 1)[0]
        return self.techniques.get(base)

    def tactics_for(self, technique_id: str) -> tuple[str, ...]:
        technique = self.resolve(technique_id)
        return technique.tactics if technique else ()

    def parent_ids(self) -> set[str]:
        return {t.technique_id for t in self.techniques.values() if not t.is_subtechnique}

    def techniques_in_tactic(self, tactic: str) -> set[str]:
        return {t.technique_id for t in self.techniques.values() if tactic in t.tactics}


def _build(payload: dict[str, Any]) -> AttackMatrix:
    techniques: dict[str, Technique] = {}
    for technique_id, entry in payload.get("techniques", {}).items():
        identifier = str(technique_id).strip().upper()
        techniques[identifier] = Technique(
            technique_id=identifier,
            name=str(entry.get("name", "")),
            tactics=tuple(str(tactic) for tactic in entry.get("tactics", [])),
            is_subtechnique=bool(entry.get("sub", False)),
        )
    return AttackMatrix(
        attack_version=str(payload.get("attack_version", "unknown")),
        source_url=str(payload.get("source_url", "")),
        source_modified=str(payload.get("source_modified", "")),
        techniques=techniques,
        tactics=tuple(str(tactic) for tactic in payload.get("tactics", [])),
    )


def load_matrix_file(path: str | Path) -> AttackMatrix:
    """Load a matrix index from an explicit path (no caching)."""
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AttackMatrixUnavailable(
            f"ATT&CK index not found at {target}. Regenerate it with "
            "`python3 scripts/build_attack_index.py`."
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AttackMatrixUnavailable(f"ATT&CK index at {target} is unreadable: {exc}") from exc
    return _build(payload)


def index_path() -> Path:
    """Which index to read: a refreshed one if configured, else the vendored one."""
    override = os.environ.get(INDEX_ENV_VAR, "").strip()
    return Path(override) if override else INDEX_PATH


@lru_cache(maxsize=1)
def load_matrix() -> AttackMatrix:
    """The active Enterprise matrix, parsed once per process.

    Call ``load_matrix.cache_clear()`` after refreshing the index in-process.
    """
    return load_matrix_file(index_path())


def default_attack_index(db_path: str | Path) -> Path:
    """Derive the refreshed-index path from a SQLite db path (``<db>.attack.json``).

    Mirrors ``threat_intel.default_intel_state`` so refreshed content lives
    beside the database rather than inside the installed package.
    """
    path = Path(db_path)
    return path.with_name(path.stem + ".attack.json")


# ---------------------------------------------------------------------------
# Refresh: fetch MITRE's published bundle and distill it
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Release:
    version: str
    url: str
    modified: str


def _require_https(url: str) -> str:
    """Reject plaintext fetches.

    The index decides which techniques exist and what they are called; a
    tampered one silently rewrites every coverage figure. Shared policy lives in
    ``net.require_https`` so intel and LLM traffic answer to the same rule.
    """
    return require_https(url, what="ATT&CK data")


def _default_fetch(url: str) -> bytes:
    request = urllib.request.Request(_require_https(url), headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
        return bytes(response.read())


def _version_key(version: str) -> list[int]:
    parts: list[int] = []
    for chunk in version.split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    return parts


def resolve_release(version: str | None = None, fetch: Fetcher | None = None) -> Release:
    """Look up a published Enterprise release (default: the newest)."""
    fetcher = fetch or _default_fetch
    index = json.loads(fetcher(ATTACK_INDEX_URL))
    collection = next(
        item for item in index["collections"] if COLLECTION_NAME in item.get("name", "")
    )
    # MITRE ships `versions` as a flat list, not a dict keyed by status.
    releases = [
        Release(str(entry["version"]), str(entry["url"]), str(entry.get("modified", "")))
        for entry in collection["versions"]
    ]
    if version is not None:
        for release in releases:
            if release.version == version:
                return release
        raise ValueError(f"ATT&CK version {version!r} is not in MITRE's published index")
    return max(releases, key=lambda release: _version_key(release.version))


def technique_id(obj: dict[str, Any]) -> str | None:
    """The ``T####`` ID from a STIX attack-pattern's ATT&CK external reference."""
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def tactics_of(obj: dict[str, Any]) -> list[str]:
    """ATT&CK tactic shortnames, ignoring other kill chains (e.g. mitre-mobile)."""
    return [
        str(phase["phase_name"])
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
    ]


def distill_bundle(bundle: dict[str, Any], release: Release) -> dict[str, Any]:
    """Reduce a STIX bundle to ``{technique_id: {name, tactics, sub}}``.

    Revoked and deprecated techniques are dropped: they are not detectable
    content any more, and counting them would deflate every coverage figure
    against a denominator MITRE itself no longer publishes as current.

    The result contains no timestamps or machine-local values, so distilling the
    same release twice produces byte-identical output.
    """
    techniques: dict[str, dict[str, Any]] = {}
    skipped = 0
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            skipped += 1
            continue
        identifier = technique_id(obj)
        if identifier is None:
            continue
        techniques[identifier] = {
            "name": str(obj.get("name", "")),
            "tactics": tactics_of(obj),
            "sub": bool(obj.get("x_mitre_is_subtechnique", False)),
        }

    tactics = sorted({tactic for entry in techniques.values() for tactic in entry["tactics"]})
    parents = sum(1 for entry in techniques.values() if not entry["sub"])
    return {
        "spec_version": SPEC_VERSION,
        "attack_version": release.version,
        "source_url": release.url,
        "source_modified": release.modified,
        "generated_by": "autosiem.attack_matrix.distill_bundle",
        "technique_count": len(techniques),
        "parent_technique_count": parents,
        "sub_technique_count": len(techniques) - parents,
        "revoked_or_deprecated_skipped": skipped,
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
    }


def write_index(payload: dict[str, Any], dest: str | Path) -> Path:
    target = Path(dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return target


@dataclass(frozen=True, slots=True)
class RefreshResult:
    refreshed: bool
    current_version: str
    latest_version: str
    message: str
    path: Path | None = None


def refresh_index(
    dest: str | Path,
    version: str | None = None,
    fetch: Fetcher | None = None,
    current_version: str | None = None,
) -> RefreshResult:
    """Bring the ATT&CK index at ``dest`` up to a published release.

    The release list is a few KB and the bundle is ~54 MB, so the version check
    happens first and the download is skipped when nothing has changed. That
    makes this cheap enough to run on a schedule.
    """
    fetcher = fetch or _default_fetch
    if current_version is None:
        try:
            current_version = load_matrix_file(dest).attack_version
        except AttackMatrixUnavailable:
            current_version = ""

    release = resolve_release(version, fetch=fetcher)
    if current_version and current_version == release.version:
        return RefreshResult(
            refreshed=False,
            current_version=current_version,
            latest_version=release.version,
            message=f"ATT&CK index already at {release.version}; no download needed",
            path=Path(dest),
        )

    bundle = json.loads(fetcher(_require_https(release.url)))
    payload = distill_bundle(bundle, release)
    path = write_index(payload, dest)
    return RefreshResult(
        refreshed=True,
        current_version=current_version,
        latest_version=release.version,
        message=(
            f"ATT&CK index refreshed {current_version or 'none'} -> {release.version} "
            f"({payload['technique_count']} techniques) at {path}"
        ),
        path=path,
    )

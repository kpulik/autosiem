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
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

INDEX_PATH = Path(__file__).with_name("attack_enterprise_index.json")


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


@lru_cache(maxsize=1)
def load_matrix() -> AttackMatrix:
    """The vendored Enterprise matrix, parsed once per process."""
    return load_matrix_file(INDEX_PATH)

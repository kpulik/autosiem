#!/usr/bin/env python3
"""Distill MITRE's ATT&CK Enterprise STIX bundle into AutoSIEM's technique index.

The published bundle is ~54 MB and mostly prose AutoSIEM never reads. Coverage
reporting needs three things per technique: its ID, its name, and its tactics.
This script keeps exactly that, which is small enough to vendor so `cli coverage`
works offline and deterministically with no network and no runtime dependency.

    python3 scripts/build_attack_index.py                    # latest released
    python3 scripts/build_attack_index.py --version 19.1     # a specific one
    python3 scripts/build_attack_index.py --from-file b.json # an offline copy

Output is written to src/autosiem/attack_enterprise_index.json and is fully
determined by the upstream bundle -- no timestamps or machine-local values -- so
regenerating from the same ATT&CK version produces a byte-identical file.

Source: https://github.com/mitre-attack/attack-stix-data (MITRE ATT&CK(R) is a
registered trademark of The MITRE Corporation; content is used under the ATT&CK
Terms of Use).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
COLLECTION_NAME = "Enterprise ATT&CK"
DEFAULT_OUT = Path(__file__).resolve().parents[1] / "src" / "autosiem" / "attack_enterprise_index.json"
USER_AGENT = "autosiem-attack-index-builder"
SPEC_VERSION = "1"


def _fetch(url: str, timeout: int = 300) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()


def _version_key(version: str) -> list[int]:
    parts: list[int] = []
    for chunk in version.split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    return parts


def resolve_release(version: str | None) -> dict[str, str]:
    """Find the requested (or latest) Enterprise release in MITRE's index."""
    index = json.loads(_fetch(INDEX_URL, timeout=60))
    collection = next(
        item for item in index["collections"] if COLLECTION_NAME in item.get("name", "")
    )
    releases = collection["versions"]
    if version is not None:
        for release in releases:
            if release["version"] == version:
                return release
        raise SystemExit(f"ATT&CK version {version!r} is not in MITRE's published index")
    return max(releases, key=lambda release: _version_key(release["version"]))


def technique_id(obj: dict[str, Any]) -> str | None:
    """The ``T####`` ID from a STIX attack-pattern's ATT&CK external reference."""
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def tactics_for(obj: dict[str, Any]) -> list[str]:
    """ATT&CK tactic shortnames, ignoring other kill chains (e.g. mitre-mobile)."""
    return [
        str(phase["phase_name"])
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
    ]


def distill(bundle: dict[str, Any], release: dict[str, str]) -> dict[str, Any]:
    """Reduce a STIX bundle to {technique_id: {name, tactics, sub}}.

    Revoked and deprecated techniques are dropped: they are not detectable
    content any more, and counting them would deflate every coverage figure
    against a denominator MITRE itself no longer publishes as current.
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
            "tactics": tactics_for(obj),
            "sub": bool(obj.get("x_mitre_is_subtechnique", False)),
        }

    tactics = sorted({tactic for entry in techniques.values() for tactic in entry["tactics"]})
    parents = sum(1 for entry in techniques.values() if not entry["sub"])
    return {
        "spec_version": SPEC_VERSION,
        "attack_version": release["version"],
        "source_url": release["url"],
        "source_modified": release.get("modified", ""),
        "generated_by": "scripts/build_attack_index.py",
        "technique_count": len(techniques),
        "parent_technique_count": parents,
        "sub_technique_count": len(techniques) - parents,
        "revoked_or_deprecated_skipped": skipped,
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", help="ATT&CK Enterprise version (default: latest released)")
    parser.add_argument("--from-file", help="Read the STIX bundle from a local file instead of fetching")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help=f"Output path (default: {DEFAULT_OUT})")
    args = parser.parse_args(argv)

    release = resolve_release(args.version)
    if args.from_file:
        bundle = json.loads(Path(args.from_file).read_text(encoding="utf-8"))
        print(f"reading bundle from {args.from_file} (labelled ATT&CK {release['version']})")
    else:
        print(f"fetching ATT&CK Enterprise {release['version']} from {release['url']}")
        bundle = json.loads(_fetch(release["url"]))

    index = distill(bundle, release)
    out = Path(args.out)
    out.write_text(json.dumps(index, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    size_kb = out.stat().st_size / 1024
    print(
        f"ATT&CK {index['attack_version']}: {index['technique_count']} techniques "
        f"({index['parent_technique_count']} parent, {index['sub_technique_count']} sub) "
        f"across {len(index['tactics'])} tactics; "
        f"skipped {index['revoked_or_deprecated_skipped']} revoked/deprecated"
    )
    print(f"wrote {out} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

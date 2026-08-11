#!/usr/bin/env python3
"""Regenerate the vendored ATT&CK Enterprise index shipped inside the package.

This is the build-time entry point. The distillation itself lives in
``autosiem.attack_matrix`` so that `cli update --refresh-attack` performs exactly
the same transformation at runtime, against a writable path rather than the
package directory.

    python3 scripts/build_attack_index.py                    # latest released
    python3 scripts/build_attack_index.py --version 19.1     # a specific one
    python3 scripts/build_attack_index.py --from-file b.json # an offline copy

Output is fully determined by the upstream bundle -- no timestamps or
machine-local values -- so regenerating the same ATT&CK version produces a
byte-identical file.

Source: https://github.com/mitre-attack/attack-stix-data (MITRE ATT&CK(R) is a
registered trademark of The MITRE Corporation; content is used under the ATT&CK
Terms of Use).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from autosiem.attack_matrix import (  # noqa: E402
    INDEX_PATH,
    _default_fetch,
    distill_bundle,
    resolve_release,
    write_index,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--version", help="ATT&CK Enterprise version (default: latest released)")
    parser.add_argument("--from-file", help="Read the STIX bundle from a local file instead of fetching")
    parser.add_argument("--out", default=str(INDEX_PATH), help=f"Output path (default: {INDEX_PATH})")
    args = parser.parse_args(argv)

    release = resolve_release(args.version)
    if args.from_file:
        bundle = json.loads(Path(args.from_file).read_text(encoding="utf-8"))
        print(f"reading bundle from {args.from_file} (labelled ATT&CK {release.version})")
    else:
        print(f"fetching ATT&CK Enterprise {release.version} from {release.url}")
        bundle = json.loads(_default_fetch(release.url))

    index = distill_bundle(bundle, release)
    out = write_index(index, args.out)

    print(
        f"ATT&CK {index['attack_version']}: {index['technique_count']} techniques "
        f"({index['parent_technique_count']} parent, {index['sub_technique_count']} sub) "
        f"across {len(index['tactics'])} tactics; "
        f"skipped {index['revoked_or_deprecated_skipped']} revoked/deprecated"
    )
    print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

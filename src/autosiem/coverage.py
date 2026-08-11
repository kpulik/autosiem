"""ATT&CK coverage reporting.

Loads detection rules and reports which MITRE ATT&CK techniques and tactics
the rule set covers, plus gaps against a small watchlist of high-value
techniques. The watchlist is a curated subset -- not the full ATT&CK matrix --
chosen to highlight common attack paths (initial access -> execution ->
credential access -> lateral movement -> impact).

Because "0 gaps" is easy to misread as full ATT&CK coverage, the report names
its own baseline (``baseline``) and scopes every gap key to the watchlist. Full
ATT&CK Enterprise coverage is a different, larger measurement that this module
does not make.
"""

from __future__ import annotations

from typing import Any

from .attack_matrix import AttackMatrix, AttackMatrixUnavailable, load_matrix
from .schemas import DetectionRule

#: What the gap number is measured against. This is reported alongside the
#: number so it cannot be quoted as full-matrix coverage: "0 gaps" means "0 gaps
#: against the list below", which AutoSIEM maintains by hand.
BASELINE_NAME = "AutoSIEM high-value technique watchlist"
BASELINE_KIND = "curated_subset"
BASELINE_NOTE = (
    "Curated subset of ATT&CK Enterprise chosen to exercise one full attack path "
    "(initial access -> execution -> credential access -> lateral movement -> "
    "impact). Maintained by hand in coverage.py and not synchronized with MITRE's "
    "published matrix, so watchlist coverage is not a measure of coverage across "
    "ATT&CK Enterprise."
)

# High-value techniques to check coverage against (technique, tactic).
WATCHLIST: list[tuple[str, str]] = [
    ("T1059", "execution"),            # Command and Scripting Interpreter
    ("T1059.001", "execution"),        # PowerShell
    ("T1566", "initial-access"),       # Phishing
    ("T1078", "initial-access"),       # Valid Accounts
    ("T1190", "initial-access"),       # Exploit Public-Facing Application
    ("T1110", "credential-access"),    # Brute Force
    ("T1003", "credential-access"),    # OS Credential Dumping
    ("T1027", "defense-evasion"),      # Obfuscated Files or Information
    ("T1070", "defense-evasion"),      # Indicator Removal
    ("T1036", "defense-evasion"),      # Masquerading
    ("T1082", "discovery"),            # System Information Discovery
    ("T1021", "lateral-movement"),     # Remote Services
    ("T1041", "exfiltration"),         # Exfiltration Over C2 Channel
    ("T1486", "impact"),               # Data Encrypted for Impact
    ("T1573", "command-and-control"),  # Encrypted Channel
]


def _base_technique(technique: str) -> str:
    """Strip a sub-technique suffix: ``T1059.001`` -> ``T1059``."""
    return technique.split(".")[0] if "." in technique else technique


def tactic_for(technique: str) -> str | None:
    """Primary tactic for an ATT&CK technique ID, per the published matrix.

    Reads MITRE's own classification rather than a local table, so tactic
    renames arrive with the next index regeneration instead of silently
    persisting. Returns None for a technique MITRE does not currently publish.
    """
    try:
        matrix = load_matrix()
    except AttackMatrixUnavailable:
        return None
    tactics = matrix.tactics_for(technique)
    return tactics[0] if tactics else None


def _percent(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


def _matrix_coverage(covered: list[str], matrix: AttackMatrix | None = None) -> dict[str, Any]:
    """Coverage against MITRE's published Enterprise matrix.

    Reported at two granularities because they answer different questions and
    one alone is misleading. Technique-level counts every published technique
    including sub-techniques, which is the strictest denominator. Parent-level
    credits a parent when the parent or any of its sub-techniques is detected,
    which is how an ATT&CK Navigator layer usually reads. Both percentages ship
    with their numerator and denominator so neither can be quoted bare.

    ``unknown_technique_ids`` lists technique IDs the rules claim that MITRE
    does not currently publish -- typos, or techniques since revoked.
    """
    if matrix is None:
        try:
            matrix = load_matrix()
        except AttackMatrixUnavailable as exc:
            return {"available": False, "error": str(exc)}

    known = {identifier for identifier in covered if identifier in matrix}
    unknown = sorted(identifier for identifier in covered if identifier not in matrix)

    all_parents = matrix.parent_ids()
    covered_parents = {
        technique.parent_id
        for identifier in known
        if (technique := matrix.get(identifier)) is not None
    } & all_parents

    by_tactic: list[dict[str, Any]] = []
    for tactic in matrix.tactics:
        in_tactic = matrix.techniques_in_tactic(tactic)
        hit = in_tactic & known
        by_tactic.append(
            {
                "tactic": tactic,
                "techniques": len(in_tactic),
                "covered": len(hit),
                "percent": _percent(len(hit), len(in_tactic)),
            }
        )

    return {
        "available": True,
        "attack_version": matrix.attack_version,
        "source_url": matrix.source_url,
        "source_modified": matrix.source_modified,
        "technique_total": len(matrix),
        "technique_covered": len(known),
        "technique_percent": _percent(len(known), len(matrix)),
        "parent_total": len(all_parents),
        "parent_covered": len(covered_parents),
        "parent_percent": _percent(len(covered_parents), len(all_parents)),
        "unknown_technique_ids": unknown,
        "by_tactic": by_tactic,
    }


def coverage_report(rules: list[DetectionRule]) -> dict[str, Any]:
    """Build an ATT&CK coverage summary for a list of rules."""
    covered_techniques: list[str] = []
    for rule in rules:
        for technique in rule.mitre_attack:
            normalized = str(technique).strip().upper()
            if normalized and normalized not in covered_techniques:
                covered_techniques.append(normalized)

    tactics: list[str] = []
    for technique in covered_techniques:
        tactic = tactic_for(technique)
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    tactics.sort()

    watchlist: list[dict[str, Any]] = []
    for technique, tactic in WATCHLIST:
        watchlist.append(
            {
                "technique": technique,
                "tactic": tactic,
                "covered": technique in covered_techniques,
            }
        )

    gaps = [entry for entry in watchlist if not entry["covered"]]
    matrix_section = _matrix_coverage(covered_techniques)

    # Every gap key is watchlist-scoped by name, and the baseline travels with
    # the number. A bare "gap_count: 0" reads as full ATT&CK coverage, which is
    # not what this measures.
    return {
        "baseline": {
            "name": BASELINE_NAME,
            "kind": BASELINE_KIND,
            "technique_count": len(WATCHLIST),
            "note": BASELINE_NOTE,
        },
        "matrix": matrix_section,
        "total_rules": len(rules),
        "rules_with_mitre_attack": sum(1 for rule in rules if rule.mitre_attack),
        "unique_techniques": len(covered_techniques),
        "tactics_covered": tactics,
        "techniques_covered": sorted(covered_techniques),
        "watchlist_coverage": watchlist,
        "watchlist_covered_count": len(watchlist) - len(gaps),
        "watchlist_gaps": gaps,
        "watchlist_gap_count": len(gaps),
    }
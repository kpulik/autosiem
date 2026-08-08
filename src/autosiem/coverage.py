"""ATT&CK coverage reporting.

Loads detection rules and reports which MITRE ATT&CK techniques and tactics
the rule set covers, plus gaps against a small watchlist of high-value
techniques. The watchlist is a curated subset -- not the full ATT&CK matrix --
chosen to highlight common attack paths (initial access -> execution ->
credential access -> lateral movement -> impact).
"""

from __future__ import annotations

from typing import Any

from .schemas import DetectionRule

# Base technique ID -> primary tactic. Sub-techniques inherit their base's
# tactic unless listed explicitly below.
_TACTIC_MAP: dict[str, str] = {
    "T1059": "execution",
    "T1047": "execution",
    "T1543": "persistence",
    "T1566": "initial-access",
    "T1078": "initial-access",
    "T1190": "initial-access",
    "T1110": "credential-access",
    "T1003": "credential-access",
    "T1552": "credential-access",
    "T1027": "defense-evasion",
    "T1070": "defense-evasion",
    "T1036": "defense-evasion",
    "T1218": "defense-evasion",
    "T1562": "defense-evasion",
    "T1082": "discovery",
    "T1482": "discovery",
    "T1018": "discovery",
    "T1087": "discovery",
    "T1021": "lateral-movement",
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1486": "impact",
    "T1498": "impact",
    "T1071": "command-and-control",
    "T1573": "command-and-control",
    "T1105": "command-and-control",
}

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
    """Return the primary tactic for an ATT&CK technique ID."""
    return _TACTIC_MAP.get(_base_technique(technique))


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

    return {
        "total_rules": len(rules),
        "rules_with_mitre_attack": sum(1 for rule in rules if rule.mitre_attack),
        "unique_techniques": len(covered_techniques),
        "tactics_covered": tactics,
        "techniques_covered": sorted(covered_techniques),
        "watchlist_coverage": watchlist,
        "gaps": gaps,
        "gap_count": len(gaps),
    }
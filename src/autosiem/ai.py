from __future__ import annotations

from .schemas import Finding, Incident


class Investigator:
    """AI investigation interface.

    The MVP implements a deterministic local report. Hosted/local LLM adapters can
    later implement this interface behind redaction and audit policies.
    """

    def explain(self, incident: Incident, findings: list[Finding]) -> str:
        related = [finding for finding in findings if finding.finding_id in incident.finding_ids]
        attack = ", ".join(incident.mitre_attack) if incident.mitre_attack else "not mapped"
        evidence_lines = []
        for finding in related[:10]:
            event = finding.evidence.get("event", {})
            evidence_lines.append(
                f"- {finding.rule_name}: action={event.get('action')} user={event.get('user')} "
                f"host={event.get('host')} src_ip={event.get('src_ip')} severity={finding.severity.name.lower()}"
            )
        next_steps = [
            "Validate whether the user/session/source IP is expected.",
            "Pull surrounding events for the same user, host, and source IP for +/- 24 hours.",
            "Check asset criticality, recent vulnerabilities, and identity privilege level.",
            "Look for lateral movement, credential access, persistence, and exfiltration signals.",
            "If confidence is high, preserve evidence and use approval-gated containment playbooks.",
        ]
        return "\n".join(
            [
                f"Incident: {incident.title}",
                f"Severity: {incident.severity.name.lower()} | Risk: {incident.risk_score}",
                f"Entities: {', '.join(incident.entities)}",
                f"MITRE ATT&CK: {attack}",
                "",
                "Why it matters:",
                incident.summary,
                "",
                "Key evidence:",
                *evidence_lines,
                "",
                "Recommended next steps:",
                *(f"{index}. {step}" for index, step in enumerate(next_steps, start=1)),
            ]
        )

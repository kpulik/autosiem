# AutoSIEM research baseline: modern SIEM capabilities and standards

_Last updated: 2026-08-04._

## 1. What top SIEMs compete on today

Modern SIEM has converged with XDR, UEBA, SOAR, threat intelligence, detection engineering, and AI investigation. Current leading platforms include Splunk Enterprise Security, Microsoft Sentinel, Elastic Security, IBM QRadar, Google Security Operations / Chronicle, CrowdStrike Falcon Next-Gen SIEM, Palo Alto Cortex XSIAM, Exabeam, Securonix, Panther, Devo, LogRhythm, and open-source/security-data-stack combinations around OpenSearch, Wazuh, Security Onion, Velociraptor, Osquery, Sigma, and OpenCTI.

The main differentiators are:

1. **Data ingestion breadth** — cloud, identity, endpoint, network, SaaS, Kubernetes, application, OT/ICS, vulnerability, EDR/XDR, threat-intel, email, and custom logs.
2. **Normalization and schema strategy** — OCSF, ECS, UDM, CIM, ASIM, CEF/LEEF, vendor-specific schemas, and automatic parser generation.
3. **Hot/cold storage economics** — searchable hot data, cheap object storage, tiered retention, summary indexes, federation, and query pushdown.
4. **Detection engineering** — Sigma-like rules, behavioral analytics, sequence/correlation rules, attack-chain detection, data-quality checks, test harnesses, rule CI/CD.
5. **UEBA and entity analytics** — per-user/device/workload baselines, peer groups, impossible travel, abnormal auth, service-account misuse, new relationships.
6. **AI/copilot workflows** — natural-language search, alert summarization, investigation plans, timeline generation, query generation, enrichment, recommended response, detection-rule authoring assistance.
7. **Case/incident management** — deduplication, alert grouping, severity/risk scoring, SLA workflows, evidence preservation, auditability.
8. **Automation/SOAR** — playbooks, response connectors, approval gates, containment, ticketing, notifications, and rollback.
9. **Threat intelligence** — STIX/TAXII ingestion, indicator lifecycle, sightings, confidence/TTL, enrichments, ATT&CK and campaign mapping.
10. **Content ecosystem** — vendor/community detection packs, compliance dashboards, curated parsers, integrations, and ATT&CK coverage maps.
11. **Governance** — RBAC/ABAC, multi-tenancy, privacy controls, PII minimization, immutable audit logs, encryption, data residency.
12. **Operational reliability** — exactly-once-ish ingestion, backpressure, replay, parser failure queues, observability, SLOs, and cost controls.

## 2. Standards and formats AutoSIEM should support

### OCSF — Open Cybersecurity Schema Framework

OCSF is a Linux Foundation project and provides a vendor-agnostic schema framework for cybersecurity events. It is storage-format agnostic and uses JSON schema definitions. AutoSIEM should use OCSF as the primary normalized event vocabulary, while allowing adapter fields for vendor-specific data.

Design implication: store every event with a normalized core plus `raw` and `vendor` fields.

### MITRE ATT&CK

MITRE ATT&CK is the dominant adversary tactics/techniques knowledge base. Detection rules, findings, incidents, coverage metrics, and AI explanations should map to ATT&CK technique IDs where possible.

Design implication: rules include `mitre_attack` arrays and incidents aggregate ATT&CK coverage.

### Sigma

Sigma is the most common portable detection-rule style. AutoSIEM should ingest Sigma later, but the MVP uses a small Sigma-inspired JSON rule format: metadata, selection predicates, severity, MITRE mappings, and risk points.

### STIX/TAXII

STIX/TAXII are key for cyber-threat-intelligence exchange. AutoSIEM should support feeds, indicator expiration, confidence, sightings, and provenance.

### CEF, LEEF, syslog, ECS, CIM, ASIM, UDM

AutoSIEM should ingest common enterprise formats:

- **Syslog/RFC 5424-ish** for network/security appliances.
- **CEF** (ArcSight) and **LEEF** (QRadar) for legacy security tools.
- **ECS** for Elastic-oriented sources.
- **Splunk CIM**, **Microsoft ASIM**, and **Google UDM** as mapping references.

### Compliance/control mappings

Future packs should map incidents/findings to NIST CSF, CIS Controls, ISO 27001, SOC 2, PCI DSS, HIPAA, and cloud benchmarks.

## 3. AI-powered SIEM: practical SOTA features

The useful AI features are not "replace the analyst". They are analyst acceleration with auditability:

1. **Natural-language to query** — generate SPL/KQL/EQL/SQL-like queries, show query before execution.
2. **Alert summarization** — summarize evidence, affected entities, likely attack stage, why severity matters.
3. **Investigation planner** — suggest next checks and enrichment steps.
4. **Timeline builder** — produce human-readable incident sequence.
5. **Detection assistant** — draft rules from descriptions or ATT&CK techniques; generate tests.
6. **Triage prioritization** — combine rule severity, anomaly, asset criticality, TI confidence, blast radius.
7. **Entity behavior reasoning** — explain deviations from baseline.
8. **False-positive feedback loop** — learn suppressions and tuning suggestions.
9. **Autonomous enrichment, not autonomous destructive response** — safe read-only enrichment by default; containment requires approval.
10. **RAG over runbooks and local telemetry** — keep sensitive data local where possible and cite sources.

Safety requirements:

- Preserve raw evidence.
- Never let LLM output directly mutate detections or perform response without validation/approval.
- Keep prompt, model, and output audit logs.
- Redact secrets/PII before sending to hosted models.
- Require deterministic fallbacks for core security decisions.

## 4. Recommended AutoSIEM strategy

Build in layers:

1. **MVP core** — local JSONL ingestion, normalization, rules, anomaly, risk, incidents, CLI.
2. **Storage/search** — DuckDB/SQLite for local dev, then ClickHouse/OpenSearch/Postgres+Parquet/object storage.
3. **API/UI** — FastAPI plus React/Next or simple HTMX dashboard.
4. **Connectors** — AWS CloudTrail, Azure AD/Entra, Okta, GitHub audit, Sysmon, Zeek, Suricata, Kubernetes audit, M365.
5. **Rule system** — Sigma import, sequence rules, sliding windows, suppression, exceptions, tests, ATT&CK coverage.
6. **AI investigator** — local fallback first; optional OpenAI/Anthropic/Ollama adapters behind a policy layer.
7. **Production pipeline** — Kafka/Redpanda/NATS, parser workers, enrichment workers, detection workers, case manager.
8. **SOAR** — approval-gated playbooks.

## 5. MVP success criteria

The first implementation should be able to:

- Read raw JSONL events.
- Normalize auth, process, network, DNS, cloud, and generic events into a stable shape.
- Load commented JSON rule files safely.
- Detect suspicious events with MITRE mappings.
- Maintain simple user/host baselines.
- Score entities and generate incidents.
- Produce an AI-style investigation report without needing an external LLM.

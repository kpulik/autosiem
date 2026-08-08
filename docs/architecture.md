# AutoSIEM architecture

## Goals

AutoSIEM should be cloud-native, standards-aligned, AI-assisted, and detection-engineering friendly.

## Reference architecture

```text
Sources
  ├─ endpoint: Sysmon, osquery, EDR, Linux auditd
  ├─ identity: Entra ID, Okta, Google Workspace, IAM
  ├─ cloud: CloudTrail, Azure Activity, GCP Audit
  ├─ network: Zeek, Suricata, firewall, DNS, proxy
  ├─ SaaS/dev: GitHub, GitLab, M365, Slack
  └─ vuln/assets/threat intel
        ↓
Collectors / Connectors
        ↓
Message bus (Kafka/Redpanda/NATS) + dead-letter queues
        ↓
Parser + Normalizer workers
        ↓
Enrichment workers
  ├─ asset criticality
  ├─ identity graph
  ├─ GeoIP / ASN
  ├─ threat intel
  └─ vulnerability/exposure context
        ↓
Storage
  ├─ hot search index
  ├─ analytical column store
  ├─ object-storage archive
  └─ metadata relational DB
        ↓
Detection layer
  ├─ stateless rules
  ├─ sequence/correlation rules
  ├─ anomaly/UEBA models
  ├─ threat-intel matching
  └─ attack-chain/campaign correlation
        ↓
Findings → incidents/cases → response/playbooks
        ↓
AI Investigation layer
  ├─ summarization
  ├─ query generation
  ├─ timeline explanation
  ├─ rule authoring assistant
  └─ runbook RAG
```

## MVP architecture in this repo

The MVP keeps everything in-process:

```text
Ingest surface
  ├─ JSONL/NDJSON (CLI ingest, POST /api/ingest)
  ├─ syslog (RFC 5424/3164) + CEF UDP listeners   (autosiem.listeners)
  └─ connectors: parser + poller + health          (autosiem.connectors)
       file · cloudtrail · okta · github · entra · sysmon · zeek · suricata · asset
  └─ threat intel: STIX bundle + matcher           (autosiem.threat_intel) → AUTO-INTEL-001
        ↓
raw events
  → normalizer
  → rule detector
  → threat-intel matcher
  → anomaly detector (UEBA)
  → suppression
  → feedback weighting
  → enrichment (asset/identity criticality scales risk)
  → risk engine
  → incident builder
  → AI investigation report
  → AI SOC Analyst Runtime
  → SQLite persistence / CLI / optional FastAPI UI
```

Phase-1 local workstation tables:

- `events` — normalized events plus original data JSON
- `findings` — rule/anomaly findings
- `incidents` — incident/case queue with triage fields (status, assignee, resolution, updated_at)
- `incident_comments` — per-incident comment thread (human and AI analyst notes)
- `investigations` — AI analyst status, decision, confidence, and evidence object
- `action_proposals` — policy-gated response proposals with pending/approved/rejected state
- `suppressions` — manual exception/suppression rules (suppress/downgrade, scoped to rule and/or entity, and to a `tenant_id`)
- `audit_log` — append-only operational audit trail for pipeline saves, suppressions, proposal decisions, and triage updates

For how companies deploy AutoSIEM and get data into it (agents, agentless connectors, syslog/CEF forwarding, topologies), see `docs/deployment-and-collection.md`.

## Module map (`src/autosiem/`)

| Module | Responsibility |
|---|---|
| `schemas.py` | `NormalizedEvent`, `DetectionRule`, `Finding`, `Incident`, `Severity`, `EventCategory`, `EntityRisk` |
| `normalization.py` | raw JSON/syslog-ish → OCSF-inspired normalized event; `_infer_category`/`_infer_action` |
| `listeners.py` | syslog (RFC 5424/3164) + CEF parsers and the zero-dependency UDP `SyslogServer` |
| `connectors.py` | connector SDK (`BaseConnector` parser/poller/health), registry, and connectors: `file`, `cloudtrail`, `okta`, `github`, `entra`, `sysmon`, `zeek`, `suricata`, `asset` |
| `threat_intel.py` | STIX 2.x bundle loading, indicator state file, `ThreatIntelMatcher` → `AUTO-INTEL-001` findings at pipeline time |
| `rules.py` | JSON + Sigma-YAML rule loading with safe leading-comment stripping; `apply_rule_state()` overlays persisted enable/disable |
| `sigma.py` | zero-dependency Sigma YAML subset parser, rule conversion, and Sigma export |
| `detection.py` | rule matching and finding creation |
| `coverage.py` | MITRE ATT&CK coverage report and technique watchlist |
| `anomaly.py` | entity behavioral analytics (UEBA): novel-action/IP/host, off-hours, population rarity, peer-group rarity, and burst signals against a per-tenant baseline persisted in SQLite |
| `risk.py` | entity risk aggregation + time-windowed entity-graph incident correlation |
| `enrichment.py` | asset inventory, identity directory, network/CIDR classification and threat-intel context; criticality scales finding risk |
| `suppression.py` | analyst exceptions and auto-repeat suppression for noisy detections |
| `ai.py` | AI investigation abstraction with deterministic local fallback |
| `policy.py` | automation/autonomy policy gates |
| `llm.py` | optional LLM adapter layer (Ollama / OpenAI-compatible) with redaction and local fallback |
| `soc_runtime.py` | AI analyst investigation, tasks, decisions, and action proposals; `search_related_events` queries the event store through the `EventSearcher` protocol |
| `storage.py` | SQLite persistence, rule-state overrides, and a hash-chained audit log |
| `pipeline.py` | end-to-end processing pipeline |
| `web/api.py` | optional FastAPI JSON API and simple HTML UI |
| `cli.py` | `autosiem.cli:main` subcommands (demo/ingest/poll/listen/coverage/export/incidents/incident/timeline/events/findings/approve/reject/audit/audit-verify/suppressions/suppression-add/suppression-delete/incident-update/incident-comments/incident-comment/rules/rule-new/search-nl/update/metrics/users/distributed/connectors/load-intel/intel/sources) |

## Phase 3/4 building blocks

**All Phase 3/4 modules are now WIRED.** The copilot stack (RAG, SOAR, feedback, querygen, rule-assistant, update job, redaction) runs inside the CLI/API/pipeline, the audit-chain + metrics surfaces are live, `rbac.py` guards the API token boundary, and the distributed-transport blocks (`bus`, `workers`, `backends`, `archive`) are wired via the `autosiem.distributed` module. Enable via environment variables:

- `AUTOSIEM_QUEUE_PATH` — SQLite durable queue for backpressure + replay
- `AUTOSIEM_ARCHIVE_PATH` — Append-only journal for crash recovery
- `AUTOSIEM_WORKERS` — Parallel parser workers
- `AUTOSIEM_BACKEND` — Alternate storage (clickhouse/opensearch)

See `docs/deployment-and-collection.md` §"Distributed pipeline" for full configuration details.

| Module | Responsibility |
|---|---|
| `bus.py` | `Bus` interface, `InMemoryBus`, optional `KafkaBus` (kafka-python extra; degrades gracefully), SQLite `DurableQueue` for backpressure + ack-based replay — wired via `distributed.py` |
| `workers.py` | `ParserWorkerPool` — `ThreadPoolExecutor` fan-out with deterministic ordering merge — wired via `distributed.py` |
| `backends.py` | `EventBackend` interface + `SqliteBackend` / `ClickHouseBackend` / `OpenSearchBackend` (stdlib urllib: HTTP JSONEachRow / bulk + search) + `make_backend` factory — wired via `distributed.py` |
| `archive.py` | Append-only JSON-lines journal (`JournalFile`), `ArchiveWriter` with optional queue enqueue, `restore()` / replay from checkpoint — wired via `distributed.py` |
| `distributed.py` | **NEW**: High-level distributed pipeline coordinator; reads `AUTOSIEM_*` env vars, orchestrates queue/archive/workers/backends; wired into CLI `ingest`/`listen` |
| `metrics.py` | `Counter`/`Gauge`/`Histogram`, `MetricsRegistry`, Prometheus `prometheus_text` export, `ApplicationMetrics` singleton, `Span`/`Trace` timing — wired as `cli metrics` + `GET /metrics` |
| `rbac.py` | Multi-tenant RBAC: roles `admin`/`analyst`/`ingest`/`viewer`, permission constants, JSON user store keyed by **sha256 token hashes**, `rbac_from_env()` — wired into the API token guard + CLI `users` (list/add/remove/roles); legacy `AUTOSIEM_API_TOKEN` remains the fallback when no users file is configured |
| `redaction.py` | Per-class PII/secrets redaction (labelled secrets, AKIA/SSH keys, Luhn card numbers, SSN, IP/email/IPv6); re-exported as `autosiem.llm.Redactor` |
| `rag.py` | `RunbookIndex` over `.md` runbooks (ATT&CK-tagged), keyword + TF-IDF-lite retrievers, `RagEngine`, `augment_prompt` — wired as RAG context in `AutoSIEMPipeline` |
| `querygen.py` | Natural-language → canonical search DSL (`translate_query`), CLI-flag rendering (`to_cli_flags`), `QueryTranslator` — wired as CLI `search-nl` + `GET /api/search-nl` |
| `rule_assistant.py` | `draft_rule(description, techniques)`, `write_rule_file`, `generate_test_cases` — wired as CLI `rule-new` |
| `feedback.py` | `FeedbackRecord`/`FeedbackEngine` — analyst approve/reject/comment → per-rule trust weights (applied in the pipeline) |
| `soar.py` | `SoarPlanner.recommend(incident, findings)` → approval-gated response-plan steps (merged into investigation proposals) |
| `update_job.py` | `UpdateJob.run_once()` → `UpdateReport`, `schedule()`; no import-time side effects — wired as CLI `update` |

Storage additions in this batch:

- `rule_state` table — persisted per-rule enable/disable overrides, keyed by a composite `(rule_id, tenant_id)` primary key so each tenant carries its own overrides (`set_rule_enabled`, `list_rule_states`, `rule_state_dict`); `rules.apply_rule_state()` overlays them onto loaded rules.
- The audit log is now a **sha256 hash chain** — every `audit()` row carries `prev_hash` + `hash`; `verify_audit_chain()` returns tamper mismatches (empty = intact).

## Data model

Core objects:

- `NormalizedEvent`
- `DetectionRule`
- `Finding`
- `Incident`
- `Suppression` (manual exceptions + auto-repeat tracking)
- `EntityRisk`
- `Investigation`
- `AnalystTask`
- `AnalystDecision`
- `ActionProposal`

Events keep:

- stable IDs
- timestamps
- category/class/action/outcome fields
- entities: user, host, IP, process, cloud account
- severity/risk signals
- MITRE mappings from detections
- raw event copy

## Why OCSF-inspired rather than strict OCSF immediately?

Strict OCSF support requires the official schema package, validators, complete class mappings, and profile support. For the MVP, AutoSIEM uses an OCSF-inspired normalized core that can later be upgraded to strict OCSF classes without rewriting the detection pipeline.

## AI safety boundary

AI is advisory. Deterministic code handles:

- ingestion
- parsing
- detection matching
- risk scoring
- incident state transitions

AI can:

- summarize
- explain
- collect deterministic evidence
- run approved read-only/low-risk analyst tasks
- propose queries
- propose rules
- recommend next steps
- propose response actions

AI cannot directly:

- suppress alerts
- change rules
- execute containment
- delete evidence
- modify incidents without audit/approval

High-impact actions such as user disablement, endpoint isolation, and indicator blocking are proposal-only at the default autonomy level. Analysts approve/reject them through the CLI, API, or UI; every decision is recorded in `audit_log`.

Suppression rules (manual or auto-repeat) are applied deterministically at ingest, before incident building — they are data-plane controls, not something the AI can toggle at runtime.

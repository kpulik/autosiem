# AutoSIEM roadmap

## Current status (2026-08-08)

- **618 tests, all pass** (`PYTHONPATH=src python3 -m pytest tests/ -q`); `pyright` clean (0 errors / 0 warnings).
- **UEBA + incident correlation deepened (2026-08-08)**: `anomaly.py` now scores seven named behavioral signals (novel action / source IP / host, off-hours, population rarity, peer-group rarity, burst) against a per-tenant baseline persisted in SQLite, with warm-up gating and a per-signal explanation on every finding; `risk.py` correlates findings through a 24h-windowed entity graph so one incident spans user ↔ host ↔ IP ↔ cloud account and carries a time-ordered kill chain.
- **16 detection rules** covering **20 MITRE ATT&CK techniques**, with **0 gaps against the 15-technique high-value watchlist** in `coverage.py`. That watchlist is a curated subset AutoSIEM maintains by hand, not MITRE's published matrix, so this is not a claim of full ATT&CK Enterprise coverage. Measuring against the real matrix is open work.
- Demo `examples/events.jsonl` (15 events) runs a full kill-chain on profile `alice` → one critical incident (risk 1000) for which the AI runtime proposes containment (never auto-executes).
- Sigma YAML import/export round-trip rules losslessly; the per-rule test harness + CI (suite + coverage smoke + pyright on Py 3.10/3.12) are live on the private repo `kpulik/autosiem`.
- Phase 2 ingest surface shipped: syslog/CEF UDP listeners, 9 connectors (file/cloudtrail/okta/github/entra/sysmon/zeek/suricata/asset), per-source health, STIX/TAXII threat-intel ingestion.
- **Phase 4 copilot + the audit-chain/metrics parts of Phase 3 are now WIRED**, **multi-tenant RBAC is implemented + wired** (`src/autosiem/rbac.py`, CLI `users`, RBAC token guard in the API), and **the Phase-3 distributed pipeline is wired** (`src/autosiem/distributed.py` — durable queue, workers, archive, ClickHouse/OpenSearch backends, all opt-in via `AUTOSIEM_*` env vars on `cli ingest`/`listen`). A first-alpha security review + High hardening (SEC-001..SEC-004) completed now lives in `docs/security-review.md`.
- **RBAC depth is now shipped**: per-tenant row isolation on the data plane (`tenant_id` on events/findings/incidents/investigations/action_proposals), token rotation + revocation (CLI `users rotate|revoke`, `POST /api/users/{name}/rotate-token|revoke-token`), and a full user-management audit trail written into the hash-chained audit log.
- **Control-plane tenancy is now shipped**: `rule_state` and `suppressions` are tenant-scoped too, so one tenant's analyst disabling a rule or adding a suppression no longer affects every other tenant.

## Phase 0 — MVP core

- [x] Research baseline
- [x] Normalized event model
- [x] Comment-tolerant JSON rule loader
- [x] Rule detection engine
- [x] Entity behavioral analytics (UEBA) — seven signals, warm-up gating, peer-group comparison, baseline persisted per tenant (`anomaly.py`)
- [x] Entity risk scoring
- [x] Incident generation
- [x] Local deterministic AI investigation report
- [x] Policy-bound AI SOC Analyst Runtime
- [x] CLI demo/ingest commands

## Phase 1 — Local analyst workstation SIEM

- [x] SQLite persistence for events, findings, incidents, investigations, proposals, and audit log
- [x] CLI persistence workflows for incident queue, event listing, proposal approval/rejection, and audit review
- [x] Optional FastAPI JSON API
- [x] Simple local web UI for incident queue, incident detail, and proposal decisions
- [x] Search/query DSL (free-text `--query` + `--entity` filters on events and incidents)
- [x] Timeline view (per-incident chronological timeline)
- [x] Suppression/exception framework (manual suppressions + auto-repeat, stored and applied at ingest)
- [x] Incident triage workflow (status/assignee/resolution + comment thread)
- [x] Generic OpenAI-compatible LLM config (URL + optional API key + context window/sampling limits; URL alone infers backend)
- [x] ATT&CK coverage matrix (CLI `coverage` report + technique watchlist)
- [x] Sigma import (YAML subset, auto-converted at load; see `rules/encoded_powershell.yaml`)
- [x] Sigma rule export (`autosiem.cli export` writes `<rule_id>.yaml` per rule)
- [x] Rule tests and CI (per-rule positive/negative harness in `tests/test_rules.py` — every rule in `rules/` must have cases or the suite fails; GitHub Actions workflow in `.github/workflows/ci.yml` runs the suite + coverage smoke + pyright on Python 3.10/3.12 — live on the private GitHub repo `kpulik/autosiem`)

## Phase 2 — Real integrations

Ingest surface (prerequisite for connectors):

- [x] JSONL ingest endpoint with token auth (`POST /api/ingest`; TLS via reverse proxy at deployment)
- [x] Syslog (RFC 5424) + CEF listeners (`autosiem.listeners`; UDP `cli listen`, zero-dep `SyslogServer`, syslog/CEF field mapping + severity translation, sshd-message field inference so real failed logins fire AUTO-AUTH-001)
- [x] Connector SDK (parser + poller + health per source — `autosiem.connectors`, `BaseConnector` + `FilePollerConnector` + registry; CLI `poll`/`connectors`)
- [x] Forwarder agent or documented Beats/Vector/Fluent Bit configs (see `docs/deployment-and-collection.md` §“Getting data in today” for rsyslog/syslog-ng/Filebeat/Vector/Fluent Bit examples)
- [x] Source-health / normalization-test view in the UI (`/sources` page + `GET /api/sources` + CLI `sources` — per-source event counts and first/last seen)

Connectors:

- [x] AWS CloudTrail connector (`CloudTrailConnector` in `autosiem.connectors` — polls S3-style `{"Records":[...]}` exports or JSONL of events from a file/dir, maps `userIdentity`/`eventName`/`roleArn`/`errorCode` to the normalized schema so cloud rules fire; operator syncs from S3, e.g. `aws s3 sync s3://bucket/AWSLogs/... dir`; direct S3/SQS pull would need a boto3 extra)
- [x] Azure/Entra ID connector (`EntraConnector` + `entra_to_raw` — sign-in logs; failed → AUTO-AUTH-001, success → AUTO-CRED-001)
- [x] Okta connector (`OktaConnector` + `okta_to_raw` — system-log entries; failed → AUTO-AUTH-001, success → AUTO-CRED-001)
- [x] **Okta API-native connector** (`OktaApiConnector`, `okta-api`) — polls `/api/v1/logs` directly with `rel="next"` pagination, a cursor persisted across restarts, bounded retry with `X-Rate-Limit-Reset` backoff, and the token read from `AUTOSIEM_OKTA_TOKEN` rather than argv. Stdlib `urllib` only; a free Okta developer org is enough to run it.
- [x] GitHub audit connector (`GitHubConnector` + `github_to_raw` — cloud-categorised audit entries feeding entity risk)
- [x] Sysmon parser (`SysmonConnector` + `sysmon_to_raw` — accepts WinEvent JSON dicts and Windows-Event XML; `Image`→process_name, `CommandLine`→command_line so cred-dump/masquerading rules fire)
- [x] Zeek/Suricata parser (`ZeekConnector` + `suricata_to_raw` — network pairs; Zeek HTTP logs project a `url` so the web-exploit rule fires)
- [x] STIX/TAXII threat-intel ingestion (`autosiem.threat_intel` — loads STIX 2.x indicator bundles, keeps them in a JSON state file, `ThreatIntelMatcher` matches IP/domain/URL/hash indicators at pipeline time, surfaced as `AUTO-INTEL-001`; CLI `load-intel`/`intel`)
- [x] Asset inventory import (`AssetConnector` + `asset_to_raw` — `endpoint`-categorised records feeding host/entity risk)

See `docs/deployment-and-collection.md` for how companies deploy AutoSIEM and get data into it.

## Phase 3 — Production scale

**Phase 3 distributed pipeline is now WIRED** via `autosiem.distributed` module. Enable components via environment variables:

- `AUTOSIEM_QUEUE_PATH` — Enable SQLite durable queue for backpressure and replay
- `AUTOSIEM_ARCHIVE_PATH` — Enable journal archive for durability
- `AUTOSIEM_WORKERS` — Parallel parser workers (default: 4)
- `AUTOSIEM_BACKEND` — Alternate storage backend (`clickhouse`, `opensearch`)

- [x] Durable audit logs — audit log is a sha256 **hash chain** (`storage.audit` writes `prev_hash`/`hash`; `storage.verify_audit_chain` returns tamper mismatches, empty = intact); CLI `audit-verify` wired (`cli audit-verify` prints `intact` + entry count).
- [x] Metrics/tracing — `autosiem.metrics` (`Counter`/`Gauge`/`Histogram`, `MetricsRegistry`, Prometheus `prometheus_text`, `ApplicationMetrics`, `Span`/`Trace`); `cli metrics` + `GET /metrics` both export Prometheus text counts.
- [x] Durable queue + backpressure — `autosiem.bus.DurableQueue` (SQLite FIFO with `push`/`ack`/`pending`); wired into `cli ingest`/`listen` via `AUTOSIEM_QUEUE_PATH` env var.
- [x] Parser workers — `autosiem.workers.ParserWorkerPool`; wired via `AUTOSIEM_WORKERS` env var.
- [x] Object archive — `autosiem.archive` (append-only `JournalFile`, `ArchiveWriter`); wired via `AUTOSIEM_ARCHIVE_PATH` env var.
- [x] Backpressure and replay — `DurableQueue` enforces `max_pending`, replays unacked messages on restart; wired into distributed pipeline.
- [x] ClickHouse/OpenSearch storage — `autosiem.backends` (`EventBackend` + `make_backend`); configurable via `AUTOSIEM_BACKEND` env var.
- [x] Kafka/Redpanda/NATS bus — `autosiem.bus.KafkaBus` (optional, requires `kafka-python`); available for production message bus.
- [x] Multi-tenant RBAC — `autosiem.rbac`: roles `admin` (everything), `analyst` (triage + approvals + rule management), `ingest` (machine accounts: ingest only), `viewer` (read-only); per-endpoint permission checks enforced on `/api/*`; user store keyed by **hashed** tokens (no plaintext). CLI `users` (list/add/remove/rotate/revoke/roles) + `AUTOSIEM_RBAC_FILE` bearer guard, with the legacy single-token `AUTOSIEM_API_TOKEN` retained as the fallback when no users file is configured. First-alpha review: `docs/security-review.md`.
- [x] **Per-tenant data isolation** — every data-plane table (`events`, `findings`, `incidents`, `investigations`, `action_proposals`) carries an indexed `tenant_id`, back-filled to `default` by an automatic migration. In RBAC mode each request is scoped to the authenticated user's tenant on both read *and* write, so a cross-tenant fetch returns **404 rather than 403** (no existence probing). Unscoped calls (the CLI, and legacy single-token mode) keep seeing every row, so single-tenant deployments are unaffected.
- [x] **Control-plane tenancy** — `suppressions` and `rule_state` are tenant-scoped as well. `rule_state` is rebuilt with a composite `(rule_id, tenant_id)` primary key so the same rule can be enabled for one tenant and disabled for another; `suppressions` gains an indexed `tenant_id`. Both are back-filled to `default` by an automatic migration (existing rows and single-tenant deployments are unaffected). The suppression engine and the rule-state overlay are built **per tenant** on every ingest/test path (`_pipeline(tenant_id=...)`), and the JSON API *and* the HTML UI POST handlers (rule toggle, suppression add/delete) all scope to the caller's tenant. The **audit log stays deliberately global** — a tenant must not be able to hide its own actions from an operator.

  The unauthenticated read-only HTML **GET** pages (`/`, `/events`, `/rules`, …) still render across all tenants by design: they are the local-workstation view, gated by `AUTOSIEM_AUTH_INSECURE`.
- [x] **Token rotation + revocation** — `Rbac.rotate_token()` issues a fresh `secrets.token_urlsafe(32)` and returns the plaintext exactly once; `Rbac.revoke_token()` drops the hash but keeps the account. Exposed as CLI `users rotate|revoke` and `POST /api/users/{name}/rotate-token|revoke-token` (plus `GET`/`POST /api/users` and `DELETE /api/users/{name}`), all gated on `users:manage`.
- [x] **User audit trail** — every user-store mutation (`rbac_user_added`, `rbac_user_removed`, `rbac_token_rotated`, `rbac_token_revoked`) is appended to the tamper-evident hash-chained audit log from both the CLI and the API, recording the acting principal.

## Phase 4 — SOTA AI SOC copilot

- [x] LLM adapter policy layer (any OpenAI-compatible endpoint, schema-validated, redacted, with local fallback)
- [x] PII/secrets redaction — `autosiem.redaction` deepens per-class policy (labelled secrets, AKIA/SSH keys, Luhn-checked card numbers, SSN, IP/email/IPv6); `llm.py` re-exports `Redactor` so `autosiem.llm.Redactor` still works. (Originally scoped as "deepen per-class policy"; done.)
- [x] Rule-management API (list/enable/disable/test rules from the UI) — `rule_state` table + `set_rule_enabled`/`list_rule_states`/`rule_state_dict` overlay applied in the pipeline (`_run_pipeline_command`/`_run_listener`/UI ingest); CLI `rules` (list/`--enable`/`--disable`/`--status`) + `GET /api/rules`, `POST /api/rules/{id}`, `/api/rules/test`, and the `/rules` UI page wired.
- [x] RAG over runbooks and historical incidents — `autosiem.rag` (`RunbookIndex`, keyword + TF-IDF-lite retrievers, `RagEngine`, `augment_prompt`, `default_rag_engine`); `docs/runbooks/*.md` created and RAG context appended to local reports + passed to the LLM via `extra_context` in `AutoSIEMPipeline`.
- [x] Natural-language search/query generation — `autosiem.querygen` (`translate_query`, `to_cli_flags`); wired as CLI `search-nl` and `GET /api/search-nl`.
- [x] Rule-authoring assistant with generated tests — `autosiem.rule_assistant` (`draft_rule`, `write_rule_file`, `generate_test_cases`); wired as CLI `rule-new`.
- [x] Analyst feedback learning — `autosiem.feedback` (`FeedbackEngine` trust weights); wired into `AutoSIEMPipeline` so rejections lower a finding's effective `risk_points` before incident building.
- [x] Approval-gated SOAR recommendations — `autosiem.soar` (`SoarPlanner.recommend`); merged into `Investigation.action_proposals` (base-technique dedup, sets `status` to `needs_approval`) in `AutoSIEMPipeline`.
- [x] Threat-intel / coverage update cycle — `autosiem.update_job` (`UpdateJob.run_once`) wired as CLI `update`: reloads local rules, recomputes ATT&CK coverage, and refreshes STIX intel from a configured URL or path. Not hourly by itself — the `schedule()` daemon is a library API nothing starts, so run it from cron. Rules are never fetched over the network; automatic rule updates are open work.

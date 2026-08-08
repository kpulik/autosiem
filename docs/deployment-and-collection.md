# How companies deploy AutoSIEM and get data in

_Written to answer: "how do companies set this up in their ecosystem? how do we connect to the computers and get the data?" Validated against 2026 vendor practice (Microsoft Sentinel data-connector model; plus the well-established Splunk/Elastic/CrowdStrike/QRadar/Wazuh collection landscape)._

## The short answer

**You almost never connect directly to a company's computers.** You connect to the places that already produce and aggregate logs. A SIEM collects from the edges and central services:

1. **Install lightweight collector agents** on servers/endpoints (optional, for OS + app logs).
2. **Point existing log pipelines** at AutoSIEM (syslog, CEF, Windows Event Forwarding, Beats/Fluent Bit/Vector).
3. **Give AutoSIEM API access** to cloud/identity/security services it polls on its own (agentless).

Modern SIEMs converge all three — see Microsoft Sentinel's model: agent-based collection via the Azure Monitor Agent for syslog/CEF/custom logs, service-to-service connectors for Microsoft + AWS, and custom connectors via the Logs Ingestion API / Codeless Connector Framework. The agentless, "pull from the platform" path is the fastest-growing pattern (CrowdStrike Next-Gen SIEM, for example, is built almost entirely around cloud-data-lake + platform telemetry connectors rather than per-endpoint agents).

The full data flow end to end:

```text
Source (server, cloud, identity, network, SaaS, EDR)
  → collector/agent or API connector
  → AutoSIEM ingest endpoint (TLS)
  → parser + normalizer (OCSF-inspired schema; raw copy preserved)
  → detection engine (rules + anomaly)  →  findings
  → suppression/exception engine  →  incidents
  → AI SOC Analyst Runtime (triage notes, enrichment, recommended response)
  → approved/executed response (via EDR/identity/cloud APIs, human-gated)
  → audit log of everything
```

## One company's setup, step by step

1. **Deploy AutoSIEM.** A VM or container on their infra (on-prem) or in a cloud account. Auth, TLS, and a way to rotate credentials are configured first — the engine is security software, so securing the engine comes before connecting anything.
2. **Stand up ingest endpoints.** AutoSIEM opens a small set of listening endpoints the customer's systems can send to:
   - HTTPS JSONL push (analogous to Splunk's HTTP Event Collector — works anywhere HTTPS works; this is the modern, not-yet-deprecated pattern in the industry).
   - Syslog (`/RFC 5424`) and CEF listeners for network/security appliances.
   - A connector runner that polls cloud/identity/EDR APIs.
3. **Connect each source** (see the table below). Each source is a connector: a parser that turns that vendor's events into AutoSIEM's normalized schema.
4. **Verify normalization.** A source-health view shows ingest rate, parse failures, and a sample of raw→normalized events so the company confirms data is landing correctly.
5. **Turn on detection content.** Rules ship tuned for the environment; suppressions/exceptions quiet known benign patterns (already built into AutoSIEM). This is when real incidents start appearing.
6. **Run the workflow.** Analysts triage the queue, the AI SOC runtime drafts notes and proposes next steps / response actions, and approvers approve or reject high-impact actions. Every action is audited.
7. **Operationalize.** Retention policies, backups, RBAC/SSO, audit-log review, and staged hourly updates (rules, threat intel, ATT&CK metadata).

## The four ways data gets in (the core question)

| Path | What it is | Effort to adopt | Typical sources |
|---|---|---|---|
| **A. Collector agents** | Small program installed on Windows/Linux servers; reads OS + app logs, sends over TLS. | Medium (must be deployed fleet-wide) | Windows Event Log, Sysmon, Linux auditd, file tails |
| **B. Agentless API connectors** | AutoSIEM polls a service API with a least-privilege, read-only role/credential. Nothing installed. | Low–medium (one-time credential setup) | CloudTrail, Entra ID, Okta, GitHub, EDR/XDR platforms |
| **C. Forward existing pipelines** | Company already runs syslog/Rsyslog/WEF/Beats/Fluent Bit/Vector/Kafka; point a copy at AutoSIEM. | Low (config only) | Firewalls, IDS/IPS, proxies, DNS, any syslog/CEF device |
| **D. Network capture (later)** | Dedicated collectors on the wire or consuming flow/alert feeds. | High | Zeek, Suricata, NetFlow, broker/proxy |

Practice: most companies use **B + C** first (fast, no endpoint software), add **A** for endpoint telemetry once value is proven, and consider **D** only for high-security networks. This ordering is what we should mirror in the product — agentless and pipeline-forwarding connectors first, then a first-party agent.

Specific connector examples to build (this is our Phase 2 list):

- **AWS CloudTrail** — via S3 bucket + SNS/SQS or by polling (agentless, matches B). The classic "first connector" and a good proof point.
- **Microsoft Entra ID / Azure Activity** — Graph API / Azure Monitor service-to-service (B).
- **Okta** — system log API (B).
- **GitHub** — audit log API (B).
- **Windows / Linux servers** — first-party agent (A) or documented Beats/Vector config (C).
- **Syslog/CEF appliances** — built-in listener (C).
- **Zeek/Suricata** — parser for their JSON/EVTX-style output (D).

## "We don't connect to your computers" (topology and trust)

AutoSIEM follows the standard collector model to avoid opening inbound holes:

- **Outbound-only collection.** Agents and forwarders on the customer's machines connect **outbound** to AutoSIEM over TLS. The company doesn't punch firewall holes into AutoSIEM; AutoSIEM doesn't need to reach the endpoints.
- **Agentless pull.** For cloud/identity/EDR, AutoSIEM uses a read-only credential the company provisions.
- **Auth on every ingest.** Transport key / API token / client cert per source; secrets stored in AutoSIEM's secret store (env/injected/vault), never hardcoded in rules or config checked into git.
- **Least privilege.** Cloud roles grant only what's needed to read the required logs.
- **Deterministic core.** Parsing, detection, risk scoring, and suppression are code, not AI. The AI layer is advisory and its actions are policy- and approval-gated (see `docs/ai-soc-runtime.md`).
- **Data residency.** Self-hosting means the logs never leave the customer's control — a core selling point vs. many SaaS SIEMs.

## Deployment topologies

| Topology | Who | Notes |
|---|---|---|
| **Single-node** | Small org / home lab / free tier (today's MVP) | All-in-one ingest + detect + UI + local or remote LLM |
| **Collector-tier + server** | Mid-size org | Lightweight forwarders/connectors in the network; central AutoSIEM server |
| **Distributed pipeline** | Large org (Phase 3) | Kafka/Redpanda/NATS bus, parser workers, ClickHouse/OpenSearch search tier — all **wired** via `autosiem.distributed` (opt-in via `AUTOSIEM_*` env vars on `cli ingest`/`listen`; see `docs/roadmap.md`) |
| **Managed SaaS, multi-tenant** | AutoSIEM paid tier | Customer gives read-only connector creds or points forwarders at us; RBAC + SSO later |

Hybrid is common: **collectors on-prem, SIEM in the cloud** (or the reverse). The collector-facing surface (TLS JSONL + syslog/CEF listeners) is what makes all of these work from the same connector code.

## What feeds the AI and why it's safe

The AI SOC analyst consumes normalized, already-detected incidents — it does not ingest raw fleets directly. It:

- reads the structured incident + findings + evidence,
- pulls related normalized events (read-only),
- writes case notes,
- recommends and **proposes** response actions.

All of it runs through the automation policy; high-impact actions (disable user, isolate host, block indicator) are proposal-only pending human approval. So the collection surface can be broad while the blast radius of the AI stays small — exactly the "automated but not risky to trust" balance the product is built around.

## Free / personal tier mapping

The same architecture serves individuals later:

- Install the lightweight agent on their own machines, or point local pipelines (OPNsense/pfSense syslog, GitHub API) at a personal AutoSIEM.
- Local LLM via any OpenAI-compatible endpoint (LM Studio/Ollama/vLLM) — already supported.
- Community rules + limited connectors; upgrade path to the managed/enterprise tier.

## Getting data in today (implemented)

The Phase-2 ingest surface is live in the MVP: a JSONL HTTP endpoint, syslog/CEF UDP listeners, a connector SDK with a file-polling reference connector, and a per-source health view. Everything below runs with zero third-party runtime dependencies.

### 1. Syslog / CEF UDP listener

```bash
PYTHONPATH=src python3 -m autosiem.cli listen --host 0.0.0.0 --port 5514 --db data/autosiem.db
```

- Listens for UDP datagrams on port 5514 by default (use 514 with `sudo`).
- Parses RFC 5424 and RFC 3164 syslog, CEF (`CEF:0|vendor|product|...`), and CEF-over-syslog (a CEF payload inside a syslog frame).
- Maps CEF `src`/`dst`/`suser`/`duser`/`dhost`/`rt` to `src_ip`/`dst_ip`/`user`/`host`/`timestamp` (actor `suser` wins over `duser`; `dhost` wins over `shost`), scales CEF severity 0–10 to product severities, and translates syslog PRI → severity.
- Infers `user`/`src_ip`/`outcome` from common sshd message shapes (`Failed password`, `Accepted password`, `session opened`) so real failed logins fire `AUTO-AUTH-001`/`AUTO-CRED-001` with no vendor-specific parsing.
- Every datagram flows through the normal pipeline (normalize → detect → risk → incidents → AI analyst) and is persisted to the DB.

### 2. Connector SDK + file polling

```bash
PYTHONPATH=src python3 -m autosiem.cli connectors   # list registered connectors
PYTHONPATH=src python3 -m autosiem.cli poll --path /var/log/autosiem/events.jsonl --db data/autosiem.db
```

`BaseConnector` (parser + poller + health) is the smallest unit of "get data into AutoSIEM": write a subclass for CloudTrail, Okta, etc., register it in the `registry`, and the CLI and API can drive it. The shipped `file` connector tails `.jsonl` files or directories and handles log rotation (truncation) by tracking byte offsets. A cron/launchd/systemd timer running `cli poll` every minute gives continuous collection today.

The **CloudTrail** connector normalizes real AWS records. Sync an S3 export into a path (or drop a JSONL of events) and poll it:

```bash
# one-time: pull CloudTrail JSON from S3 into ./cloudtrail (any IAM user/role with read access)
aws s3 sync s3://your-bucket/AWSLogs/123456789012/CloudTrail/ ./cloudtrail

PYTHONPATH=src python3 -m autosiem.cli poll --connector cloudtrail --path ./cloudtrail --db data/autosiem.db
```

Each file may be an S3-style export (`{"Records": [...]}` with many events) or JSONL with one event per line. Records map `userIdentity.userName` (or the `arn` tail) → `user`, `eventName` → `action`, `sourceIPAddress` → `src_ip`, `accountId`/`recipientAccountId` → `cloud_account`, and `requestParameters.roleArn` → `resource`, with `errorCode` driving `outcome` (failure/success) — so an `AssumeRole` into an `Admin*` role trips `AUTO-CLOUD-001` (see `examples/cloudtrail.json`), and failed sign-ins surface through the anomaly baseline detector, all with no vendor-specific rules.

### 3. Forwarder configs (point existing pipelines at AutoSIEM)

rsyslog → AutoSIEM UDP listener:

```ini
# /etc/rsyslog.d/autosiem.conf
*.* @192.0.2.10:5514     # UDP (plain); use @@ for TCP
```

syslog-ng → AutoSIEM UDP listener:

```conf
# /etc/syslog-ng/conf.d/autosiem.conf
destination d_autosiem { udp("192.0.2.10" port(5514)); };
log { source(s_sys); destination(d_autosiem); };
```

Filebeat/Vector/Fluent Bit → JSONL HTTP endpoint (`POST /api/ingest`, ndjson body, optional `x-api-key` token auth). For example, a Vector `file` → `http` sink pushing each JSON event line as NDJSON:

```toml
[sinks.autosiem]
type = "http"
inputs = ["parsed"]
uri = "http://127.0.0.1:8000/api/ingest"
encoding.codec = "ndjson"
# request.headers.AUTOSIEM_INGEST_TOKEN = "${AUTOSIEM_INGEST_TOKEN}"
```

### 4. Source-health view

```bash
PYTHONPATH=src python3 -m autosiem.cli sources --db data/autosiem.db
```

or in the UI: the **Sources** page (`/sources`, API `GET /api/sources`) shows per source the event count and first/last seen — the first check that normalization is working before you trust the detection queue.

## What this means for our roadmap

The **ingest surface** (the prerequisite for connectors) is implemented: HTTPS JSONL ingest with token auth, syslog (RFC 5424) + CEF listeners, the connector SDK, documented forwarder configs (above), a source-health view, and all Phase-2 connectors (CloudTrail, Entra ID, Okta, GitHub, Sysmon, Zeek, Suricata, asset inventory) plus STIX/TAXII threat-intel ingestion.

The **Phase-3 distributed pipeline** is now wired into the CLI and listeners. Use environment variables to enable each component:

### 5. Distributed pipeline (Phase 3)

Enable backpressure, durability, parallel processing, and alternate storage backends:

```bash
# Enable durable queue with backpressure (SQLite-backed)
export AUTOSIEM_QUEUE_PATH=data/queue.db
export AUTOSIEM_QUEUE_MAX_PENDING=10000

# Enable journal archive for replay after crash
export AUTOSIEM_ARCHIVE_PATH=data/archive.jsonl

# Enable parallel parser workers (default: 4)
export AUTOSIEM_WORKERS=4

# Use ClickHouse or OpenSearch instead of SQLite
export AUTOSIEM_BACKEND=clickhouse
export AUTOSIEM_BACKEND_URL=http://localhost:8123
export AUTOSIEM_BACKEND_TABLE=events

# Or OpenSearch:
# export AUTOSIEM_BACKEND=opensearch
# export AUTOSIEM_BACKEND_URL=http://localhost:9200
# export AUTOSIEM_BACKEND_INDEX=events

# Then run ingest/listen as usual:
PYTHONPATH=src python3 -m autosiem.cli ingest --file examples/events.jsonl --db data/autosiem.db
```

**Component details:**

| Component | Module | Purpose |
|---|---|---|
| **DurableQueue** | `autosiem.bus` | SQLite FIFO with ack/replay; backpressure via `max_pending` |
| **JournalFile** | `autosiem.archive` | Append-only log for durability; replay from checkpoint after crash |
| **ParserWorkerPool** | `autosiem.workers` | Parallel chunked processing; deterministic merge |
| **ClickHouseBackend** | `autosiem.backends` | HTTP JSONEachRow bulk insert; fast columnar storage |
| **OpenSearchBackend** | `autosiem.backends` | Bulk API insert; full-text search tier |

**Data flow in distributed mode:**

```
CLI ingest/listen
  → ArchiveWriter (journal for durability)
  → DurableQueue (backpressure + replay)
  → ParserWorkerPool (parallel processing)
  → Backend storage (SQLite/ClickHouse/OpenSearch)
```

When `AUTOSIEM_QUEUE_PATH` is set, unprocessed events survive restarts. The queue is compacted automatically when acked messages exceed 1000 entries. When `AUTOSIEM_ARCHIVE_PATH` is set, every raw event is journaled before processing for forensic replay.

## Okta, API-native (`okta-api`)

The `okta` connector reads a file someone exported. The `okta-api` connector
talks to Okta directly, so there is no export step to schedule or keep working.

```bash
export AUTOSIEM_OKTA_TOKEN='00abc...'          # SSWS API token
PYTHONPATH=src python -m autosiem.cli poll --connector okta-api \
  --url https://dev-123456.okta.com --db data/autosiem.db
```

Run it from cron or a systemd timer; each run resumes from the stored cursor.

What it handles for you:

- **Pagination** — follows Okta's `Link: <...>; rel="next"` header, bounded by
  `--max-pages` (default 10) so a single run cannot loop away.
- **Cursor persistence** — the next link is written to
  `<db-dir>/okta-api_cursor.json` (override with `--state`), so a restart
  resumes exactly instead of replaying or skipping a window. Okta's documented
  polling pattern is to follow the next link forever; it stays valid and returns
  an empty page when there is nothing new.
- **Rate limiting** — a 429 is retried up to 3 times, waiting for
  `X-Rate-Limit-Reset` when Okta sends it and falling back to exponential
  backoff, capped at 60s. 5xx responses retry the same way.
- **Credentials** — the token is read from an environment variable
  (`--token-env`, default `AUTOSIEM_OKTA_TOKEN`). There is deliberately no
  `--token` flag: arguments end up in shell history and in `ps` output.
- **Failure reporting** — an invalid token, a missing token or an unreachable
  org is surfaced through `connector.health()` and printed by `cli poll`; the
  poll returns no events rather than raising.

First run with no cursor reaches back `--since` (or 24h by default). Events map
through the same tested `okta_to_raw` mapper as the file connector, so failed
sign-ins fire `AUTO-AUTH-001` and successful ones `AUTO-CRED-001`.

Getting a token: create a free Okta developer org, then Security → API → Tokens
→ Create Token. The token inherits your admin permissions, so use a read-only
service account in anything real.

Adding another API-native connector: subclass `BaseConnector` the way
`OktaApiConnector` does, inject the transport via config so it stays testable
without a network, and register it in `registry`.

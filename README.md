# AutoSIEM

AutoSIEM is a greenfield, AI-ready SIEM foundation built around modern security operations patterns:

- OCSF-style normalized events
- MITRE ATT&CK mappings
- Sigma-like detection concepts
- Streaming-friendly ingestion and correlation
- Entity behavioral analytics (UEBA)
- Entity risk scoring
- AI SOC analyst runtime with approval-gated response proposals
- SQLite persistence, CLI workflows, and an optional FastAPI/API UI MVP

This repository currently contains a Python MVP core rather than a full distributed production SIEM. The intent is to build iteratively: prove the detection/risk/AI analyst pipeline, then add production storage, API, UI, connectors, distributed workers, model operations, and enterprise governance. See `docs/roadmap.md` for where the project is and what is planned.

## Key features

- **Normalized event model** — OCSF-inspired schema so one rule detects the same attack from any source (`autosiem.normalization`).
- **Detection engine** — JSON + Sigma-YAML rules with a rich selection-operator language, per-rule risk points, and MITRE ATT&CK tags (`autosiem.detection`, `autosiem.rules`, `autosiem.sigma`).
- **ATT&CK coverage reporting** — coverage against MITRE's full published Enterprise matrix (vendored as a distilled index, refreshable with `cli update --refresh-attack`) plus a curated high-value watchlist, with a per-tactic breakdown and detection of technique IDs MITRE no longer publishes (`cli coverage`).
- **Entity behavioral analytics (UEBA)** — per-entity baselines scoring seven named signals: novel action, novel source IP, novel host, off-hours activity, population-wide rarity, peer-group rarity ("no other user has ever run this"), and event bursts. Baselines persist per tenant, so a restart does not relearn from zero, and every anomaly finding carries a breakdown of exactly which signals fired and why (`autosiem.anomaly`).
- **Incident correlation** — findings are joined into one incident when they share an entity within a 24h window, transitively across entity types, so a single case spans user ↔ host ↔ IP ↔ cloud account and reads as an attack story with a time-ordered ATT&CK kill chain (`autosiem.risk`).
- **Entity enrichment** — asset criticality, identity context (department, privileged, disabled), network/CIDR classification, and threat-intel hits, all from local files or indicators you already load. No API keys, no third-party calls. Asset and identity criticality scale finding risk, so the same detection on a crown-jewel host outranks it on a spare laptop (`autosiem.enrichment`).
- **Identity roles** — mark an account as `backup`, `config-management`, `ci-deploy`, `vuln-scanner`, `it-admin` or `scm-admin` in the identity file, and findings that are that account's normal job (a backup account creating a shadow copy, the deploy pipeline assuming the admin role) are turned down to low severity with the reason recorded. Never hidden, and never applied to critical rules, log clearing, disabled defences, exfiltration, threat-intel hits, behavioural anomalies or disabled accounts. Anything the account does off its list still escalates in full.
- **Risk scoring & triage** — entity risk aggregation and a full triage workflow (status, assignee, resolution, comment thread).
- **AI SOC analyst runtime** — a deterministic local investigator (or your own LLM) that investigates and proposes actions; high-impact actions always require human approval. Its related-event task really queries the event store, answering "what else has this user/host/IP done?" and attaching the prior activity as evidence.
- **Suppressions & exceptions** — analyst-defined exceptions and auto-repeat suppression for noisy detections, applied at ingest and fully audited.
- **Ingest surface** — JSONL CLI + HTTP endpoint, syslog (RFC 5424/3164) + CEF UDP listeners, a connector SDK (file-based CloudTrail, Okta, Entra ID and GitHub exports, plus **API-native** `okta-api`, `github-api`, `entra-api` and `cloudtrail-api` over S3; Sysmon, Zeek, Suricata, asset inventory), and STIX/TAXII threat-intel matching.
- **Security controls** — fail-closed API and UI auth, multi-tenant RBAC with salted PBKDF2 token hashes, a write-only ingest token for collectors, CSRF on UI forms, and a hash-chained audit log sealed with an HMAC key held outside the database (`AUTOSIEM_AUDIT_SECRET`). See [`SECURITY.md`](SECURITY.md).
- **Optional PostgreSQL control plane** — a shared store with forward-only checksummed migrations and a transactional event outbox for OpenSearch/ClickHouse projection; SQLite stays the default. Implemented, not HA-certified: see [`docs/postgresql.md`](docs/postgresql.md).
- **Zero runtime dependencies** — the entire core uses only the Python standard library.

## Quick start

### One-command dashboard

Install API deps if needed, seed demo data, start the server, and open the browser:

```bash
./scripts/run_dashboard.sh
```

Then the incident queue is at `http://127.0.0.1:8000/` and API docs at `http://127.0.0.1:8000/docs`.

Optional environment overrides:

```bash
AUTOSIEM_DB=data/autosiem.db AUTOSIEM_PORT=9000 ./scripts/run_dashboard.sh
```

Stop the server with `Ctrl+C` in the terminal that launched it.

### CLI

Run the demo pipeline and persist results to SQLite:

```bash
PYTHONPATH=src python -m autosiem.cli demo --db data/autosiem.db
```

Process your own JSONL events:

```bash
PYTHONPATH=src python -m autosiem.cli ingest --file examples/events.jsonl --db data/autosiem.db
```

Check MITRE ATT&CK coverage across your detection rules (which of the watchlist techniques you can detect, and which are gaps):

```bash
PYTHONPATH=src python -m autosiem.cli coverage --rules rules
```

The report measures two things and names both:

- **The full ATT&CK Enterprise matrix**, from MITRE's published STIX bundle
  distilled into `src/autosiem/attack_enterprise_index.json`. The shipped rule
  set covers **20 of 697 techniques (2.9%)** and **15 of 222 parent techniques
  (6.8%)** on ATT&CK 19.2, broken down per tactic. That is what a 16-rule
  demonstration rule set covers; it is not a production content library.
- **A curated 15-technique watchlist** chosen to exercise one full attack path
  (initial access → execution → credential access → lateral movement → impact),
  which the shipped rules cover completely.

The report also lists `unknown_technique_ids` — technique IDs your rules claim
that MITRE does not currently publish, which catches typos and techniques that
have since been revoked.

Refresh the matrix after an ATT&CK release. At runtime this is part of the
update cycle, opt-in and off by default:

```bash
# Checks MITRE's release list first and downloads only if a newer version
# exists; writes <db>.attack.json beside the database.
PYTHONPATH=src python -m autosiem.cli update --refresh-attack --db data/autosiem.db
```

Point `AUTOSIEM_ATTACK_INDEX` at that file to use it in place of the vendored
one. To regenerate the copy shipped inside the package instead:

```bash
python3 scripts/build_attack_index.py
```

Both paths run the same distillation, so they produce byte-identical output for
the same ATT&CK release.

Pull runnable detections from the SigmaHQ community ruleset:

```bash
PYTHONPATH=src python -m autosiem.cli sigma-sync --db data/autosiem.db
export AUTOSIEM_SIGMA_DIR=data/autosiem.sigma
```

The sync is deliberately conservative about what it counts as a win. Parsing a
rule is not the same as being able to run it. AutoSIEM normalizes common Windows
fields such as `EventID`, `TargetObject`, `ParentImage`, and `ScriptBlockText`,
preserves Sigma `logsource` product/service scope, and evaluates Boolean
`and`/`or`/`not` plus `1 of`/`all of` conditions exactly. Rules that need other
fields or unsupported modifiers are not imported. Every candidate therefore
lands in one of three counted buckets: imported, needs-fields-we-lack, or
unsupported-syntax. The report names the fields that blocked the rest, so
"why is coverage low" becomes a ranked list of normalizer work.

On SigmaHQ r2026-07-01: **1377 examined, 895 imported, 437 need fields the
event model lacks, 45 unsupported syntax**, taking matrix coverage from
**2.9% to 30.3%** (parents 6.8% to 49.1%). Curated rules win on a rule-id
collision, so synced content never replaces a rule this project authored and
tested.

Sigma rules also work out of the box: drop a `.yaml` Sigma rule into `rules/` (see `rules/encoded_powershell.yaml`) and it is parsed and converted automatically when you run `demo` or `ingest`. To share your rules back with the Sigma ecosystem, export them:

```bash
PYTHONPATH=src python -m autosiem.cli export --rules rules --out-dir /tmp/sigma-rules
```

This writes one `<rule_id>.yaml` per rule; the files re-import cleanly (tags/risk are the only lossy fields — Sigma has no risk concept).

Inspect and decide AI action proposals:

```bash
PYTHONPATH=src python -m autosiem.cli incidents --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli incident --id <incident-id> --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli approve --proposal-id <proposal-id> --actor analyst --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli audit --db data/autosiem.db
```

Manage suppressions/exceptions (suppress or downgrade noisy-but-benign detections at ingest):

```bash
PYTHONPATH=src python -m autosiem.cli suppressions --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli suppression-add --rule-id '*' --name 'alice noise' --action suppress --entity user:alice --reason 'known benign' --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli suppression-delete --id <suppression-id> --db data/autosiem.db
```

Collect continuously — syslog/CEF UDP listener, connector polling, and per-source health:

```bash
# Syslog (RFC 5424/3164) + CEF listener on UDP 5514; forwarders point at it
PYTHONPATH=src python -m autosiem.cli listen --host 0.0.0.0 --port 5514 --db data/autosiem.db

# Poll a JSONL file/directory connector (handles log rotation) — run from cron/systemd
PYTHONPATH=src python -m autosiem.cli poll --path /var/log/autosiem/events.jsonl --db data/autosiem.db

# Vendor connectors: Okta / Entra ID / GitHub / Sysmon / Zeek / Suricata / asset inventory
PYTHONPATH=src python -m autosiem.cli poll --connector okta --path ./okta_system_log.jsonl --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli poll --connector entra --path ./entra_signins.jsonl --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli poll --connector github --path ./github_audit.jsonl --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli poll --connector sysmon --path ./sysmon.jsonl --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli poll --connector zeek --path ./zeek_logs --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli poll --connector suricata --path ./eve.jsonl --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli poll --connector asset --path ./assets.jsonl --db data/autosiem.db

# AWS CloudTrail (S3-synced export or JSONL)
PYTHONPATH=src python -m autosiem.cli poll --connector cloudtrail --path ./cloudtrail --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli connectors   # list registered connectors

# Okta, API-native: polls the System Log API directly, no file export step.
# The token is read from the environment, never passed as an argument, so it
# stays out of shell history and the process list. A free developer org works.
export AUTOSIEM_OKTA_TOKEN='00abc...'
PYTHONPATH=src python -m autosiem.cli poll --connector okta-api \
  --url https://dev-123456.okta.com --db data/autosiem.db
# Pagination, a cursor persisted across restarts, and rate-limit backoff are
# handled for you; re-run it from cron/systemd and it resumes where it stopped.

# Threat intelligence: load a STIX 2.x bundle, list indicators, and matches surface
# as AUTO-INTEL-001 findings on the next ingest/poll
PYTHONPATH=src python -m autosiem.cli load-intel --file examples/intel_sample.json --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli intel --db data/autosiem.db

# Per-source ingest health (also at UI /sources, API GET /api/sources)
PYTHONPATH=src python -m autosiem.cli sources --db data/autosiem.db
```

Incident triage (status transitions, assignment, and comments):

```bash
PYTHONPATH=src python -m autosiem.cli incident-update --id <incident-id> --status investigating --assignee bob --note 'first look' --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli incident-comment --id <incident-id> --body 'follow-up' --db data/autosiem.db
PYTHONPATH=src python -m autosiem.cli incident-comments --id <incident-id> --db data/autosiem.db
```

### API / web UI

Run the optional API/UI:

```bash
pip install -e '.[api]'
PYTHONPATH=src uvicorn autosiem.web.api:app --host 127.0.0.1
```

This binds loopback only. AutoSIEM does not terminate TLS, so anything that
reaches it over a network must go through a TLS reverse proxy, or its bearer
tokens travel in cleartext; see
[Exposing the API beyond localhost](docs/deployment-and-collection.md#exposing-the-api-beyond-localhost).

Then open `http://127.0.0.1:8000/` for the incident queue, `http://127.0.0.1:8000/sources` for per-source ingest health, or `http://127.0.0.1:8000/docs` for API docs.

The API is also the machine-to-machine ingest path:

```bash
curl -X POST http://127.0.0.1:8000/api/ingest \
  -H 'content-type: application/x-ndjson' \
  --data-binary @examples/events.jsonl
```

Optional: set `AUTOSIEM_INGEST_TOKEN` when starting the server and every ingest call must send it as `x-api-key` or a `Bearer` token (TLS is handled by putting a reverse proxy like Caddy/nginx in front).

## Detection coverage

The bundled `rules/` set (29 curated rules mapping to 34 techniques, 4.9% of the ATT&CK 19.2 Enterprise matrix; `cli sigma-sync` adds community rules on top) exercises a full attack kill-chain on the demo `alice` profile — phishing → valid-account auth → brute force → encoded PowerShell → download cradle → system recon → masquerading → credential dumping → lateral movement → web exploit → encrypted C2 tunnel → data exfiltration → log clearing → ransomware → cloud admin takeover — producing a critical (risk 1000) incident that the AI runtime proposes containment for.

Run `PYTHONPATH=src python -m autosiem.cli coverage --rules rules` to see the current technique coverage and the remaining gap list. The rule-by-technique table is in `docs/tutorial.md` (§6).

## Safety model

AutoSIEM does **not** let an LLM silently take high-impact action. The AI analyst runtime is deterministic and auditable: read-only/low-risk tasks can complete automatically, while actions such as disabling users, isolating hosts, and blocking indicators are proposed for approval by default. See `docs/ai-soc-runtime.md`.

## Optional LLM integration

By default everything runs on a deterministic local investigator with no network calls. To let a self-hosted or hosted model author the narrative report and propose a decision, point at any OpenAI-compatible server and pass `--llm`:

```bash
AUTOSIEM_LLM_BACKEND=openai_compat AUTOSIEM_LLM_MODEL=<model-name> AUTOSIEM_LLM_URL=http://localhost:1234/v1 \
  PYTHONPATH=src python -m autosiem.cli demo --llm --no-save
```

Safety stays intact: secrets are redacted before leaving the process, LLM output is schema-validated, and decisions still run through policy so high-impact actions require approval. If the model is unavailable, the pipeline silently falls back to the local investigator. See `docs/ai-soc-runtime.md` for the full backend and env-var reference.

## System One decision layer (optional)

The LLM layer above writes prose. A **System One** model does the opposite: it
answers typed questions about an incident with a value and a probability, in tens
of milliseconds, and nothing else. AutoSIEM can use one as an extra signal on a
correlated incident, asking four questions in a single call:

| Question | Type | Answers |
|---|---|---|
| `malicious` | noul (yes/no + probability) | is this genuinely security-relevant |
| `severity` | choice | informational / low / medium / high / critical |
| `action` | choice | suppress / monitor / enrich / investigate / escalate |
| `needs_llm_analysis` | noul | is it murky enough to deserve a narrative write-up |

**It is advisory, and that is the whole design.** The deterministic rules, UEBA
scoring, risk model and policy gates stay authoritative. A System One answer
never changes a severity, never approves an action, and never shortens an
approval path; a disagreement is recorded on the incident and the engine's
verdict stands. If the provider is slow, wrong, unreachable or absent, AutoSIEM
behaves exactly as it does with the feature switched off. It is off by default.

### Jev versus Laya

| | **Jev** (TypeSafe) | **Laya** (`laya-typed-decisions`) |
|---|---|---|
| Where it runs | hosted API, **remote** | your hardware, **local** |
| Licence | proprietary | Apache 2.0, open weights |
| Needs | `TYPESAFE_API_KEY` | `pip install '.[laya]'` (~421M params) |
| Cost | $0.042 per million input tokens, output free | electricity |
| Data leaves the host | **yes** | no |

Both answer the same question shapes, so AutoSIEM normalizes them into one
internal result and the rest of the system cannot tell which model replied.

### Configuration

```bash
# Off by default. Nothing below is required.
AUTOSIEM_DECISION_PROVIDER=jev        # none (default) | jev | laya
AUTOSIEM_DECISION_FALLBACK=laya       # none (default) | jev | laya

# Jev (hosted). Never commit the key; read it from the environment.
TYPESAFE_API_KEY=sk-...
AUTOSIEM_JEV_MODEL=jev-latest
AUTOSIEM_JEV_TIMEOUT=10
AUTOSIEM_JEV_RETRIES=2

# Laya (local). Lazily loaded, so a Jev-only install never pays for it.
AUTOSIEM_LAYA_MODEL=convaiinnovations/laya-typed-decisions
AUTOSIEM_LAYA_DEVICE=auto             # auto picks CUDA, then Apple MPS, then CPU

# Thresholds, with their defaults.
AUTOSIEM_DECISION_ACCEPT_CONFIDENCE=0.75
AUTOSIEM_DECISION_REVIEW_CONFIDENCE=0.5
AUTOSIEM_DECISION_FALLBACK_ON_LOW_CONFIDENCE=0   # see below
AUTOSIEM_DECISION_GATE_LLM=0                     # see below
```

Confidence is treated as a signal, not as truth. At or above the accept
threshold the classification is recorded as an accepted signal; between the two
thresholds it is marked for review; below the review threshold it is kept but
carries no weight, which is the same as having no answer.

### Fallback

```
Jev answers               -> use it
Jev times out / errors /
  returns something invalid -> try Laya, and mark fallback_used
Laya answers              -> use it
both fail                 -> deterministic AutoSIEM behaviour, unchanged
```

A **low-confidence answer is not a failure**, so it does not trigger fallback.
Shopping for a more confident second opinion is opt-in
(`AUTOSIEM_DECISION_FALLBACK_ON_LOW_CONFIDENCE=1`), because a model that is
honestly unsure is giving you information, not an error.

### How it interacts with the LLM layer

They do different jobs: System One classifies, the LLM explains. By default
enabling System One changes nothing about when the generative model runs. Set
`AUTOSIEM_DECISION_GATE_LLM=1` and a confident `needs_llm_analysis=false` may
skip the narrative call for clear-cut incidents; an ambiguous or low-confidence
assessment always lets it run.

### Privacy

Jev is remote, so the state is built by whitelist, not by filter:

- Summarised signals, not log dumps: counts, named UEBA signals, rule ids,
  entity kinds, the deterministic severity and risk score.
- Only named raw fields (`process_name`, `command_line`, `url`, ...) are copied
  from an event; everything else stays local.
- Every string passes through the existing redactor, so bearer tokens, API keys
  and private keys are masked even inside a whitelisted command line.
- IP addresses are sent as their class only (`<IP:internal>` or `<IP:public>`),
  never the address, because internal-versus-external is what triage needs.
- Field names that look like credentials are never copied at all.
- Caps on how many findings and events are included.

Run Laya instead if nothing may leave the host at all.

### Using it

```bash
# Annotate incidents during any ingest path
AUTOSIEM_DECISION_PROVIDER=jev TYPESAFE_API_KEY=... \
  PYTHONPATH=src python3 -m autosiem.cli demo --db data/autosiem.db

# Configuration and what has been recorded so far
PYTHONPATH=src python3 -m autosiem.cli decisions --db data/autosiem.db
```

The assessment appears in the CLI run output, on `cli incident --id <id>`, and
in the JSON API's incident bundle under `system_one`:

```
=== System One Assessment (advisory) ===
Provider: jev (jev-1.13.0)
Malicious: 0.94
Severity: high (0.87)
Action: investigate (0.91)
Needs LLM Analysis: 0.18
Latency: 84 ms
Weight: accepted
- disagrees with the deterministic severity: model 'high' vs engine 'critical' (engine wins)
```

### Benchmarks

Compare the deterministic path against each model on identical labelled
incidents. It runs with whatever is available, so it works with no API key and
no local model, and says which paths it skipped and why:

```bash
PYTHONPATH=src python3 -m autosiem.cli evaluate-decisions \
  --cases my_labelled_incidents.json --json-out results.json
```

Reported per path and per question: accuracy, a confusion matrix, Brier score
for the probabilistic yes/no call, expected calibration error with its bin
count, latency mean/p50/p95, error and fallback rates, and token cost for
providers that report usage (a local model reports none, so no cost is invented
for it). A case is `{"id": ..., "state": {...}, "labels": {...}}`; build `state`
with `autosiem.system_one.build_state`. There is no bundled labelled dataset
yet, so bring your own.

## Documentation

- `docs/tutorial.md` — start here (20-minute beginner walkthrough)
- `docs/architecture.md` — module map and how the pieces fit together
- `docs/roadmap.md` — current status and the phased plan
- `docs/deployment-and-collection.md` — how real deployments get data in
- `docs/ai-soc-runtime.md` — the AI analyst runtime, LLM config, and safety model
- `docs/system-one.md` — the typed decision layer: providers, thresholds, evaluation
- `docs/siem-research-2026.md` — the 2026 SIEM landscape research baseline
- `docs/product-vision-ai-soc.md` — the end-state product vision

Project files: [`CONTRIBUTING.md`](CONTRIBUTING.md) (setup + PR gates),
[`SECURITY.md`](SECURITY.md) (policy + implemented controls),
[`.env.example`](.env.example) (every environment variable), and
[`CLAUDE.md`](CLAUDE.md) (the working state doc for AI coding sessions).

## Development

- Keep the suite green after every change: `PYTHONPATH=src python3 -m pytest tests/ -q`.
- **Zero runtime dependencies.** The core (`src/autosiem/*`) imports nothing beyond the standard library — the Sigma YAML parser is a deliberate subset, do not add PyYAML. Extra deps live only in optional extras (`api`, `dev`, `postgres`, `laya` in `pyproject.toml`).
- `rules/*.json` may start with `//` or `#` comment lines (the loader strips them). Editor JSON "linter errors" on those files are expected — don't quote the comments.
- **New rules must ship tested**: add positive + negative cases to `tests/test_rules.py` or the suite fails.
- Editor diagnostics are clean (0 errors / 0 warnings); `pyrightconfig.json` sets a pragmatic `basic` type-checking mode.
- CI (`.github/workflows/ci.yml`) runs the suite, a coverage smoke check, and pyright on Python 3.10/3.12.
- Don't touch `data/autosiem.db` — it's dev data (tests use temp DBs).

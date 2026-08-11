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
- **ATT&CK coverage reporting** — see which watchlist techniques your rules cover and which are gaps (`cli coverage`).
- **Entity behavioral analytics (UEBA)** — per-entity baselines scoring seven named signals: novel action, novel source IP, novel host, off-hours activity, population-wide rarity, peer-group rarity ("no other user has ever run this"), and event bursts. Baselines persist per tenant, so a restart does not relearn from zero, and every anomaly finding carries a breakdown of exactly which signals fired and why (`autosiem.anomaly`).
- **Incident correlation** — findings are joined into one incident when they share an entity within a 24h window, transitively across entity types, so a single case spans user ↔ host ↔ IP ↔ cloud account and reads as an attack story with a time-ordered ATT&CK kill chain (`autosiem.risk`).
- **Entity enrichment** — asset criticality, identity context (department, privileged, disabled), network/CIDR classification, and threat-intel hits, all from local files or indicators you already load. No API keys, no third-party calls. Asset and identity criticality scale finding risk, so the same detection on a crown-jewel host outranks it on a spare laptop (`autosiem.enrichment`).
- **Risk scoring & triage** — entity risk aggregation and a full triage workflow (status, assignee, resolution, comment thread).
- **AI SOC analyst runtime** — a deterministic local investigator (or your own LLM) that investigates and proposes actions; high-impact actions always require human approval. Its related-event task really queries the event store, answering "what else has this user/host/IP done?" and attaching the prior activity as evidence.
- **Suppressions & exceptions** — analyst-defined exceptions and auto-repeat suppression for noisy detections, applied at ingest and fully audited.
- **Ingest surface** — JSONL CLI + HTTP endpoint, syslog (RFC 5424/3164) + CEF UDP listeners, a connector SDK (file, CloudTrail, Okta file **and API-native**, Entra ID, GitHub, Sysmon, Zeek, Suricata, asset inventory), and STIX/TAXII threat-intel matching.
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

The report measures against a curated 15-technique watchlist chosen to exercise
one full attack path, and it names that baseline in its own output. It is not a
measure of coverage across ATT&CK Enterprise, which is a much larger matrix.

Sigma rules work out of the box: drop a `.yaml` Sigma rule into `rules/` (see `rules/encoded_powershell.yaml`) and it is parsed and converted automatically when you run `demo` or `ingest`. To share your rules back with the Sigma ecosystem, export them:

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
PYTHONPATH=src uvicorn autosiem.web.api:app --reload
```

Then open `http://127.0.0.1:8000/` for the incident queue, `http://127.0.0.1:8000/sources` for per-source ingest health, or `http://127.0.0.1:8000/docs` for API docs.

The API is also the machine-to-machine ingest path:

```bash
curl -X POST http://127.0.0.1:8000/api/ingest \
  -H 'content-type: application/x-ndjson' \
  --data-binary @examples/events.jsonl
```

Optional: set `AUTOSIEM_INGEST_TOKEN` when starting the server and every ingest call must send it as `x-api-key` or a `Bearer` token (TLS is handled by putting a reverse proxy like Caddy/nginx in front).

## Detection coverage

The bundled `rules/` set (16 rules mapping to 20 techniques) exercises a full attack kill-chain on the demo `alice` profile — phishing → valid-account auth → brute force → encoded PowerShell → download cradle → system recon → masquerading → credential dumping → lateral movement → web exploit → encrypted C2 tunnel → data exfiltration → log clearing → ransomware → cloud admin takeover — producing a critical (risk 1000) incident that the AI runtime proposes containment for.

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

## Documentation

- `docs/tutorial.md` — start here (20-minute beginner walkthrough)
- `docs/architecture.md` — module map and how the pieces fit together
- `docs/roadmap.md` — current status and the phased plan
- `docs/deployment-and-collection.md` — how real deployments get data in
- `docs/ai-soc-runtime.md` — the AI analyst runtime, LLM config, and safety model
- `docs/siem-research-2026.md` — the 2026 SIEM landscape research baseline
- `docs/product-vision-ai-soc.md` — the end-state product vision

Project files: [`CONTRIBUTING.md`](CONTRIBUTING.md) (setup + PR gates),
[`SECURITY.md`](SECURITY.md) (policy + implemented controls),
[`.env.example`](.env.example) (every environment variable), and
[`CLAUDE.md`](CLAUDE.md) (the working state doc for AI coding sessions).

## Development

- Keep the suite green after every change: `PYTHONPATH=src python3 -m pytest tests/ -q`.
- **Zero runtime dependencies.** The core (`src/autosiem/*`) imports nothing beyond the standard library — the Sigma YAML parser is a deliberate subset, do not add PyYAML. Extra deps live only in optional extras (`api`, `dev` in `pyproject.toml`).
- `rules/*.json` may start with `//` or `#` comment lines (the loader strips them). Editor JSON "linter errors" on those files are expected — don't quote the comments.
- **New rules must ship tested**: add positive + negative cases to `tests/test_rules.py` or the suite fails.
- Editor diagnostics are clean (0 errors / 0 warnings); `pyrightconfig.json` sets a pragmatic `basic` type-checking mode.
- CI (`.github/workflows/ci.yml`) runs the suite, a coverage smoke check, and pyright on Python 3.10/3.12.
- Don't touch `data/autosiem.db` — it's dev data (tests use temp DBs).

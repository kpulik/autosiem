# Engineering history

What was built, what broke, and how it was measured, moved out of the agent
working doc so that doc stays short. Newest work is at the end of each section.
Numbers are as measured on the date given; re-measure before quoting them.

## Merged pull requests

Merged with CI green (rebase-merged; #15 squashed): #1 PostgreSQL control plane + outbox, #2 GitHub connector + SCM rules, #5 Entra connector, #6 per-source cursors + HTTP timeouts, #7 tenant/audit isolation + fail-closed detection (SEC-019/020/021), #8 CloudTrail over S3 with hand-rolled SigV4, #9 `/search`, #10 nine rules, #11 console type system, #12 OKLCH palette, #13 salted PBKDF2 tokens (SEC-006/008), #14 audit sealing (SEC-005), #15 ingest-token scope + audit actor + TLS docs (SEC-007/009/012), #16 System One decision layer, #17 AUTO-EXFIL-001 size regex, #18 AUTO-CRED-004 shadow-copy split, #19 identity roles, #20 labelled eval set + first System One benchmark, #21 doc audit (README, .env.example, architecture, roadmap, CONTRIBUTING, security-review status table), #22 `/health` status only (SEC-015), #23 RAG context redaction (SEC-010), #24 JSON depth cap + owner-only files (SEC-016), #25 redactor JSON-form/JWT/AWS secret (SEC-011), #26 events stored as ingested, documented (SEC-014), #27 redirect policy (SEC-017), #28 event-backend timeout + one-line CLI failure, #29 listener fixes (queue thread affinity, serialized pipeline, reported failures, SIGTERM), #30 listener batching (one incident per batch instead of per datagram), #31 incident merge across batches, #32 UI redesign, #33 listener queue drain, #34 journal append, #35 replay drain, #36 queue compaction. Copilot PRs #3 and #4 were closed unmerged.

## Gaps closed by the 2026-08 code review

Independent code-level review (not doc-level) puts AutoSIEM at a credible SIEM
MVP with a real end-to-end pipeline, but with specific depth gaps. Honest
positioning: *"an AI-native SIEM and SOC analyst platform with behavioral
analytics, MITRE ATT&CK detection, automated investigation, and policy-gated
response"* — not an Exabeam competitor.

**Closed on 2026-08-08:**

- ~~UEBA is shallow~~ — `anomaly.py` was rewritten as a real behavioral engine: seven named signals (`novel_action`, `novel_src_ip`, `novel_host`, `off_hours`, `rare_action`, `peer_rare`, `burst`), warm-up gating on the **statistical** signals only (off-hours, rarity, burst) - the three novelty signals deliberately need just one prior observation, so a new entity's second distinct action counts as novel (measured 2026-09-27: gating novelty would drop 1 false alarm and 3-4 real detections on the eval set, so it stays), population-wide and peer-group rarity scoring, and a `BaselineState` persisted per tenant in SQLite so baselines survive restarts. Every finding now carries a per-signal breakdown explaining *why* it fired. 29 tests in `tests/test_anomaly.py`.
- ~~Incident correlation is naive~~ — `build_incidents` now runs `correlate_findings`: a union-find entity graph where findings link when they share an entity **and** fall within `CORRELATION_WINDOW_SECONDS` (24h). Correlation is transitive, so one incident spans user ↔ host ↔ IP ↔ cloud account; the time window prevents everything collapsing into one endless case. Incidents carry a time-ordered kill chain and a summary naming the tactic progression. 21 tests in `tests/test_risk.py`.
- ~~`search_related_events` is simulated~~ — the runtime takes an optional `EventSearcher` (satisfied by `AutoSIEMStorage`) and now really queries stored telemetry per incident entity, excludes events already in the case, dedupes across entities, and attaches the hits as `related_events` evidence. Wired through `AutoSIEMPipeline(event_search=…, tenant_id=…)` from the CLI (`ingest`/`demo`/`poll`/`listen`) and the API (tenant-scoped). Without a store it degrades to a clear "no event store configured" message. 12 tests in `tests/test_related_events.py`.

**Also closed 2026-08-08:**

- ~~The other three analyst tasks are simulated~~ — `enrich_entities` profiles each entity from local telemetry (event count, first/last seen, distinct actions) and flags first observations; `link_duplicate_alerts` groups findings by rule and entity and reports the collapsed clusters; `create_case_note` drafts a structured triage note that `save_pipeline_result` writes to the incident comment thread as a real comment by `ai-analyst`. 13 tests in `tests/test_analyst_tasks.py`.
- ~~UEBA baseline is not persisted~~ — per-tenant `baselines` table plus `AutoSIEMPipeline(baseline_store=…)`. `demo` deliberately opts out: its fixed timestamps would trip `burst` on every re-run. 13 tests in `tests/test_baseline_persistence.py`.
- ~~Peer-group analytics~~ — the `peer_rare` signal compares an entity against other entities of the same kind.
- ~~Distributed path is dual-write~~ — `DistributedPipeline.run()` wraps one pipeline pass and returns the real `PipelineResult`. Also fixed: an empty `DurableQueue` was falsy (`__len__`, no `__bool__`) so nothing was ever enqueued, and the ack/replay logic acked archive markers instead of ingest messages. 13 tests in `tests/test_distributed_wiring.py`.
- ~~RAG is runbook-only~~ — `default_rag_engine(store, tenant_id)` indexes recent incidents with their status and resolution alongside the runbooks. 13 tests in `tests/test_rag_incidents.py`.
- ~~UI pages bypass auth~~ (SEC-005) — see the auth section below. 23 tests in `tests/test_ui_auth.py`.
- ~~Connectors are all file/poll-based~~ — `OktaApiConnector` (`okta-api`) polls the Okta System Log API directly: `rel="next"` pagination, a cursor persisted across restarts, bounded retry with `X-Rate-Limit-Reset` backoff, and a token read from the environment rather than argv. Reuses the already-tested `okta_to_raw` mapper. 30 tests in `tests/test_okta_api_connector.py`.
- ~~No external enrichment sources~~ — new `enrichment.py`: `AssetEnricher`, `IdentityEnricher`, `NetworkEnricher` and `ThreatIntelEnricher` behind an `EnrichmentRegistry`. All sources are local files or already-loaded STIX indicators, so enrichment needs no API key and never leaks entity names. Asset/identity **criticality scales finding risk** (critical x2.0 … low x0.75, capped) before incidents are built, so the same detection on a crown-jewel host outranks it on a spare laptop. 59 tests in `tests/test_enrichment.py`.

**Remaining gaps:**

1. ~~Connectors are file-based~~ — **all four sources are API-native**: `okta-api`, `github-api`, `entra-api`, `cloudtrail-api`. Each persists a cursor, backs off on throttling, takes its credential from the environment, and routes through `net.require_https`. Three auth models now: a long-lived token (Okta, GitHub), OAuth client-credentials with refresh (Entra), and request signing (CloudTrail, `sigv4.py`). The file-based connectors stay for offline and export workflows.
2. **No HA story.** Single SQLite writer; alternate backends store events only, so findings, incidents, investigations and the audit chain remain single-node.
3. **The worker pool is bypassed on the CLI path.** `AUTOSIEM_WORKERS` only applies to library use of `DistributedPipeline` without an injected pipeline, because chunked parallel runs would each get their own behavioral baseline.
4. **Re-ingesting an identical file doubles event density** and can trip `burst`. Deriving event ids from content hashes would make re-ingest idempotent but would also collapse genuinely repeated events, which brute-force detection depends on — deliberately not done.

## Defects a green suite missed

A green suite is **not** sufficient evidence on this project. On 2026-08-08 four
real defects survived a passing suite and were caught only by running the CLI
and reading the output:

- a per-entity count string reported `user:alice 0` when alice drove everything
- `DurableQueue` was falsy when empty, so nothing was ever enqueued
- the distributed path processed every event twice
- the demo pipeline silently missed its enrichment wiring

On 2026-09-14 the same thing happened to the PostgreSQL work, which passed 773
tests and pyright before any of these were found:

- `migrate` and `outbox` printed a raw Python traceback when
  `AUTOSIEM_POSTGRES_DSN` or the `postgres` extra was missing. Every test called
  the library, never the CLI.
- `outbox --deliver` printed two JSON documents, so its output did not parse.
- on a **SQL_ASCII** database psycopg returns text columns as `bytes`, so
  checksums never matched and every migration after the first failed with
  "migration history mismatch; do not edit applied migrations" - a false tamper
  alarm. The offline `_validate_history` test passed because it built its rows
  from `str`. `_connection` now pins `client_encoding=utf8`.

Run the PostgreSQL tests against a cluster you created with `--encoding=UTF8`
**and** one with `--encoding=SQL_ASCII`; `initdb` picks SQL_ASCII under a C
locale, so operators hit it.

So after any pipeline change:

```bash
D=/tmp/verify.db && rm -f $D
PYTHONPATH=src python3 -m autosiem.cli demo --db $D          # run it twice:
PYTHONPATH=src python3 -m autosiem.cli demo --db $D          # second run exercises warm state
PYTHONPATH=src python3 -m autosiem.cli incident --id <id> --db $D   # read the task results
PYTHONPATH=src python3 -m autosiem.cli audit-verify --db $D
```

Read the `tasks[].result` strings and the evidence kinds in the investigation.
Then write the regression test for what you actually saw.

## Security review, listener and queue work (2026-09 to 2026-11)

Done since this section was last written: all four connectors are API-native,
the KEV vulnerability enricher exists, `/search` shipped, and the security review's
High findings are all closed. What is actually left (see the status table at the
top of `docs/security-review.md`):

Closed on 2026-09-27/28: SEC-015 (#22), SEC-010 (#23), SEC-016 (#24), SEC-011
(#25), SEC-014 (#26, by design), SEC-017 redirects (#27). **Every finding in
`docs/security-review.md` is now fixed or closed by design**; residuals are
written down there (prompt injection contained by the policy gate; an unlabelled
secret in prose; feed signing, which no upstream publishes; redirects to internal
HTTPS hosts). Each of these was bigger than its write-up: RAG was a live leak,
one deep line killed a whole ingest, JSON-form secrets were never masked, and
urllib forwarded the Okta token across redirects. **Check a finding's premise
against current code before sizing it.**

1. ~~**`backends.py`**~~ - merged as #28: 30s timeout, every failure is one
   `BackendError`, one CLI line on ingest / `distributed --replay` / listener
   startup replay, built from the run's real state (`--no-save`, queue or not).
2. **Listener (PR #29)** - `cli listen` with `AUTOSIEM_QUEUE_PATH` stored **0 of
   200** events, silently: the `DurableQueue` connection was used across threads
   and `SyslogServer` was `except: pass`. Fixed: locked queue connection, locked
   `JournalFile.append`, the listener's pipeline runs one line at a time
   (`process_lock` in `_run_listener`; the shared baseline/SOAR state lost ~1 in
   300 concurrently), failures reported per stage and rate-limited per (stage,
   error type) so a parse flood cannot hide a storage failure
   (`SyslogServer.failures` / `failures_by_stage`, total printed on exit, also on
   SIGTERM), exception text control-escaped, `stop()` drains workers,
   `compact()` acked rows only. Measured: 500/500 with a queue, 3000/3000
   distinct users, 3000 malformed datagrams -> 2 stderr lines. Full suite also
   run against a local PostgreSQL 14 cluster (1300 passed): CI's postgres job
   had caught a `FakeServer` without `failures` that SQLite runs skip.
   Reviews: two adversarial workflows plus Codex (3 threads, all fixed and
   resolved). Known cost: `listen --llm` is ~1 event per model response.
   **Batching (merged, #30)**: `listen` made one `process_lines` call per
   datagram, and incidents are built per call, so nothing correlated (593
   incidents for 600 failed logins). `BatchingHandler` flushes at `--batch-size`
   (200) or `--batch-wait` (1.0 s, max 3600); one thread runs the pipeline.
   Measured: 600 failed logins -> 3 incidents; `--batch-size 1` restores
   per-event. A batch is cut to the queue's free room (`queue_room()`), so a small
   `AUTOSIEM_QUEUE_MAX_PENDING` means small chunks (limit 30 -> 21 incidents).
   Incidents now also merge across batches, see below.
   **Next, in order** (found by the 2026-10-15 review, all measured):
   a. ~~Merge a batch's incidents into stored ones~~ - PR #31 `feat/incident-merge`
      (2026-11-02, check `gh pr view 31 --json state`). Merge runs **before** the investigation, in
      `AutoSIEMPipeline._correlate` -> `risk.merge_into_stored`, because the
      containment decision needs risk >= 200 and batch-only risk would never get
      there on a slow attack. `save_pipeline_result` then recomputes from stored
      findings under the row lock (`_merge_incident`), so two writers cannot lose
      findings, and never uses `_insert` for it (SQLite's `insert or replace`
      would wipe triage). Opt-in via `incident_store=`: CLI ingest/poll/listen,
      distributed replay and API ingest pass it; `demo`, `--no-save` and
      `/api/rules/test` do not. Measured: 16 batches of 200 stay under 0.35 s per
      batch; 300 sshd failures over UDP -> 1 incident, one of each proposal.
      Same PR: the listener no longer writes the **sender's address into
      `src_ip`** (now `raw.sender_ip`). It tied everything behind one relay
      together and proposed blocking the relay.
   b. ~~Queue-full wedge~~ - branch `fix/listener-queue-drain` (2026-11-04).
      With a queue, `cli listen` now commits each burst (<=256 lines) to the
      queue in the **receive thread** (`SyslogServer(batch_handler=...)`,
      `_serve_bursts`, `DistributedPipeline.admit`) and one `QueueDrainer`
      thread runs `drain_queue`, which retries with 1-30 s backoff **with no new
      traffic**. Without a queue the old `BatchingHandler` path is unchanged.
      `drain_queue` holds a processed-but-unsaved batch (only the save is
      retried), retries only the ack if the ack fails after a save
      (`_unacked`; backend copy and report happen **before** the ack), bisects a
      batch on any non-transient error (`_is_transient`: OSError, MemoryError,
      anything named OperationalError/InterfaceError) and **dead-letters**
      (`acked = 2`) the failing lines **only if other lines of the batch saved**
      (`_settle_batch`); if none saved the store is at fault and the batch is
      retried, nothing set aside. Snapshots/restores the **two learned states**,
      UEBA baseline and `SuppressionEngine._seen`, so a retried or bisected
      batch is learned once. The event backend is a held, bounded in-memory
      backlog retried every 60 s; it no longer stops the listener (it still
      stops `ingest` and `distributed --replay`). A full queue refuses at once
      (stage `queue`): **never block the receive thread**, the kernel then drops
      datagrams uncounted. Default `AUTOSIEM_QUEUE_MAX_PENDING` raised
      10,000 -> 100,000 (it now bounds the whole backlog). `cli distributed
      --requeue-dead-letters`. A 3-lens Sonnet review found the suppression,
      ack-order, whole-queue-dead-letter and blocking-wait defects; all fixed
      with mutation-checked tests.
      Measured with the real CLI: `kill -9` with 1000 lines read and none
      processed -> restart -> 1000 stored; store made read-only 15 s -> 4
      retries -> drained 2 s after recovery, 1300/1300, no duplicates; 20,000
      datagrams in 10 s -> peak backlog 16,581 -> 20,000 stored, none refused.
      **Processing ran ~100 lines/s** on that mostly-unique-user load, so a
      sustained rate above that fills the bound (refused, counted). **An
      SQLite lock does not exercise this path**: every pipeline read waits its
      5 s busy timeout and degrades ("Incident merge skipped"), so the drainer
      is slow, not failing; use `chmod 400` on the store to test it.
      Tests: `test_queue_drain.py`, listener tests in `test_cli.py`.
   c. ~~Throughput~~: partial index `messages_pending` (#33; at 1M acked rows
      `push` 61 -> 4,396 lines/s) and **`JournalFile` rewrite** (branch
      `fix/journal-append`, 2026-11-04): exclusive `fcntl.flock` spans
      count-and-write (sequence unique across processes; tested with 4 real
      processes), only bytes written since the last look are scanned, a torn
      last line is ended with `\n` and kept (never truncated: evidence) and
      readers skip and count unparseable lines; `append_many` / `write_many`
      write a burst at once and `_archive_lines` uses it. At 100k lines: single
      `append` 7 -> 331/s, bursts 666k lines/s. **Measured regression this
      closes:** #33 moved archiving into the receive thread, and on `main`
      with a 100k-line journal the listener queued **257 of 5,000** datagrams,
      the rest dropped by the kernel with no warning; now 5,000/5,000.
   d. ~~Replay cap and duplicates~~ - #35 (2026-11-05):
      `replay_from_queue` is now `drain_queue` plus totals (`replayed`,
      `set_aside`, `backend_undelivered`), so `distributed --replay` has no
      1000-line cap and a backend failure no longer leaves saved lines pending
      (the old rerun saved them twice). Exit 1 with one line naming the backend
      error and the undelivered count; a stopped replay exits with one line
      that says whether a rerun saves anything twice (`unacknowledged`).
      Measured: 2,500 queued lines with a silent backend -> one 30 s timeout,
      2,500 saved, exit 1; rerun replays 0; 2,500 events in the store.
      Still open: an undelivered backend copy cannot be resent (the SQLite path
      has no outbox).
   e. ~~Nothing compacts the queue~~ - branch `feat/queue-compaction`
      (2026-11-05): `DurableQueue.ack_many` counts acks (seeded from the file at
      open) and at `COMPACT_AFTER_ACKS` (10,000) runs `compact_acked()`: deletes
      acked rows except the newest (`checkpoint()` unchanged), `COMPACT_CHUNK`
      5,000 per statement with the lock released between chunks, never pending
      or dead letters; a failure is a warning, never a failed ack.
      `cli distributed --compact` also VACUUMs (stop the listener first; a busy
      queue fails in one line). `--compact`/`--replay`/`--requeue-dead-letters`
      without `AUTOSIEM_QUEUE_PATH` now exit with one line instead of 0.
      Measured: 1M acked rows cleared in 0.7 s, concurrent push max 25-165 ms
      (chunk 1,000 was worse: up to 177 ms); VACUUM 187 MB -> <1 MB; real
      listener 12,000 datagrams -> 2,001 queue rows, 12,000 events. Review
      (3 lenses): no durability/concurrency defects; the two CLI gaps fixed.
      **Codex then found a real one**: SQLite can refuse a `commit()` and keep
      the transaction open, so a swallowed compaction failure kept the queue's
      write lock, and a failed push was committed by the next one. Every
      `DurableQueue` write now goes through `_write()` (rollback on failure).
3. **Structural** - no HA (PostgreSQL implemented, not deployed); worker pool
   bypassed on the CLI path; the `schedule()` update daemon is never started
   (running `cli update --refresh-attack --refresh-kev` from cron/systemd is the
   simpler answer; document it rather than start a thread).
4. **This file is ~420 lines**; Claude Code recommends <200. Trim history into
   `docs/` once the state settles.

A `Content-Length: abc` 500 exists only in Starlette's TestClient: uvicorn
(httptools and h11) answers 400 before the app runs. Not a bug; don't fix it.

## Test map (which file proves what)

1423 passed / 20 skipped without PostgreSQL (1443 on PostgreSQL 14, UTF8 and SQL_ASCII, 2026-11-05). Scratch clusters on macOS need a short `-k` socket dir (`mktemp -d /tmp/pgs.XXXX`): the 103-byte socket path limit makes a scratchpad path fail as 'connection refused'. 2 System One provider-integration tests are deselected by default (marker `system_one_integration`). When you change a module, run its file
first, then the whole suite. **A users-file fixture is a PostgreSQL-only tripwire**: `test_postgres.py`
builds its own RBAC users file, so an auth change that the SQLite profile cannot see will only fail in
CI's `postgres` job. Run the suite with `AUTOSIEM_TEST_POSTGRES_DSN` before pushing an auth change.
**Adding a rule to `rules/` breaks five hardcoded counts** in `test_cli.py` (x2), `test_sigma_export.py` and `test_web_api.py` (x2). Update them; that is the design, not a bug.

| Area | Test file |
|---|---|
| UEBA signals, warm-up, peer groups, serialization | `test_anomaly.py` (29) |
| Baseline persistence + pipeline resume | `test_baseline_persistence.py` (13) |
| Correlation, kill chain, entity risk | `test_risk.py` (21) |
| Enrichment + criticality→risk + pipeline integration | `test_enrichment.py` (59) |
| Related-event pivot | `test_related_events.py` (12) |
| enrich/link/case-note analyst tasks | `test_analyst_tasks.py` (13) |
| RAG over runbooks + past incidents | `test_rag_incidents.py` (13) |
| UI auth, cookie auth, CSRF (SEC-005), typography guards | `test_ui_auth.py` (29) |
| OKLCH palette: tokens, fallbacks, even ramp, WCAG AA contrast | `test_ui_palette.py` (19) |
| Page structure: demo button reaches a real route, nav + `aria-current`, timeline (date once per day), timestamp zones, severity-class sanitising, generic table | `test_ui_pages.py` (16, PR #32) |
| Distributed single-pass, queue, replay | `test_distributed_wiring.py` (13) |
| Okta API pagination, cursor, backoff | `test_okta_api_connector.py` (30) |
| GitHub audit-log API: pagination, replay suppression, 403-vs-throttle | `test_github_api_connector.py` (38) |
| SCM destruction/branch-protection/access-removal rules | `test_rules.py` (`AUTO-IMPACT-002/003`, `AUTO-DEFEV-003`) |
| Ransomware/discovery/persistence rules, 9 techniques | `test_rules.py` (`AUTO-IMPACT-004`, `AUTO-COLLECT-001`, `AUTO-C2-002`, `AUTO-DISCO-002/003`, `AUTO-PERSIST-001/002`, `AUTO-DEFEV-004`, `AUTO-CRED-003`) |
| Entra Graph: OAuth token cache/refresh/401-retry, @odata.nextLink | `test_entra_api_connector.py` (39) |
| SigV4 signing vs AWS's botocore reference vectors | `test_sigv4.py` (20) |
| `/search` page: translation panel, targets, escaping, nav | `test_search_nl_page.py` (16) |
| CloudTrail over S3: ListObjectsV2, gzip, key resume, throttling | `test_cloudtrail_api_connector.py` (28) |
| Per-source cursor isolation; HTTP timeout on every connector call | `test_cli.py`, `test_connectors.py` |
| Tenant row/audit isolation, legacy migration, fail-closed operators | `test_tenant_isolation.py` (13) |
| Action/target semantics + policy gating under LLM decisions | `test_action_targets.py` (30) |
| Vendored ATT&CK matrix: lookup, parent fallback, fail-loud, drift guard | `test_attack_matrix.py` (13) |
| ATT&CK refresh: release pick, skip-when-current, HTTPS-only, job wiring | `test_attack_refresh.py` (14) |
| Autonomy gate: whose confidence can authorize containment | `test_autonomy_gate.py` (22) |
| SigmaHQ sync: applicability buckets, merge precedence, offline | `test_sigma_sync.py` (21) |
| KEV catalogue + vulnerability enricher | `test_kev.py` (25) |
| Transport policy: HTTPS on every remote feed | `test_net_policy.py` (20) |
| Detection rules (every rule needs +/- cases) | `test_rules.py` |
| Storage, tenancy, audit chain | `test_storage.py` |
| PostgreSQL migrations, tenancy, concurrency, outbox, CLI errors | `test_postgres.py` (22, 17 need a local server) |
| Outbox projection sinks (OpenSearch/ClickHouse contracts) | `test_projections.py` |
| API endpoints + RBAC | `test_web_api.py` |
| Ingest-token scope, audit-actor forgery, non-ASCII token 500 | `test_auth_surfaces.py` (SEC-007/009, 12) |
| JSON depth cap: exact limit, API 400, CLI keeps good lines around a deep one | `test_json_depth.py` (SEC-016, 11) |
| Owner-only file modes under umask 022; operator mode kept on existing DB | `test_file_permissions.py` (SEC-016, 8) |
| RAG context redacted before the LLM, via the real store path | `test_llm.py` (SEC-010, 2 of them) |
| Redactor: JSON-form labels, prefixed labels, JWT, AWS secret, SSWS/Basic, GitHub prefixes; hashes kept | `test_redaction.py` (SEC-011, 34) |
| Redirects: HTTPS-only hops, cross-origin credential drop, real sockets, no direct urlopen | `test_redirect_policy.py` (SEC-017, 11) |
| Event backends: request shape, `BackendError` mapping, silent-cluster timeout; CLI one-line failure on ingest / replay / listen | `test_backends.py`, `test_cli.py` (`silent_server` fixture in `conftest.py`) |
| Listener batching: size/time flush, close flushes, serial single thread, failure counts per line, `--batch-size 1` synchronous; 40 failed logins -> 1 incident | `test_batching.py`, `test_cli.py` |
| Merging into stored incidents: window, per-entity link, redelivery, cap, materiality, triage kept, closed stays closed (also mid-save), two writers, tenants, store failure, CLI, PostgreSQL | `test_incident_merge.py` (39) |
| Journal: incremental append, torn last line, several objects/processes (4 real processes), rotation | `test_archive.py` |
| Queue compaction: threshold, count at open, chunking, failure never fails an ack, VACUUM, CLI flags | `test_queue_compaction.py` (14) |
| Listener queue drain: receive-thread queueing, in-process retry (the wedge), held save, ack-only retry, dead letters via bisection, baseline learned once, backend backlog, wait-for-room, SIGKILL durability | `test_queue_drain.py` (31), `test_cli.py` |
| Listener threads: queue used cross-thread, atomic capacity, unique journal seq, failures logged (per stage, rate-limited) not swallowed, pipeline never concurrent, exit total, compact keeps pending | `test_bus.py`, `test_archive.py`, `test_listeners.py`, `test_distributed_wiring.py`, `test_cli.py` (`_FakeSyslogServer`) |
| Salted PBKDF2 tokens, constant-time compare, plaintext refusal | `test_rbac.py` (SEC-006/008) |
| System One primitives, Jev/Laya parsing, malformed answers, fallback, thresholds | `test_system_one.py` (54) |
| System One in the pipeline: policy-gate preservation, privacy, persistence | `test_system_one_pipeline.py` (19) |
| Evaluation harness maths (Brier/ECE/confusion) + the CLI around it | `test_system_one_eval.py` (22) |
| Real Jev/Laya calls | `test_system_one_integration.py` - marker `system_one_integration`, excluded by default |
| Identity roles: turn-down, guards (critical/never-routine/disabled/typo), off-list still escalates, profile drift | `test_identity_roles.py` (13) |
| The labelled eval set stays buildable (every scenario raises an incident, labels valid, not copied from the engine) | `test_system_one_cases.py` (5) |
| Audit sealing: rechained-rewrite attack, downgrade, legacy history, wrong key, CLI output | `test_audit_seal.py` (10) + one owner-disables-trigger test in `test_postgres.py` |

## Detailed rule notes (snapshot, 2026-11-05)

The full form of the rules the agent doc now states briefly.

### Data model & conventions (important)

- **Severity enum**: `INFORMATIONAL=0, LOW=25, MEDIUM=50, HIGH=75, CRITICAL=100`.
- `DetectionRule(rule_id, name, description, severity, risk_points, selection, mitre_attack, tags, enabled)`.
- Rules load at `demo`/`ingest` time. JSON files may start with `//`/`#` comment lines (the loader strips them); editor JSON linter errors on those are expected — **don't quote the comments**.
- **Selection operators** (`_match_operator` in `detection.py`): plain equality, list membership, `contains`, `contains_any`, `contains_all`, startswith/endswith any/all variants, regex, membership, exact negative string variants, and `exists`. Recursive `any_of`, `all_of`, and `not` nodes preserve Boolean conditions. Numeric `gt/gte/lt/lte` is not implemented.
- `raw` is present in `event.to_dict()`, so `raw.process_name` / `raw.command_line` are reachable.
- **Sigma mapping** (`sigma.py`): common Windows fields map to the normalized schema; list-form blocks, parentheses, `not`/`and`/`or`, and `1 of`/`all of` wildcard conditions compile to an exact Boolean selection tree. Product/service logsource scope is retained. Unsupported modifiers such as `cidr`, `windash`, `base64offset`, and `fieldref` fail closed instead of being ignored.
- `build_incidents` correlates findings into an **entity graph bounded by a 24h window** (`correlate_findings` in `risk.py`), sorted by **risk_score descending**. Findings sharing any entity within the window merge transitively, so one incident can span user/host/IP/cloud entities. All demo events chain to `user:alice` → a single incident; `incidents[0]` is highest risk.
- Anomaly findings use `rule_id="builtin-anomaly-baseline"` and carry `evidence["signals"]` — a list of `{signal, entity, points, detail}`. Add new signals in `anomaly.py`, not in the detection rules.

### Auth model (read before touching `web/api.py`)

- The auth **middleware is fail-closed** for `/api/*`, `/ui/*` **and every rendered UI page**: with neither `AUTOSIEM_RBAC_FILE` nor `AUTOSIEM_API_TOKEN` set, requests get 401 unless `AUTOSIEM_AUTH_INSECURE=1`. Only `/health`, `/metrics` and the generated docs stay open.
- UI pages were open until 2026-08-08 (SEC-005), which served `/audit` and every incident detail to unauthenticated callers. `AUTOSIEM_AUTH_INSECURE=1` is now the way to get the old open local-workstation behaviour.
- Tokens are read from `Authorization: Bearer`, `x-api-key`, **or an `autosiem_token` cookie** — the cookie is what makes the browser UI usable under RBAC.
- `UI_PAGES` matches paths exactly; a loose `startswith` previously meant `/eventsfoo` counted as a UI page.
- **`AUTOSIEM_INGEST_TOKEN` is a write-only collector credential (SEC-007).** Outside RBAC mode it alone
  authenticates `POST /api/ingest` and nothing else; once set, ingest requires it. In RBAC mode it is an
  extra check on top of an `ingest`-role user, never a bypass. `_ingest_authorized` returning True when the
  token is unset is NOT open: the middleware already required RBAC, the API token, or insecure mode.
- **Audit actor comes only from authentication (SEC-009).** `_actor(request)` takes no caller input: RBAC
  user name, else `api-token` / `ingest-token` from `request.state.auth_mode`, else `unauthenticated`. Never
  add an `actor` query/body parameter to an endpoint.
- **Compare tokens with `_tokens_equal`, not `secrets.compare_digest` on raw header strings.** Starlette
  decodes headers as latin-1; a non-ASCII `str` makes `compare_digest` raise, which was a 500.
- **No TLS in-app, by design (SEC-012).** Beyond loopback: TLS reverse proxy, uvicorn on `127.0.0.1`, no
  `--reload`. `run_dashboard.sh` only adds `--reload` on loopback; keep that script bash-3.2-safe (macOS
  `/bin/bash`): an empty array under `set -u` needs `${arr[@]+"${arr[@]}"}`.
- CSRF on `/ui/*` forms is **on by default** (per-process secret when `AUTOSIEM_CSRF_SECRET` is unset), read at call time, and bound to the form's target path.
- **Token storage is salted PBKDF2-HMAC-SHA256** (`pbkdf2_sha256$<iters>$<salt>$<digest>`, written as
  `token_hash`). Never compare verifiers with `==` — `rbac.verify_token` is the only comparison path
  and uses `secrets.compare_digest`. Legacy `token_sha256` digests still verify so old files keep
  working; `cli users rotate` rewrites them salted. Per-user salts make auth **O(N)**: a failed
  authentication costs one PBKDF2 pass per user (~15ms x N). Do not reintroduce a digest lookup
  index to fix that — it would undo the salt.
- **Audit sealing (SEC-005):** with `AUTOSIEM_AUDIT_SECRET` set, each audit row stores `mac` =
  HMAC-SHA256(key, hash). The hash chain is unchanged, so old databases still verify, and the first
  sealed row protects the unsealed history beneath it. Missing key = warn once, write unsealed (never
  refuse). `audit-verify` reports `seals_checked`; without the key it must never read as a full pass.
  Not covered: tail truncation, whole-log MAC stripping, key rotation. A rewrite simulation against a
  SQL_ASCII cluster must pin `client_encoding=utf8` or it hashes `b'...'` and fails for the wrong reason.
- Env var reference: `.env.example`. Policy: `SECURITY.md`. Findings + resolution status: `docs/security-review.md`.

### System One decision layer (read before touching `system_one/`)

- **It is advisory and must stay advisory.** It never changes severity, risk or a
  policy gate; a disagreement is a note plus a metric. The load-bearing test is
  `test_system_one_pipeline.py::test_a_confident_model_cannot_lower_a_policy_gate`,
  which runs the demo twice and asserts identical `approval_required` flags.
- **Off by default** (`AUTOSIEM_DECISION_PROVIDER=none`). Every failure path -
  no key, no model, timeout, malformed answer, both providers down - degrades to
  exactly the no-provider behaviour.
- **`decide` is sync on purpose.** The pipeline is sync top to bottom; an async
  provider would mean an event loop inside it for one HTTP call.
- **Jev uses `urllib`, not the SDK** (zero-runtime-dependency rule). Laya is the
  `.[laya]` extra and is imported lazily.
- **Malformed answers raise `DecisionInvalid`,** never a defaulted classification.
- **Three distinct states:** provider failed (fall back), answered but
  low-confidence (no fallback unless opted in), answered confidently.
- A noul's certainty floors at 0.5, so only a choice/score confidence can push an
  assessment below the review threshold. That is why the disposition is the
  **minimum** of the `malicious` and `severity` certainties.
- Migration `005_system_one_decisions.sql` on PostgreSQL; in-place table create on
  SQLite. Composite `(tenant_id, incident_id)` key, like every tenant table.
- Building this found two real redactor gaps (bearer tokens, `sk-live-` keys),
  now fixed and recorded under SEC-011.

### Constraints and hard-won notes

Two different things used to sit under one "do not fix" heading, which made
accumulated observations read like product rules. They are separated now.

**Product decisions — do not undo without the owner:**

- **Zero runtime dependencies in `src/autosiem`.** stdlib only, network via
  `urllib`, extras only for `api`/`dev`/`postgres`. No PyYAML, no `requests`,
  no `boto3`. This is in README, CONTRIBUTING and `docs/architecture.md`, and
  the Sigma parser exists because of it.
- **The palette is OKLCH with hex fallbacks, and contrast is a test, not a taste.**
  Surfaces share one hue and step evenly in lightness, which sRGB could not express.
  `test_ui_palette.py` enforces WCAG AA on every foreground/background pair; it
  exists because the previous palette put white button labels on a light cyan
  gradient at **1.66:1**, unreadable on every button, and no screenshot caught it.
- **No webfont request from the UI, and no Inter/Roboto/Arial.** `_page` sets
  `--font-display` (monospace, for headings, labels and identifiers) and
  `--font-body` (humanist sans, for prose) from system stacks only. A SOC console
  must render identically in an air-gapped network, and a webfont link would tell
  the font host every time an analyst opens the dashboard. Guarded by three tests
  in `test_ui_auth.py`.
- **UI layout (PR #32, 2026-11-04, `feat/ui-redesign`):** colour is reserved for
  severity (critical=danger, high=warn, medium=accent); one top nav from `_NAV`;
  the incident page leads with the attack timeline; every JSON dump is a table
  via `_table` with the raw row folded behind `<details>`. Design follows
  Anthropic's `frontend-design` skill. `/search` markup strings are pinned by
  `test_search_nl_page.py` (`_chips` regex, the toggle's single-quoted
  `chipbtn active' href=...`): do not reuse `<span><strong>` elsewhere on that page.
- **Fail closed on anything the engine cannot evaluate.** An unsupported Sigma
  modifier, an unmapped logsource category, and an unknown selection operator
  all refuse rather than silently drop the constraint. A dropped constraint is
  a rule that matches more than its author wrote.

**Notes from earlier sessions — useful, not sacred. Re-verify before trusting:**

- Do not delete or edit `data/autosiem.db` (dev data). Tests use temp DBs.
- A new org/tenant-scoped connector must add its identifying flag to
  `_CONNECTOR_IDENTITY` in `cli.py`, or its cursor collides with a peer's.
- **`PostgresStorage` overrides several `RelationalStorage` methods.** Change a base
  signature and the override silently keeps the old one: adding `tenant_id` to
  `audit()` made every audited write on the PostgreSQL path raise `TypeError`,
  which the default SQLite-only test profile cannot catch. **Run the suite with
  `AUTOSIEM_TEST_POSTGRES_DSN` before claiming a PostgreSQL number.**
- A new tenant-scoped table must be added to `_TENANT_KEYED_TABLES` in
  `storage.py` so it gets a composite `(tenant_id, id)` key. A `tenant_id`
  column alone is not isolation: `INSERT OR REPLACE` on a single-column key
  lets one tenant overwrite another's row.
- **A rule's selection must be FLAT to survive `cli export`.** `any_of`/`all_of`/`not`
  trees are evaluated correctly but do not round-trip through Sigma export, and
  `test_sigma_export.py` gates on that. Put multiple operators in one field dict
  (they are ANDed) or use a single `regex`; a rule that cannot be exported cannot
  be shared.
- JSON rule files contain `//` comments - editor "errors" are expected.
- Python 3.10.14, macOS. `cd` into the project root; `PYTHONPATH=src` on every
  command.
- Running many pytest processes at once produces timing/race artifacts.
- The repo has been modified by parallel sessions mid-work. **Re-run
  `git log --oneline -3` before trusting any commit hash in this file.**

# AutoSIEM — First-Alpha Security Review

**Scope:** current first-alpha codebase (v0.1.0). A stdlib-only, single-node SOC SIEM:
raw events → normalize → MITRE/ATT&CK + Sigma detections → risk → incidents → policy-gated
AI proposals → SQLite / CLI / FastAPI UI.

**Date:** 2026-08-06. **Method:** static read of the auth, storage, ingest, LLM, and RBAC paths.
**Verification:** no test suite run; findings are grounded in the code read and marked `verify`
where a claim depends on runtime or deployment conditions.

**Verdict in three lines:** Good foundations for an alpha (parameterized SQL, hash-chained audit,
redaction, proposal-only AI, stdlib-only), but the web surface is **open by default** — with no API
token, RBAC users file, or ingest token configured, the entire API and the state-changing UI are
unauthenticated. That, plus an unbounded synchronous ingest path and an unauthenticated, spoofable
UDP syslog listener, is what must change before AutoSIEM is exposed to a shared host or real
forwarders.

---

## 1. Scope & model

The MVP is a **single-node workstation SOC SIEM**. The threat model implied by the code and
documented in `docs/deployment-and-collection.md` is that AutoSIEM runs on a trusted operator's
machine and talks to a small set of known forwarders (rsyslog / syslog-ng / Filebeat / Vector) and a
local or remote LLM.

The authentication posture in `src/autosiem/web/api.py` is **open by default** and sits in four
separable boundaries:

| Boundary | What it protects | Enforced by | Default when unconfigured |
|---|---|---|---|
| **UI read pages**<br>`/`, `/events`, `/findings`, `/rules`, `/sources`, `/suppressions`, `/audit`, `/incidents/*` | Local read-only view | None | **Open** |
| **UI write routes**<br>`/ui/proposals/…/approve`, `/ui/rules/{id}/toggle`, `/ui/suppressions/…`, `/ui/incidents/…`, `/ui/ingest-demo` | State changes | **None today** (see SEC-002) | **Open (write)** |
| **Data `/api/*`** | Incidents, events, findings, audit, rules, suppressions, proposals | RBAC (per-endpoint) **or** legacy `AUTOSIEM_API_TOKEN` | **Open** |
| **Ingest `/api/ingest`** | Event ingestion | `AUTOSIEM_INGEST_TOKEN` (plus the API token when present) | **Open** |
| **Syslog/CEF UDP**<br>`cli listen --port 5514` | Syslog / CEF event intake | None | **Open, spoofable** |

There is **no TLS inside the application**; `uvicorn` or a reverse proxy must supply it
(SEC-012). Until auth and TLS are additive and mandatory, treat the web listener as
**localhost-only**, not a network-facing or shared-host service.

Environment variables are read **at call time** — `_env_db_path()`/`_env_rule_path()` in
`api.py:49-56`, `rbac_from_env()` in `rbac.py:274-284`, `config_from_env()` in `llm.py:66-84`.
This is good (no secrets in the repo, easy to test) and means the real boundary is whatever is
exported to the process, so deployment docs should be explicit about which variables gate which
surface.

---

## 2. Assets & trust boundaries

| Asset | Where | Sensitivity | Who can touch it today |
|---|---|---|---|
| **SQLite DB** (`data/autosiem.db`, `AUTOSIEM_DB`) | Events (incl. raw evidence), findings, incidents, investigations, proposals, comments, `rule_state`, `audit_log` | High (PII in event `data` and incident summaries) | Any process with the path; an unconfigured API/UI |
| **Detection rules dir** (`rules/`, `AUTOSIEM_RULES`) | Static rule JSON + persisted enable/disable in `rule_state` | High (can disable all detections) | `ui/rules/{id}/toggle` open; `api/rules` permission-gated |
| **RBAC users file** (`data/rbac_users.json`, `AUTOSIEM_RBAC_FILE`) | `User` records + sha256 token hashes | High (the privilege boundary itself) | Local filesystem; written by `cli users` / `RBAC.save()` |
| **Threat-intel STIX state** (`<db>.intel.json`) | Indicators matched at ingest | Medium (content integrity) | Local filesystem; `load-intel` / `update` |
| **LLM outbound network** | `AUTOSIEM_LLM_URL` + `AUTOSIEM_LLM_API_KEY` | Medium (PII can leave the host) | Only when an LLM backend is configured |
| **Audit log** (`audit_log` table) | Tamper-evident hash chain | High | Any actor on the DB / API write paths |

---

## 3. Findings

### SEC-001 — API open by default (High)

| | |
|---|---|
| **Location** | `web/api.py:_api_auth_middleware` (L106-132), `_require_permission` (L80-96) |
| **Description** | If no RBAC users file (`AUTOSIEM_RBAC_FILE`) is present and `AUTOSIEM_API_TOKEN` is unset, the middleware passes every `/api/*` request through with no check at all (L129-132). Even when RBAC **is** configured, `_require_permission` returns early when `request.state.rbac` is `None`/disabled (L88-89). So an unconfigured install exposes incidents, events, audit, proposals, and every write route unauthenticated. |
| **Recommendation** | Make the API **fail closed**: default every data-protecting `/api/*` route to requiring a token/RBAC user, and refuse to start (or log a loud warning) when neither `AUTOSIEM_RBAC_FILE` nor `AUTOSIEM_API_TOKEN` is set. Add an explicit `AUTOSIEM_AUTH_INSECURE=1` dev opt-out so open-by-default is deliberate, not accidental. |
| **Severity** | **High** |

### SEC-002 — `/ui/*` state-changing routes bypass auth entirely (High)

| | |
|---|---|
| **Location** | `api.py` middleware L118 (`if not request.url.path.startswith("/api"): return await call_next(request)`); `ui_toggle_rule` (L618-623), `ui_ingest_demo` (L626-629), `ui_approve`/`ui_reject` (L632-641), `ui_add_suppression` (L671-683), `ui_delete_suppression` (L686-689), `ui_update_incident` (L692-702), `ui_add_comment` (L705-711) |
| **Description** | The auth middleware only runs for URLs starting with `/api`. All **state-changing paths** live under `/ui/*`, so `request.state.rbac`/`request.state.user` are never populated for them; `_require_permission` sees `rbac is None` and returns (allowed), and several handlers (e.g. `ui_toggle_rule` L622) call `get_store().…` directly with **no permission check at all**. Net effect: **even with RBAC enabled**, an unauthenticated `POST /ui/proposals/{id}/approve`, `/ui/suppressions/{id}/delete`, `/ui/rules/{id}/toggle`, or `/ui/incidents/{id}/update` succeeds — approving AI actions, deleting exceptions, disabling detections, and rewriting triage. These are also plain HTML form POSTs with **no CSRF token**, so a page you visit could drive them on a shared or network-exposed host. |
| **Recommendation** | (a) Populate `request.state` for all paths and add explicit auth/permission requirements to every `/ui/*` mutating handler, or port these routes onto the authenticated `/api` controllers they already wrap. (b) Add CSRF tokens / `SameSite` handling once auth exists. Until then treat the UI as local-only. The single most serious gap if AutoSIEM is ever bound to a non-loopback interface on a shared host. |
| **Severity** | **High** |

### SEC-003 — Ingest abuse / DoS on `/api/ingest` (High)

| | |
|---|---|
| **Location** | `api.py:api_ingest` (L346-366), `_parse_ingest_payload` (L309-333), `_pipeline()` (L280-296); `llm.py` 30s call timeout (L166-176) |
| **Description** | `POST /api/ingest` has **no rate limit, no max body size, no max line/event count**. It decodes the entire body (`await request.body()` → per-line `json.loads`) and runs the **full pipeline synchronously inside the request**, including an optional **LLM call that can take up to 30s**, then persists. A flood of requests (or one huge NDJSON body) turns the endpoint into a CPU / memory / I/O DoS target. |
| **Recommendation** | Add per-client and per-token rate limits; reject bodies above a configurable `MAX_INGEST_BYTES` / `MAX_INGEST_EVENTS` with `413`; move ingest work to a bounded queue or the existing `workers.ParserWorkerPool` so the request handler never blocks on long work. |
| **Severity** | **High** |

### SEC-004 — UDP syslog/CEF listener is open, spoofable, unthrottled (High)

| | |
|---|---|
| **Location** | `listeners.py:SyslogServer._serve` (L210-220) and `start()` (L200-208); `cli.py:_run_listener` (L481-508) |
| **Description** | `_serve` does `recvfrom(65536)` in a single thread and calls `self.handler(line_to_raw(line))` **synchronously inside the receive loop**. Anyone who can reach the UDP port can (a) **inject arbitrary events** — the source `_address` is ignored, there is no allowlist/auth — and (b) **starve the listener**, because each datagram blocks the socket loop through the full normalize → detect → incident → (possibly LLM) pipeline. The deployment doc's example binds `0.0.0.0`. UDP has no handshake, so spoofed events are trivial and can be used for **detection poisoning** (fabricated findings / fabricated non-findings). |
| **Recommendation** | (a) Add a source-IP allowlist and a per-source rate limit. (b) Move datagram handling into a bounded worker pool so one datagram cannot block `recvfrom`. (c) Prefer TLS/TCP or forwarders relaying to `/api/ingest` with a token for anything untrusted. If UDP is kept in production, treat it as unauthenticated by design and bind it only on a trusted collector network. |
| **Severity** | **High** |

### SEC-005 — Audit log is tamper-evident but not tamper-proof (Medium)

| | |
|---|---|
| **Location** | `storage.py:audit` (L552-567), `verify_audit_chain` (L569-586), migration (L152-156); `cli.py:audit-verify` (L363-365) |
| **Description** | Good: each row stores `prev_hash` + `hash`, where `hash = sha256(prev_hash|timestamp|actor|action|target|details)` (L562-563); `verify_audit_chain` recomputes every digest and reports `prev_hash_mismatch`/`hash_mismatch` (L578-584); `cli audit-verify` surfaces this. **Gap:** it is a bare sha256 with **no secret/HMAC**. Any actor who can write to the DB can recompute valid hashes after an edit, so the chain detects accidental modification but not *deliberate* tampering by a DB-writer. |
| **Recommendation** | Stage 1: key the hash with an HMAC secret held outside the DB (e.g. `hmac.new(key, payload, hashlib.sha256)`) so only a secret-holder can re-seal. Stage 2, when cost-justified: periodically ship the per-batch chain anchor to append-only external storage for strong non-repudiation. |
| **Severity** | **Medium** |

### SEC-006 — Token comparisons are not constant-time (Medium)

| | |
|---|---|
| **Location** | `rbac.py:authenticate` L194-196 (`stored == digest`); `api.py` legacy middleware L130 (`token != api_token`); `_ingest_authorized` L339-343 (`x-api-key == token`, `authorization == f"Bearer {token}"`) |
| **Description** | All bearer-token comparisons use Python string `==` (short-circuiting) instead of `secrets.compare_digest`. On loopback/LAN the timing risk is low in practice, but this is standard hygiene and the fix is trivial. |
| **Recommendation** | Replace each with `secrets.compare_digest`. For RBAC auth, compare the two 64-hex digests with `secrets.compare_digest(stored, digest)`. |
| **Severity** | **Medium** |

### SEC-007 — Ingest token is default-open and is a separate surface from the API token (Medium)

| | |
|---|---|
| **Location** | `api.py:_ingest_authorized` (L336-343) and middleware (L123-131) |
| **Description** | `_ingest_authorized` returns `True` when `AUTOSIEM_INGEST_TOKEN` is unset (L339-340). Consequences: setting **only** `AUTOSIEM_API_TOKEN` leaves `POST /api/ingest` open; setting **only** `AUTOSIEM_INGEST_TOKEN` protects ingest but leaves every other `/api/*` endpoint default-open. When both are set, `POST /api/ingest` requires **both** (middleware token **and** ingest token), which invites operators to reuse one value and collapse the boundary. |
| **Recommendation** | Make ingest fail closed when neither an ingest token nor an `ingest:events` RBAC user is configured; add a startup log that states exactly which surfaces are open. Document the two tokens in one config diagram. |
| **Severity** | **Medium** |

### SEC-008 — Users-file tokens are unsalted sha256, never rotate/expire, and `load()` accepts plaintext (Medium)

| | |
|---|---|
| **Location** | `rbac.py:hash_token` (L96-98), `Rbac.load` (L157-181, accepts a plaintext `token` field), `save` (L253-271, writes only `token_sha256`), `add_user`/`remove_user` (L227-251); CLI `users` (cli.py:377-401) |
| **Description** | Good: tokens are persisted only as sha256 hex digests and `save()` never writes plaintext back. **Gaps:** (1) `load()` also accepts a plaintext `"token"` field and hashes it on load (L178), which quietly breaks the never-store-plaintext invariant if a file carries a plaintext token. (2) The hash is **unsalted sha256**, so anyone who reads the users file can brute-force low-entropy tokens fast — no KDF, no rate-limiting on guesses. (3) Tokens are bearer and long-lived, generated only at `add_user` time; there is no `rotate-token`, no expiry, and revocation only by deleting the user. |
| **Recommendation** | (a) Use `hashlib.pbkdf2_hmac`/`bcrypt` with a per-user salt (or at minimum pepper the digest). (b) Generate high-entropy tokens (`python3 -c "import secrets; print(secrets.token_urlsafe(32))"`) and document it. (c) Reject a `token` key on load (accept only `token_sha256`) and add a `users rotate-token` command. |
| **Severity** | **Medium** |

### SEC-009 — Legacy mode lets callers forge the audit-log `actor`; `/ui/*` hardcode it (Medium)

| | |
|---|---|
| **Location** | `api.py:_actor` (L99-103); `api_approve`/`api_reject` `actor: str = "analyst"` (L193-209); `api_update_incident` (L246-260), `api_add_incident_comment` (L270-277); hardcoded `actor="analyst"` in `ui_toggle_rule` (L622), `ui_update_incident` (L700), `ui_add_comment` (L710) |
| **Description** | In legacy mode no authenticated user is set, so `_actor` returns the **caller-supplied** `actor` query parameter (default `analyst`). Anyone can `POST /api/proposals/{id}/approve?actor=admin` and have that string recorded in `audit_log.actor` — forging who did what. In RBAC mode `_actor` resolves from the authenticated user, so the hole only bites in legacy mode. The `/ui/*` handlers hardcode `actor="analyst"`, so they stamp an arbitrary name regardless of the real actor. |
| **Recommendation** | Derive the audit actor only from the authenticated principal; remove the caller-provided `actor` parameter in legacy mode (or reject requests carrying one when auth is off). |
| **Severity** | **Medium** |

### SEC-010 — LLM prompt-injection surface and an unredacted RAG context path (Medium)

| | |
|---|---|
| **Location** | `llm.py:annotate`/`_build_user_prompt` (L241-299), `_fit_context` (L301-334), `mask_pii` config (L81); `rag.py:RagEngine` / `_index_incidents` (L145-168); `pipeline.py` feeds `rag.build_prompt(incident)` as `extra_context` |
| **Description** | The incident+findings JSON is redacted before send (L267-277, L283) — good. But the **`extra_context` string is appended to the prompt with no redaction** (L294-298). Today `default_rag_engine()` indexes only the bundled static runbooks (`rag.py:32-36`), which are safe. If `RagEngine(incidents=...)` is ever used (a listed future feature is "RAG over historical incidents"), `_index_incidents` includes `inc.get('summary')` (L152), which could carry IPs/emails into the prompt unmasked unless `redact` is applied to `extra_context`. Separately, because events are attacker-controllable at ingest, prompt-injection content can flow into the analyst prompt. Blast radius is limited: LLM decisions are schema-validated + coerced (`validate_decision`, L202-218), and unknown/unsafe action names are **blocked by default** by `policy.py` (L96-97: `Unknown action … blocked by default`). |
| **Recommendation** | (a) Keep `AUTOSIEM_LLM_MASK_PII=1` as the default and run `extra_context` through `redact` before appending. (b) Continue to treat LLM output as untrusted and never let an LLM-generated action name execute without passing the `policy.py` allow-list. |
| **Severity** | **Medium** |

### SEC-011 — PII/secrets redaction is heuristic and has documented gaps (Medium)

| | |
|---|---|
| **Location** | `redaction.py` (L20-126): `_LABELLED_SECRET`, `_HIGH_ENTROPY`, `_AWS_ACCESS_KEY`, `_SSH_KEY`, `_IPV4`, `_EMAIL`, `_SSN`, `_IPV6`, `_CREDIT_CARD_RE`; `llm.py:config_from_env` `mask_pii` (L81) |
| **Description** | Redaction is deterministic and layered: labelled secrets always; high-entropy tokens (`sk-`, `ghp_`, `Bearer …`) always; AWS `AKIA…`; SSH key blocks; IP/email/SSN/IPv6 only when `mask_pii`. Known gaps: (a) plain passwords or keys in prose are only caught if they follow `key=value`/a known prefix; (b) JWTs/opaque tokens are not matched (not in `_HIGH_ENTROPY`); (c) the AWS **secret key** itself is not matched — only the `AKIA…` access key ID (L33); (d) `AUTOSIEM_LLM_MASK_PII=0|false|no` turns PII masking **off globally** (llm.py:81). It defaults to on; anyone disabling it sends IPs/emails/SSNs to the model unmasked. |
| **Recommendation** | Extend patterns to JWT/opaque tokens and cloud secret-key material; keep `mask_pii` on by default; treat `AUTOSIEM_LLM_MASK_PII=0` as a conscious, documented decision. |
| **Severity** | **Medium** |

### SEC-012 — No in-app TLS; docs/README show plain `http://` and dev `--reload` (Medium)

| | |
|---|---|
| **Location** | `pyproject.toml` `[api]` extra; `README.md` `uvicorn autosiem.web.api:app --reload`; `docs/deployment-and-collection.md` Vector sink example using plain `http://` with an `x-api-key` token header |
| **Description** | Nothing in the app terminates TLS; over a network, tokens (ingest/API/LLM `AUTOSIEM_LLM_API_KEY`) travel in cleartext. The README quick-start runs `uvicorn ...:app --reload`, a dev-mode flag that should never be left on behind a real listener. The deployment doc's stated "Auth, TLS … configured first" is aspiration, not enforced behavior. |
| **Recommendation** | Terminate TLS at a reverse proxy (Caddy/nginx) in front of the uvicorn worker; drop `--reload` in production; do not document plain `http://` + token examples for anything but loopback. |
| **Severity** | **Medium** |

### SEC-013 — Tenant label is stored but not enforced (Medium)

| | |
|---|---|
| **Location** | `rbac.py:User.tenant` (L116), `Rbac` (L133-197); all `/api/*` data reads call `search_incidents`/`list_incidents`/`list_events` with **no tenant filter** |
| **Description** | `tenant` is recorded per user and listed (rbac.py L118, L222, L267) but is **never used to scope query data** — any `data:read` user reads every tenant's incidents/events. For a single-workstation alpha this is fine; if multi-tenant SaaS is the direction (`docs/deployment-and-collection.md`), this is a hard boundary to build before shipping it. |
| **Recommendation** | When multi-tenant ships, thread `user.tenant` into every `search_*`/`list_*` call and add a test asserting one tenant cannot read another's rows. |
| **Severity** | **Medium** |

### SEC-014 — Secrets in config & code: handled well today; DB-at-rest and docs hygiene notes (Low)

| | |
|---|---|
| **Location** | `llm.py:config_from_env` (L66-84, reads `AUTOSIEM_LLM_API_KEY`), `rbac.py:rbac_from_env` (L274-284), `api.py` env reads (L49-56); `storage.py` persists raw event payloads in `events.data` |
| **Description** | No hardcoded secrets in the source; tokens/keys come from env read at call time — keep this. Two notes: (a) `events.data`/`findings.data` persist whatever the ingest payload contained, so a client that logs secrets into events stores them at rest (see SEC-016/SEC-014-data-at-rest); (b) examples and docs must never print real tokens, and a `.env.example` (empty values) would help operators. The LLM API key is only sent to the configured `base_url` and only when present (`llm.py:122-123`) — good. |
| **Recommendation** | Keep env-only secrets; add `.env.example` with empty values; document that event payloads are stored as-is; never print tokens in docs/examples. |
| **Severity** | **Low** |

### SEC-015 — Info disclosure via `/health` (Low)

| | |
|---|---|
| **Location** | `api.py:health` (L135-137); `/metrics` (L440-445) |
| **Description** | `/health` is deliberately open and returns `_env_db_path()` and `_env_rule_path()` on the wire, leaking absolute DB/rules paths to any caller. Minor, but a nice-to-fix. `/metrics` returns only observed counts — fine to leave open. |
| **Recommendation** | Return status only (`{"status":"ok"}`), or strip paths from the public health response. |
| **Severity** | **Low** |

### SEC-016 — Deep/oversized JSON and plaintext-at-rest can 500 or memory-spike (Low)

| | |
|---|---|
| **Location** | `api.py:_parse_ingest_payload` (L316-333), `api_ingest` (L351-355, catches `ValueError` only); `storage.py:DEFAULT_DB_PATH` (L24) / `AutoSIEMStorage.__init__` (L30-33); `rbac.py:save` (L270-271); `threat_intel.py:save_intel_state` (L125-132, atomic) |
| **Description** | (a) `json.loads` on deeply nested payloads can raise `RecursionError`/`MemoryError`, neither caught here (only `ValueError` at L354), producing a 500 and memory pressure (see SEC-003 for the DoS angle). (b) The SQLite file holds raw events/evidence in cleartext on disk; `rbac_users.json` and the intel state are plaintext JSON with umask-derived permissions (commonly `0644`). On a shared host another local process can read PII. The intel state write is atomic (tmp+rename) — keep that. |
| **Recommendation** | Catch `RecursionError`; enforce a body-size cap (SEC-003); restrict `data/` + users-file permissions (e.g. `chmod 0600` on `rbac_users.json`); recommend OS full-disk encryption on the host. |
| **Severity** | **Low** |

### SEC-017 — Threat-intel refresh allows plaintext fetch with no integrity check (Low)

| | |
|---|---|
| **Location** | `update_job.py:_load_indicators` (L81-99, `urllib.request.urlopen` with `# noqa: S310` at L85); `threat_intel.py:load_intel_state`/`save_intel_state` (L112-132) |
| **Description** | `--intel-url` fetches a STIX bundle over whatever scheme is given, including plain `http://`, where a MITM can tamper with the feed (indicators are just match strings — a tampered bundle yields fabricated findings or false-negatives). `https://` uses the default CA verification (good for that path). State-file writes are atomic (good). |
| **Recommendation** | Enforce `https://` for `--intel-url` and `AUTOSIEM_LLM_URL` when remote; sign the bundle or pin the feed; add an allow-list/SSRF guard if auto-refreshing in production. |
| **Severity** | **Low** |

### Verified clean — SQL injection through the search DSL (no vulnerability)

| | |
|---|---|
| **Location** | `storage.py:search_events` (L321-350), `search_incidents` (L352-372), `_findings_by_ids`/`_events_by_ids` (L380-393) |
| **Description** | **Positive.** `search_events`/`search_incidents` build `WHERE` clauses from a `params` list and pass every user value as a `?` placeholder (query `LIKE`, entity, status, limit — all parameterized); `_findings_by_ids`/`_events_by_ids` construct `IN (?,…)` placeholders only from `?` counts (L383, L390). The NL DSL (`translate_query`) feeds strings into those `search_*` calls. **No SQL injection present today.** |
| **Recommendation** | Keep the `?`-only discipline. **Verify:** if any future query interpolates a raw SQL fragment, this flips — add a code-review rule that all dynamic SQL goes through parameter binding. |

---

## 4. Findings table

| ID | Severity | Title | Location | Recommendation |
|---|---|---|---|---|
| SEC-001 | **High** | API open by default | `web/api.py:_api_auth_middleware` L106-132; `_require_permission` L80-96 | Fail-closed; refuse to start without a token/RBAC file (or explicit `AUTOSIEM_AUTH_INSECURE=1`) |
| SEC-002 | **High** | `/ui/*` mutators bypass auth and RBAC (no CSRF) | `api.py` L118, L618-711 | Populate `request.state` for all paths; guard/port `/ui/*` writes to API controllers; add CSRF |
| SEC-003 | **High** | Unbounded, synchronous `/api/ingest` → DoS | `api.py:api_ingest` L346-366; `_parse_ingest_payload` L309-333 | Rate limits, `MAX_INGEST_BYTES`/`MAX_INGEST_EVENTS` (413), move work to a bounded pool |
| SEC-004 | **High** | UDP syslog/CEF listener open, spoofable, unthrottled | `listeners.py:SyslogServer._serve` L210-220; `cli.py:_run_listener` L481-508 | Source allowlist + rate limit; bounded worker pool; prefer TLS/TCP/API ingest |
| SEC-005 | Medium | Audit chain tamper-evident, not tamper-proof | `storage.py:audit` L552-567; `verify_audit_chain` L569-586 | HMAC the payload with a key outside the DB; external anchor later |
| SEC-006 | Medium | Token comparisons use `==` (timing) | `rbac.py:authenticate` L194; `api.py` L130, L339-343 | `secrets.compare_digest` everywhere |
| SEC-007 | Medium | Ingest token default-open; overlaps/combines with API token | `api.py:_ingest_authorized` L336-343 | Fail closed when no ingest auth; document both tokens; startup surface log |
| SEC-008 | Medium | Users-file tokens: unsalted sha256, no rotation/expiry, `load()` accepts plaintext `token` | `rbac.py:hash_token` L96-98; `load` L157-181; `save` L253-271 | KDF + salt; `rotate-token`; reject plaintext `token` on load |
| SEC-009 | Medium | Audit-actor spoofing via caller `actor` param (legacy); `/ui/*` hardcode `analyst` | `api.py:_actor` L99-103; L193-209, L246-271; L622/700/710 | Actor from authenticated principal only; drop/deny caller `actor` when auth off |
| SEC-010 | Medium | LLM prompt-injection surface; RAG `extra_context` unredacted | `llm.py` L241-299, L294-298; `rag.py` L145-168 | `redact` `extra_context`; keep schema validation + deny-unknown-action policy |
| SEC-011 | Medium | Redaction is heuristic; `AUTOSIEM_LLM_MASK_PII=0` disables PII masking | `redaction.py` L20-126; `llm.py` L81 | Extend patterns (JWT, cloud secret keys); keep PII masking on by default |
| SEC-012 | Medium | No TLS in-app; docs/README show plain `http://` + `--reload` | `pyproject.toml`; `README.md`; `docs/deployment-and-collection.md` | Reverse-proxy TLS; drop `--reload`; only loopback examples |
| SEC-013 | Medium | `tenant` stored but unenforced (multi-tenant gap) | `rbac.py:User.tenant` L116; data queries | Thread `tenant` into `search_*`/`list_*`; add cross-tenant isolation test |
| SEC-014 | Low | Secrets-in-config handled well; event payloads stored as-is; docs hygiene | `llm.py` L66-84; `storage.py` `events.data` | Keep env-only secrets; `.env.example`; document at-rest payload storage |
| SEC-015 | Low | `/health` leaks db/rules paths | `api.py:health` L135-137 | Return `{"status":"ok"}` only |
| SEC-016 | Low | Deep/oversized JSON → 500/memory; plaintext at rest + umask perms | `api.py` L316-355; `storage.py` L30; `rbac.py` L271; `threat_intel.py` L125 | Catch `RecursionError`; body cap; `chmod 0600`; full-disk encryption |
| SEC-017 | Low | Intel refresh allows plaintext fetch, no integrity/SSRF guard | `update_job.py:_load_indicators` L81-99 | Enforce `https://`; sign/pin feed; SSRF guard |
| Verified clean | — | Search DSL → parameterized SQL (no injection) | `storage.py` L321-393 | Keep `?`-only binding; review rule for future SQL |

---

## 5. Positive hardening — what’s already done well

**Already good (keep and advertise):**

- **Stdlib-only core.** `dependencies = []`; LLM/network over `urllib`; FastAPI only in an optional
  extra. Small supply-chain surface.
- **Parameterized SQL everywhere** — no string interpolation into queries (verified clean, above).
- **Hash-chained audit log + `cli audit-verify`** — tamper-evident and cheap to check.
- **Deterministic local AI that only *proposes***. `Investigator` (`ai.py`) is a pure function;
  `policy.py` requires approval for high/critical actions and **blocks unknown action names by
  default** (L96-97). The AI never auto-executes response actions. The strongest design control in
  the repo.
- **Token hashing in the users store** and `save()` never writes plaintext.
- **Per-class redaction** (secrets always; PII optional-but-default-on) before anything leaves the
  process.
- **Atomic intel-state writes** (tmp+rename).
- **HTML output consistently escaped** via `_esc()` on all template values (mitigates stored XSS).
- **Config through env read at call time** (`config_from_env`, `rbac_from_env`, `_env_db_path`) —
  keeps secrets out of the repo and is testable.

**Should-stage next (time-boxed):**

1. Fail-closed auth + startup guard (SEC-001/SEC-002) — closes the biggest risk.
2. Rate/size caps on ingest (SEC-003) and a bounded UDP handler (SEC-004).
3. Timing-safe compares (SEC-006) and HMAC-sealed audit (SEC-005).
4. Token KDF + rotation, users-file perms (SEC-008/SEC-016).
5. Keep PII redaction on, extend patterns, redact RAG `extra_context` (SEC-011/SEC-010).
6. Write a real `SECURITY.md` capturing the open-by-default posture, env vars, ports, TLS/proxy
   requirement, and this table, so every later alpha decision is recorded.

---

## 6. Recommendations — ranked, with a two-minute next action

1. **Fail-closed auth.** Next action (≤2 min): in `src/autosiem/web/api.py`, at startup, if
   `AUTOSIEM_RBAC_FILE` is absent **and** `AUTOSIEM_API_TOKEN` is unset **and** no explicit
   `AUTOSIEM_AUTH_INSECURE=1` is set, raise `RuntimeError` telling the operator to configure auth
   or opt out — instead of serving open.
2. **Close `/ui/*` mutators.** Next action (≤2 min): set `request.state.rbac`/`user` for all paths
   in the middleware and add explicit permission checks to the `/ui/*` write handlers (or point them
   at the `/api` controllers they wrap), then add CSRF tokens.
3. **Cap ingest.** Next action (≤2 min): add `MAX_INGEST_BYTES` / `MAX_INGEST_EVENTS` checks in
   `api_ingest` that reject oversized posts with `413` before the pipeline runs.
4. **Harden the UDP listener.** Next action (≤2 min): add an `--allow-from` source list to
   `cli listen` and move `handler(...)` into a bounded pool so a flood cannot block `recvfrom`.
5. **Timing-safe compares.** Next action (≤2 min): swap `==` for `secrets.compare_digest` in
   `rbac.py:194`, `api.py:130`, and `_ingest_authorized`.
6. **HMAC the audit chain.** Next action: HMAC-SHA256 the audit payload with an
   `AUTOSIEM_AUDIT_SECRET` held outside the DB; have `verify_audit_chain` honor it.
7. **Users-file hygiene.** Next action: `rbac.save()` `chmod 0600`; switch `hash_token` to
   `pbkdf2_hmac`; add a `users rotate-token` command.
8. **Write `SECURITY.md`.** Next action: capture the open-by-default banner, env table, port list,
   TLS reverse-proxy note, and a pointer to this review.

---

**Final summary — findings:** 17 findings + 1 verified-clean: **4 High** (API open by default
`SEC-001`; `/ui/*` mutators bypass auth `SEC-002`; unbounded/synchronous ingest DoS `SEC-003`;
open/spoofable UDP syslog `SEC-004`), **9 Medium** (audit not tamper-proof, `==` token compares,
ingest-token default-open/overlap, RBAC token hygiene, audit-actor spoofing, LLM prompt-injection +
unredacted RAG, redaction gaps, no TLS, tenant scoping unenforced), **4 Low** (secrets/config
hygiene, `/health` path leak, deep-JSON/at-rest, intel fetch integrity). Top three severities to act
on first: `SEC-002` (UI write bypass), `SEC-001` (API open default), and `SEC-003`/`SEC-004`
(unbounded, open ingest). The good foundations — parameterized SQL, hash-chained audit,
proposal-only AI, token hashing, redaction, stdlib-only — are worth preserving.

---

## 7. Resolution status since the review

The review above is preserved as written on 2026-08-06. This section tracks what has
changed in the code since then. **Findings not listed below remain open as originally
written.**

| ID | Severity | Status | Where it was addressed |
|---|---|---|---|
| SEC-001 | **High** | ✅ **Resolved** | `ca0ffcc` — API middleware is fail-closed; serving without auth now requires an explicit `AUTOSIEM_AUTH_INSECURE=1` opt-out |
| SEC-002 | **High** | ✅ **Resolved** | `ca0ffcc` — `/ui/*` state-changing routes require permission **and** a stateless CSRF token (`_validate_csrf` in `web/api.py`) |
| SEC-003 | **High** | ✅ **Resolved** | `ca0ffcc` — `AUTOSIEM_MAX_INGEST_BYTES` (10 MB default) + `AUTOSIEM_MAX_INGEST_EVENTS` (10,000 default) reject oversized posts before the pipeline runs |
| SEC-004 | **High** | ✅ **Resolved** | `ca0ffcc` — UDP listener takes a source-IP allowlist (`allowed_hosts`) and dispatches through a bounded `ThreadPoolExecutor` |
| SEC-006 | Medium | ⚠️ **Partial** | `secrets.compare_digest` is now used in `web/api.py` (CSRF validation, legacy `AUTOSIEM_API_TOKEN` guard). **Still open:** `rbac.py:authenticate` compares the stored digest with `==` |
| SEC-008 | Medium | ⚠️ **Partial** | `400b73e` — `rotate_token()` / `revoke_token()` shipped (CLI `users rotate\|revoke`, `POST /api/users/{name}/rotate-token\|revoke-token`). **Still open:** tokens are still unsalted sha256 (no KDF), and `Rbac.load()` still accepts a plaintext `token` field |
| SEC-013 | Medium | ✅ **Resolved** | `400b73e` (data plane) + `f0bc677` (control plane) — see below |

### SEC-013 in detail — tenancy is now enforced

Tenancy was the largest structural gap in the original review (`tenant` was stored on the
`User` record but never threaded into queries). It is now enforced on both planes:

- **Data plane** (`400b73e`) — `events`, `findings`, `incidents`, `investigations`, and
  `action_proposals` each carry an indexed `tenant_id`, back-filled to `default` by an
  automatic migration. In RBAC mode every request is scoped to the authenticated user's
  tenant on read *and* write, and a cross-tenant fetch returns **404 rather than 403** so
  callers cannot probe for the existence of other tenants' rows.
- **Control plane** (`f0bc677`) — `rule_state` was rebuilt with a composite
  `(rule_id, tenant_id)` primary key and `suppressions` gained an indexed `tenant_id`, so
  one tenant disabling a rule or adding a suppression no longer changes detection for
  every other tenant. The suppression engine and rule-state overlay are constructed **per
  tenant** on every ingest path.
- **Deliberately global:** the audit log is *not* tenant-scoped — a tenant must not be able
  to hide its own actions from an operator. The unauthenticated read-only HTML `GET` pages
  also still render across tenants by design; they are the local-workstation view, gated by
  `AUTOSIEM_AUTH_INSECURE`.

Unscoped callers (the CLI, and legacy single-token mode) continue to see every row, so
single-tenant deployments are unaffected by either change.

### Highest-value remaining work

1. **SEC-006 (finish it)** — swap the `==` digest comparison in `rbac.py:authenticate` for
   `secrets.compare_digest`; it is the one remaining timing-sensitive compare.
2. **SEC-008 (finish it)** — move `hash_token` to a salted KDF (`hashlib.pbkdf2_hmac`) and
   make `Rbac.load()` reject a plaintext `token` field instead of hashing it on the fly.
3. **SEC-005** — HMAC the audit chain with a key held outside the DB (`AUTOSIEM_AUDIT_SECRET`)
   so the chain is tamper-*proof*, not just tamper-*evident*.
4. **SEC-009 / SEC-007 / SEC-012** — actor-from-principal only, fail-closed ingest token, and
   a documented TLS reverse-proxy requirement remain as originally written.

## SEC-005 — Unauthenticated read access to the UI pages (fixed 2026-08-08)

**Severity:** High. **Status:** Fixed.

The auth middleware deliberately exempted rendered UI pages (`/`, `/events`,
`/findings`, `/sources`, `/audit`, `/rules`, `/suppressions`, `/incidents/{id}`)
so a local workstation install stayed convenient. Because the exemption ran
before the RBAC and token checks, those pages returned data to any
unauthenticated caller even when `AUTOSIEM_RBAC_FILE` or `AUTOSIEM_API_TOKEN`
was configured. A server bound to `0.0.0.0` therefore published the
tamper-evident audit log and every incident detail to the network.

The path test also used a loose `startswith`, so `/eventsfoo` and `/auditlog`
were treated as exempt UI pages.

**Fix:** UI pages are guarded exactly like `/api/*`. Path classification is now
exact-match plus an explicit `/incidents/` prefix. The open local-workstation
behaviour is available through `AUTOSIEM_AUTH_INSECURE=1`. Because browsers
cannot set an `Authorization` header on a navigation, tokens are additionally
accepted from an `autosiem_token` cookie, and CSRF validation was changed from
opt-in to on-by-default (per-process secret when `AUTOSIEM_CSRF_SECRET` is
unset, tokens bound to the form's target path) so cookie auth does not
introduce a CSRF hole. Covered by `tests/test_ui_auth.py`.

## SEC-018 — Model-reported confidence could authorize autonomous containment (fixed 2026-08-08)

**Severity:** High (latent — unreachable at the default autonomy level). **Status:** Fixed.

`AIAnalystRuntime` passed `decision.confidence` straight into
`AutomationPolicy.decision_for_action`, and at `POLICY_BOUNDED_AUTONOMOUS_RESPONSE`
(level 4) a high-risk action above `minimum_confidence_for_policy_bounded_response`
(0.98) executes with no human in the loop. When the decision came from the optional
LLM, that number was self-reported by the model and only clamped to `[0.0, 1.0]`.
A model returning `{"decision_type": "containment_proposed", "confidence": 1.0}` —
whether hallucinating or steered by prompt injection through ingested event text
(see SEC-010) — could therefore authorize its own `disable_user` / `isolate_host` /
`block_indicator` execution. The untrusted component controlled its own
authorization signal.

Not reachable in a default install: autonomy defaults to level 2
(`REVERSIBLE_AUTOMATION`), where high-risk actions are proposal-only. The exposure
was for operators who deliberately opted into level 4.

A related inconsistency sat next to it: `soar.py` forced `approval_required = True`
on high/critical steps but left `allowed` set, so a level-4 SOAR step could be
persisted as `executable_now=True` *and* `approval_required=True` — and
`executable_now` is what a downstream executor reads.

**Fix:** `AnalystDecision.confidence_source` records whether a score is
`deterministic` (derived by AutoSIEM from the evidence) or `model` (self-reported),
and `decision_for_action` accepts it. A `model` score never satisfies the
policy-bounded autonomous branch — it falls back to human approval regardless of
value. Raising the threshold instead was rejected: a model that will assert 0.99
will assert 0.999. The deterministic level-4 capability is unchanged. The source is
written to the audit log (`action_proposed ... confidence_source=model`) and
persisted with the investigation. `soar.py` now clears `allowed` whenever it forces
approval. Covered by `tests/test_autonomy_gate.py` (17 tests).

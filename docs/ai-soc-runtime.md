# AI SOC Analyst Runtime

AutoSIEM now has the first implementation of the AI SOC Analyst Runtime: a policy-bound automation layer that behaves like a junior analyst while preserving safety and auditability.

## Runtime responsibilities

For each incident, the runtime:

1. Creates an investigation object.
2. Collects structured evidence.
3. Plans analyst tasks.
4. Executes allowed low-risk/read-only tasks.
5. Produces a decision and confidence score.
6. Proposes response actions if needed.
7. Applies the automation policy to determine whether actions can execute or need approval.
8. Writes an audit log.

## Object model

Implemented in `src/autosiem/soc_runtime.py`:

- `Investigation`
- `Evidence`
- `AnalystTask`
- `AnalystDecision`
- `ActionProposal`

Implemented in `src/autosiem/policy.py`:

- `AutonomyLevel`
- `AutomationPolicy`
- `ActionPolicy`

## Default autonomy

Default autonomy is `REVERSIBLE_AUTOMATION`.

This means AutoSIEM can:

- search related events
- enrich entities
- create case notes
- link duplicate alerts
- run reversible workflow actions

But it cannot directly execute high-impact response actions.

High-impact actions are proposed and require approval:

- disable user
- isolate host
- block indicator
- close incident

## Whose confidence opens the gate

At `POLICY_BOUNDED_AUTONOMOUS_RESPONSE` (level 4, never the default) a high-risk
action above `minimum_confidence_for_policy_bounded_response` may execute without
a human. That makes the confidence score an authorization signal, so where it
came from matters.

`AnalystDecision.confidence_source` records it: `deterministic` when AutoSIEM
derived the score from the evidence, `model` when a language model reported it
about its own output. **Only a deterministic score can open the autonomous
gate.** A model-reported score always falls back to human approval, however high
it is — a model asserting 0.99 is not evidence, and raising the threshold would
only invite it to assert 0.999. Otherwise a model could authorize its own
containment action simply by claiming certainty.

The source is carried on the decision, written to the investigation audit log
(`action_proposed ... confidence_source=model`), and persisted with the
investigation, so an auditor can see which one drove any given case.

The SOAR planner scores separately, from the severity and weight of the findings
behind the incident, and its ceiling (`soar.MAX_PLAN_CONFIDENCE`, 0.90) sits
below the autonomous threshold by construction. Matching a runbook is therefore
never on its own enough to open the gate, whatever the alert volume.

## Valid action targets

Risk is only half of what makes a proposal safe; the other half is *what* it
points at. Every action declares the target kinds it accepts in
`policy.ActionPolicy.target_kinds`, and `AutomationPolicy.validate_target`
enforces it on every path that can create a proposal — the analyst runtime, the
SOAR planner, and the pipeline merge.

| Action | Valid targets |
|---|---|
| `isolate_host` | `host:` (shared infrastructure such as a VPN concentrator is excluded) |
| `disable_user` | `user:` |
| `block_indicator` | `ip:` / `domain:` / `url:` / hash |
| `notify_channel` | `channel:`, an ATT&CK technique, or an incident |
| `close_incident` | `incident:` |
| `search_related_events`, `enrich_entities`, `create_case_note`, `link_duplicate_alerts` | any entity, an ATT&CK technique, or an incident |

Validation is fail-closed on both sides: an action the policy does not know has
no valid targets, and a target that cannot be classified is rejected rather than
guessed at. Rejections and dropped runbook steps are written to the
investigation audit log with the reason, so nothing disappears silently.

## Why deterministic first?

The runtime keeps a deterministic core as its safe baseline. An optional LLM adapter (see below) can now author the narrative report and propose a decision, but that output is schema-validated, redacted, marked as model-sourced, and still run through the same policy gates before any action can execute — and a model-reported confidence can never satisfy the autonomous gate (see above). When no model is configured or a call fails, behaviour falls back to this local deterministic baseline automatically, so the pipeline never breaks.

## Optional LLM adapter

Implemented in `src/autosiem/llm.py`. Backends are loaded lazily via stdlib `urllib` only, so no extra third-party dependency is required.

Backends (set `AUTOSIEM_LLM_BACKEND`):

- `none` — deterministic local fallback (default)
- `ollama` — self-hosted Ollama `/api/chat`
- `openai` — hosted OpenAI-compatible `/v1/chat/completions`
- `openai_compat` — any OpenAI-compatible `/v1/chat/completions` endpoint (LM Studio, vLLM, TGI, llama.cpp). Defaults to LM Studio at `http://localhost:1234/v1`.

Environment variables:

- `AUTOSIEM_LLM_BACKEND` (`none` | `ollama` | `openai` | `openai_compat`). If unset but `AUTOSIEM_LLM_URL` is set, the backend is inferred as `openai_compat`. Explicit `none` is respected.
- `AUTOSIEM_LLM_MODEL`
- `AUTOSIEM_LLM_URL` (e.g. `http://localhost:1234/v1` for LM Studio, or Ollama's `http://localhost:11434`)
- `AUTOSIEM_LLM_API_KEY` (only needed if your server requires one)
- `AUTOSIEM_LLM_MASK_PII` (`1` default: also masks IPs/emails)
- `AUTOSIEM_LLM_CONTEXT_WINDOW` (optional token budget; prompt content is fitted/truncated to fit)
- `AUTOSIEM_LLM_MAX_TOKENS` (optional max completion length)
- `AUTOSIEM_LLM_TEMPERATURE` (optional sampling temperature, `0` allowed)
- `AUTOSIEM_LLM_TOP_P` (optional nucleus sampling; sent to `openai_compat`/`openai`, mapped to `options.top_p` for Ollama)

The config is server-agnostic: any OpenAI-compatible endpoint (LM Studio, Ollama, vLLM, TGI, llama.cpp) works from a URL plus an optional API key and context limits.

Enable from the CLI:

```bash
AUTOSIEM_LLM_BACKEND=ollama AUTOSIEM_LLM_MODEL=llama3.2 PYTHONPATH=src python -m autosiem.cli demo --llm --no-save
```

With LM Studio (OpenAI-compatible server already running):

```bash
AUTOSIEM_LLM_BACKEND=openai_compat AUTOSIEM_LLM_MODEL=local-model-name AUTOSIEM_LLM_URL=http://localhost:1234/v1 PYTHONPATH=src python -m autosiem.cli demo --llm --no-save
```

Safety properties:

- secrets and tokens are always redacted before leaving the process
- responses are safely parsed and schema-validated
- LLM decisions still flow through the automation policy (high-impact actions remain approval-gated)
- any failure falls back to the deterministic local investigator

Suppression and triage are deterministic, not AI-controlled: suppression rules are applied at ingest (before incident building), and incident triage fields (status/assignee/resolution/comments) are managed through the CLI, API, or UI and audited. The AI analyst may propose decisions and draft case notes, but it cannot suppress findings or transition incidents on its own.

LLM outputs are always:

- schema-validated
- evidence-cited (prompted to ground claims in provided findings)
- policy-checked
- audit-logged
- human-approved for high-impact response

## Phase 4 building blocks (built and wired)

The copilot-facing modules are implemented, unit-tested, and **wired into the CLI/API/pipeline** (commit `0d3f5c8`):

- **RAG** (`autosiem.rag`) — `RunbookIndex` loads `.md` runbooks (parsed for ATT&CK tags) into keyword + TF-IDF-lite retrievers; `RagEngine.augment_prompt(incident)` appends the top runbooks to the prompt sent to the investigator/LLM — wired into `AutoSIEMPipeline`.
- **Natural-language search** (`autosiem.querygen`) — `translate_query("failed logins by alice last 24h")` → canonical DSL dict → `to_cli_flags()` for `cli events`/`incidents` — wired as CLI `search-nl` + `GET /api/search-nl`.
- **Rule assistant** (`autosiem.rule_assistant`) — `draft_rule(description, techniques)` returns a rule dict; `write_rule_file` + `generate_test_cases` ship it with a `tests/test_rules.py` entry — wired as CLI `rule-new`.
- **Feedback learning** (`autosiem.feedback`) — `FeedbackEngine` records analyst approve/reject/comment decisions and derives per-rule trust weights that can de-prioritize noisy rules — wired into `AutoSIEMPipeline`.
- **SOAR planner** (`autosiem.soar`) — `SoarPlanner.recommend(incident, findings)` returns an ordered, approval-gated plan (runbook steps + proposed actions) — merged into `Investigation.action_proposals` in `AutoSIEMPipeline`. Runbooks are keyed by ATT&CK technique, but a technique is a *scope*, not something you can act on: steps that operate on a concrete thing are resolved against the incident's entities (see below), and dropped with a stated reason when the incident holds nothing of the required kind.
- **Update job** (`autosiem.update_job`) — `UpdateJob.run_once()` refreshes bundled rule/threat-intel content from configured URLs and writes an `UpdateReport`; `schedule()` runs it on a timer — wired as CLI `update`.
- **Redaction** now lives in its own module: `autosiem.redaction` deepens per-class policy (labelled secrets, AKIA/SSH keys, Luhn-checked card numbers, SSN, IP/email/IPv6). `llm.py` re-exports `Redactor`, so `autosiem.llm.Redactor` still works unchanged.

All wiring was completed in commit `0d3f5c8` (Phase 3/4 wiring) and confirmed in `033d92d` (docs refresh).

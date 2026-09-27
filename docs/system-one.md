# The System One decision layer

Why it exists, what it is allowed to do, and how to judge whether it earns its
place. Configuration lives in the README; this is the design record.

## What a System One model is

A model that answers **typed questions** about a **state** and returns values
with probability distributions, rather than text. Three primitives:

- **noul** — a yes/no question answered with P(true). No confidence field: the
  probability *is* the answer.
- **choice** — one of several named options, with a probability per option and a
  confidence derived from how concentrated that distribution is.
- **score** — an ordered scale, same distribution and confidence treatment.

Every question is answered in one call. There is no prose to parse, no JSON to
repair, and no prompt-injection surface in the output, because the output space
is fixed by the question.

## Why AutoSIEM uses one

The existing pipeline already produces a verdict: rules fire, UEBA scores
behaviour, risk aggregates, correlation builds an incident. What it does not
produce is a second, independent opinion on *whether the whole thing matters*,
cheap enough to run on every incident.

The generative LLM layer can give that opinion, but it costs seconds and dollars,
it writes prose that has to be parsed and schema-validated, and it is the wrong
tool for a five-way classification. Separating the two jobs is the point:

- **System One classifies.** Fast, typed, probabilistic, on every incident.
- **The LLM explains.** Slow, narrative, on the incidents that deserve it.

The fourth question, `needs_llm_analysis`, is the hinge between them.

## What it is not allowed to do

This is the part that matters. The layer is **advisory**:

- It never changes `Incident.severity` or `risk_score`.
- It never marks an action proposal executable, and never removes an approval
  requirement. `autosiem.policy` is untouched by it.
- A disagreement with the deterministic severity is *recorded as a note* on the
  incident and counted in a metric. The engine's verdict stands.
- A provider failure, a malformed answer, a missing key, an uninstalled model, or
  no configuration at all all degrade to the same thing: the behaviour of a
  deployment without the feature.

`tests/test_system_one_pipeline.py::test_a_confident_model_cannot_lower_a_policy_gate`
runs the demo kill chain twice, once with a model insisting everything is benign,
and asserts that every proposal's `approval_required` is identical. That test is
the reason the layer is allowed to exist.

## Where it sits

```
events
  ↓ normalize → rules + threat intel → UEBA
  ↓ suppression → feedback weighting → enrichment
  ↓ build_incidents (24h entity graph)
  ↓ System One decision engine          ← advisory annotation
  │    ├── Jev (hosted)
  │    └── Laya (local fallback)
  ↓ normalized DecisionResult
  ↓ existing policy / safety gates      ← still authoritative
  ↓ optional generative LLM analysis    ← may be gated by needs_llm_analysis
  ↓ incident output + persistence
```

## Module map

| File (`src/autosiem/system_one/`) | Responsibility |
|---|---|
| `types.py` | `DecisionQuestion` / `DecisionAnswer` / `DecisionResult`, and the strict normalizer both providers share |
| `questions.py` | The four security questions and the whitelisting, redacting state builder |
| `config.py` | Every environment variable and threshold, with documented defaults |
| `providers.py` | `DecisionProvider` protocol, `JevDecisionProvider`, `LayaDecisionProvider`, `DisabledDecisionProvider` |
| `engine.py` | Provider selection, fallback, thresholds, metrics, disposition |
| `baseline.py` | The deterministic AutoSIEM path expressed as a comparable provider |
| `evaluation.py` | The scoring harness: accuracy, confusion, Brier, ECE, latency, cost |

## Design decisions worth knowing

**`decide` is synchronous.** The reference sketch for this subsystem used
`async def`. `AutoSIEMPipeline.process_lines` and every storage call beneath it
are synchronous, so an async provider would mean starting an event loop inside a
sync pipeline for one HTTP request. Matching the repository beat matching the
sketch. Providers are small; an async variant can be added later without
touching callers.

**Jev is reached with `urllib`, not the TypeSafe SDK.** `src/autosiem` has no
runtime dependencies. That rule is why the Sigma parser and the SigV4 signer are
hand-rolled, and it applies here too. The endpoint is one POST with a JSON body.

**Laya is a real optional extra.** `pip install '.[laya]'` pulls torch and a
421M-parameter checkpoint. It is imported lazily, so configuring Laya as a
fallback costs nothing until the fallback actually fires.

**Malformed answers raise.** A provider that returns a probability of 1.4, an
option that was not offered, an answer to a question that was not asked, or a
missing answer produces `DecisionInvalid`. It is never coerced into a usable
classification, because a silently-defaulted "benign" is a detection gap wearing
a valid shape.

**Three states are kept distinct**, because collapsing them is how a decision
layer becomes a liability:

| State | Meaning | What happens |
|---|---|---|
| provider failed | unreachable, timeout, invalid response | try the fallback, then give up quietly |
| answered, not confidently | a real answer below threshold | recorded, carries no weight, **no fallback** by default |
| answered confidently | at or above the accept threshold | recorded as an accepted signal |

**A noul's certainty has a floor of 0.5.** Certainty for a yes/no answer is
P(selected side), which cannot be below a coin flip. Only a choice or score
confidence can push an assessment below the review threshold, which is why the
disposition is the minimum of the `malicious` and `severity` certainties rather
than the maximum or the mean.

## Privacy

For the hosted provider, the state is a **whitelist**:

- Summaries, not dumps: counts, named UEBA signals, rule ids, entity kinds, the
  deterministic severity and risk score, the tactic list.
- Only the named fields in `RAW_FIELD_WHITELIST` are copied from an event.
- Any field name containing `token`, `secret`, `password`, `credential`,
  `api_key`, `authorization`, `cookie` or `session` is never copied.
- Every string is passed through `autosiem.redaction`. IPv4 addresses are first
  replaced by their **class**, `<IP:internal>` (RFC 1918, carrier-grade NAT,
  loopback, link-local) or `<IP:public>`, so the address never leaves but the
  single most useful fact about it does. Redaction alone turned every address into
  `<IP>`, which made an office login and an attacker's login indistinguishable.
  The RFC 5737 documentation ranges count as public, deliberately.
- `AUTOSIEM_DECISION_MAX_FINDINGS` / `MAX_EVENTS` cap the size.

Building this found two real gaps in the shared redactor, both now fixed:
`Authorization: Bearer <token>` had its label masked but its token left behind
(the labelled-secret pattern consumed the word `Bearer`, removing the anchor the
high-entropy pattern needed), and modern `sk-live-…` / `sk-proj-…` keys did not
match a pattern that stopped at the first hyphen. Recorded against SEC-011.

A demo incident builds a state of roughly 10 KB, which is the input-token cost
driver for Jev.

## Evaluation

`cli evaluate-decisions` scores the deterministic path, Jev and Laya on the same
labelled incidents with the same questions. Notes on the metrics:

- **Brier score** is the honest measure for the probabilistic `malicious` call;
  accuracy throws the probability away. 0.25 is what always answering 0.5 gets.
- **ECE** is reported with its bin count and sample size, because ECE is
  sensitive to binning and a bare number is not comparable across runs.
- **The deterministic path scores 100% on severity by construction**, since it
  reads the severity out of the state it was given. That is a property of the
  baseline, not a result; the interesting columns for it are Brier and ECE.
- **Cost is only computed from reported usage.** Jev reports input and output
  tokens; Laya reports none, and is shown as no cost rather than a guess.
- Unavailable providers are reported with the reason and excluded, never
  simulated.

There is no bundled labelled dataset. The format is deliberately simple so a
real one can be added:

```json
{"id": "case-1", "state": { ... }, "labels": {"malicious": true, "severity": "high", "action": "investigate"}}
```

Build `state` with `autosiem.system_one.build_state(incident, findings, events=...)`
so the cases carry exactly what the pipeline would have sent.

## Persistence

One row per incident in `system_one_decisions`, keyed `(tenant_id, incident_id)`
like every other tenant-scoped table. It stores the provider, model, disposition,
the selected classifications with their probabilities, latency, whether fallback
was used, and whether the generative LLM ran. The **state is not stored**: it is
derivable from the events and findings already persisted, and a second copy would
duplicate event content into another table.

An unavailable assessment is still written. "The provider was asked and did not
answer" is what an operator needs when a dashboard shows no decision, and it is
what the fallback-rate figure is computed from.

## Limitations

- No labelled AutoSIEM dataset ships with this, so no accuracy claim is made for
  either model on AutoSIEM's own data. The harness exists to produce that claim
  once a dataset does.
- The decision engine's in-process metrics are per-process. The durable view is
  the `system_one_decisions` table via `cli decisions`.
- Laya's device argument is not documented upstream, so the provider attempts
  `laya.load(model, device=...)` and falls back to `laya.load(model)` on
  `TypeError` rather than assuming a signature.
- Jev usage-based cost uses the published price as a constant. If TypeSafe
  repriced, the constant in `evaluation.py` is the single place to change.
- Prompt wording has not been tuned against real incidents; the questions are
  written to be short and concrete, which is what these models want, but no
  A/B evidence backs the exact phrasing yet.

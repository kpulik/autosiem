# System One evaluation set

A labelled set of security incidents for `cli evaluate-decisions`, so the
deterministic AutoSIEM path, Jev and Laya can be compared on the same cases.

> **Status: SELF-REVIEWED, not independently reviewed.** 39 scenarios written and
> labelled by Claude on 2026-09-27, then checked for evidence visibility and
> consistency (see `review_log` in `scenarios.json`). The author reviewing their
> own labels is not an independent check: scores against this set measure
> agreement with one careful labeller, not ground truth.

## Files

| File | What it is | Edit it? |
|---|---|---|
| `scenarios.json` | Source of truth: raw events, labels, rationale per scenario | **Yes** - this is where labels live |
| `REVIEW.md` | Reviewer sheet: proposed label beside the engine's verdict | No, regenerated |
| `cases.jsonl` | Built cases, the input to the harness | No, regenerated and gitignored |

## Build and run

```bash
PYTHONPATH=src python3 scripts/build_system_one_cases.py
PYTHONPATH=src python3 -m autosiem.cli evaluate-decisions \
  --cases evals/system_one/cases.jsonl --json-out results.json
```

The builder runs every scenario through the real `AutoSIEMPipeline` on its own
and builds the state with the same `build_state` call the pipeline uses, so a
case carries exactly what a provider would be sent. It fails if a scenario
produces no incident, because System One never sees events that did not become
one.

## How to review

1. Open `REVIEW.md`. Start with the rows marked `low` confidence, then `medium`.
2. For each scenario, read the events in `scenarios.json` and ask: *given only
   what the model can see, is the proposed label right?*
3. Change `labels` in `scenarios.json`, and set `"review": "approved"` (or
   `"changed"`) on each scenario you have checked.
4. When every scenario is reviewed, change the top-level `status`.
5. Rebuild and re-run.

A ⚑ in `REVIEW.md` means the proposed severity differs from the engine's. That
is the point, not an error: labels that always matched the engine would let the
deterministic baseline score 100% by construction.

## Labelling guide

Labels describe **what actually happened**, judged from evidence the model can
see. Never copy the engine's verdict.

**`malicious`** - `true` if the activity is attacker-driven, or a real misuse or
policy violation someone must act on. `true` even when contained (a quarantined
phishing email is still malicious). `false` for expected administration,
automation, and ordinary user behaviour.

**`severity`** - the real-world impact:

| Level | Meaning |
|---|---|
| informational | No impact. Benign activity the rules happened to match. |
| low | Minor, contained, or unsuccessful: a failed brute force, one scanner probe. |
| medium | Real but early or contained: discovery, one account, no confirmed impact. |
| high | Privileged access, credential theft, lateral movement, persistence, a crown-jewel asset. |
| critical | Active damage or organisation-wide impact: ransomware, NTDS theft, confirmed exfiltration. |

**`action`** - what a SOC analyst should do next:

| Action | When |
|---|---|
| suppress | Known-benign pattern. Close with no work. |
| monitor | Nothing to do now, watch for a follow-up. |
| enrich | Cannot judge without more context (asset, identity, deploy log). |
| investigate | A human should work it now. |
| escalate | Active impact, or containment is needed. |

**The evidence rule.** Every label must be defensible from fields that reach the
model: user and host entities, process names, command lines, parent processes,
URLs, user agents, and outcomes. If a benign case is only benign because of
something in the `story` that the model cannot see, the case tests guessing, not
judgement. `visible_evidence` on each scenario names what the label rests on.

`needs_llm_analysis` is deliberately **not labelled**: whether an incident
deserves a narrative write-up is a workflow preference, not a fact about the
incident. The harness only scores questions that carry labels.

## Composition

| | Count |
|---|---|
| True positives | 19 |
| False positives | 15 |
| Ambiguous (labelled by judgement) | 5 |
| `malicious` true / false | 21 / 18 |

Severity labels: critical 4, high 12, medium 2, low 8, informational 13.
Actions: escalate 9, investigate 9, monitor 5, suppress 13, enrich 3.

## Known limitations

- **Small.** 39 cases means one case moves an accuracy figure by about 2.6
  points. Differences under ~10 points between providers are not meaningful here.
- **Skewed on purpose.** The false positives were written to trip rules that the
  engine rates high or critical, because telling those apart is the job. Scores
  on this set are not an estimate of production accuracy.
- **Thin on `medium`.** Only 2 severity labels are `medium`, so medium-vs-high
  confusion is barely measured.
- **Cold baselines.** Each scenario runs on a fresh pipeline, so UEBA signals
  (novelty, off-hours, peer rarity, burst) rarely fire. A production-derived set
  would carry them.
- **Author bias.** The scenarios and labels were written by the same author,
  who also knows the rules. Human review is the correction; a second
  independent labeller would be better.
- **Synthetic.** Real incidents are messier. This set is a way to start, and
  the format is simple so real, redacted incidents can be added the same way.

## Results (2026-09-27, self-reviewed labels, measured on `main` at `a87d806`)

| Path | malicious acc | Brier | ECE | severity acc | action acc | latency |
|---|---|---|---|---|---|---|
| deterministic AutoSIEM | 64.1% | 0.300 | 0.282 | 38.5% | 33.3% | ~0 ms |
| deterministic + identity roles* | 71.8% | 0.236 | | 41.0% | 33.3% | ~0 ms |
| Laya `laya-typed-decisions` 0.3.20 | 53.8% | 0.250 | 0.063 | 28.2% | 17.9% | 710 ms mean, 1106 ms p95 |
| Jev | not run: paid API, declined | | | | | |

\* With the roles an operator would assign to the set's service and admin
accounts (backup, config-management, ci-deploy, vuln-scanner, it-admin,
scm-admin). This shows identity roles (#19) working when configured, not a
generic improvement: 10 benign cases turned down, no real attack touched.

Laya ran locally on an Apple M4 Pro (MPS), four questions per call, about 2,100
input tokens per case. Latency varies with machine load (an earlier run on the
same machine measured 494 ms mean).

Earlier in the day, before #18 split shadow-copy creation out of the critical
NTDS rule, the deterministic path measured 61.5% malicious (Brier 0.321).

**Reading it:**

- **Laya does not discriminate on this set.** Its P(malicious) averaged 0.589 on
  real attacks and 0.585 on benign cases, and it called all 39 malicious. It never
  chose informational or low severity, and never suppress, monitor or enrich.
- **Its good calibration numbers are hollow.** A Brier of 0.250 is exactly what
  always answering 0.5 scores, and a low ECE is easy when every answer sits near
  0.59 and about half are right.
- **Its confidence never exceeded 0.08.** Under AutoSIEM's default thresholds
  (accept 0.75, review 0.5) every Laya answer would be recorded and ignored. The
  engine's design held: a useless signal was kept out of the pipeline.
- **The deterministic path is not good either.** Its malicious Brier (0.300) is
  worse than a coin flip, because a risk score is not a probability, and it asks
  for investigation on 11 of the 13 cases labelled suppress. That is the gap a
  typed-decision model would need to close.
- Consistent with Laya's published caveat: this checkpoint was trained for agent
  observability and invoice processing, and its zero-shot base scored below the
  majority-class baseline on its own benchmark. Security triage is out of domain.

**Input-format check (scratch experiment, not product code):** sending the same
cases as a plain-English summary instead of JSON moved Laya's malicious accuracy
to 66.7%, but P(malicious) still averaged 0.560 on attacks and 0.531 on benign.
The 66.7% vs 61.5% difference is two cases on a 39-case set, which is noise.

**What this does not show:** that Laya is useless in general, or that a model
fine-tuned on security incidents would do this badly. It shows that this
checkpoint, zero-shot on these questions, adds nothing here.

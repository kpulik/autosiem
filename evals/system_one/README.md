# System One evaluation set

A labelled set of security incidents for `cli evaluate-decisions`, so the
deterministic AutoSIEM path, Jev and Laya can be compared on the same cases.

> **Status: DRAFT.** 39 scenarios written and labelled by Claude on 2026-09-27,
> pending human review. Until a person has reviewed the labels, any score
> computed against them measures agreement with Claude's judgement, not
> accuracy.

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

## First baseline (against the draft labels)

The deterministic path, on 2026-09-27, before review:

| Question | Accuracy | Other |
|---|---|---|
| malicious | 61.5% | Brier 0.32 (worse than the 0.25 of always answering 0.5) |
| severity | 38.5% | |
| action | 33.3% | recommends `investigate` for 11 of 13 `suppress` cases |

Recorded to show the harness working and the size of the gap a model would have
to close. Not a result until the labels are reviewed.

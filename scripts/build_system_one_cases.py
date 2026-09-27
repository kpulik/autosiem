#!/usr/bin/env python3
"""Turn the labelled scenarios into evaluation cases, through the real pipeline.

Each scenario in ``evals/system_one/scenarios.json`` is a short list of raw
events plus human labels. This script runs every scenario through
``AutoSIEMPipeline`` **on its own**, so scenarios cannot correlate into each
other, and builds the decision state with the same ``build_state`` call the
pipeline uses. The cases therefore carry exactly what a provider would be sent.

It also refuses to hide problems:

- a scenario that produces **no incident** is an error: System One never sees
  events that did not become an incident, so such a case would test nothing;
- a scenario that produces **more than one** incident is reported, and the
  highest-risk incident is the one labelled;
- the engine's own verdict is written next to the proposed label in the review
  sheet, so a reviewer can see where the rules and the label disagree.

Usage::

    PYTHONPATH=src python3 scripts/build_system_one_cases.py
    PYTHONPATH=src python3 -m autosiem.cli evaluate-decisions --cases evals/system_one/cases.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from autosiem.pipeline import AutoSIEMPipeline  # noqa: E402
from autosiem.rules import load_rules  # noqa: E402
from autosiem.system_one import ACTIONS, SEVERITY_LEVELS, build_state  # noqa: E402

DEFAULT_SCENARIOS = ROOT / "evals/system_one/scenarios.json"
DEFAULT_CASES = ROOT / "evals/system_one/cases.jsonl"
DEFAULT_REVIEW = ROOT / "evals/system_one/REVIEW.md"


def _validate_labels(scenario: dict) -> list[str]:
    problems = []
    labels = scenario.get("labels") or {}
    if not isinstance(labels.get("malicious"), bool):
        problems.append("labels.malicious must be true or false")
    if labels.get("severity") not in SEVERITY_LEVELS:
        problems.append(f"labels.severity must be one of {list(SEVERITY_LEVELS)}")
    if labels.get("action") not in ACTIONS:
        problems.append(f"labels.action must be one of {list(ACTIONS)}")
    if not scenario.get("events"):
        problems.append("no events")
    return problems


def build(scenarios_path: Path) -> tuple[list[dict], list[dict], list[str]]:
    doc = json.loads(scenarios_path.read_text(encoding="utf-8"))
    rules = load_rules(ROOT / "rules")
    cases: list[dict] = []
    rows: list[dict] = []
    errors: list[str] = []
    seen: set[str] = set()

    for scenario in doc["scenarios"]:
        sid = scenario["id"]
        if sid in seen:
            errors.append(f"{sid}: duplicate id")
            continue
        seen.add(sid)
        problems = _validate_labels(scenario)
        if problems:
            errors.extend(f"{sid}: {problem}" for problem in problems)
            continue

        lines = [json.dumps(event) for event in scenario["events"]]
        # A fresh pipeline per scenario: no shared baseline, no cross-scenario
        # correlation. The cost is that UEBA signals rarely fire on a cold
        # baseline, which the README states as a known limitation.
        result = AutoSIEMPipeline(rules).process_lines(lines)
        if not result.incidents:
            errors.append(f"{sid}: produced no incident, so System One would never see it")
            continue
        incident = result.incidents[0]  # sorted by risk, highest first
        related = [f for f in result.findings if f.finding_id in incident.finding_ids]
        event_ids = {f.event_id for f in related}
        events = [e for e in result.events if e.event_id in event_ids]

        cases.append({
            "id": sid,
            "state": build_state(incident, related, events=events),
            "labels": dict(scenario["labels"]),
        })
        rows.append({
            "id": sid,
            "kind": scenario.get("kind", ""),
            "title": scenario.get("title", ""),
            "engine_severity": incident.severity.name.lower(),
            "engine_risk": incident.risk_score,
            "rules": sorted({f.rule_id for f in related}),
            "incidents": len(result.incidents),
            "labels": scenario["labels"],
            "confidence": scenario.get("label_confidence", ""),
            "evidence": scenario.get("visible_evidence", ""),
            "rationale": scenario.get("rationale", ""),
            "review": scenario.get("review", "pending"),
        })
    return cases, rows, errors


def render_review(rows: list[dict], status: str) -> str:
    """A reviewer-facing sheet: proposed label beside the engine's verdict."""
    def label_cell(labels: dict) -> str:
        return f"{'malicious' if labels['malicious'] else 'benign'} / {labels['severity']} / {labels['action']}"

    disagree = [r for r in rows if r["labels"]["severity"] != r["engine_severity"]]
    lines = [
        "# System One evaluation set - label review",
        "",
        f"**Status:** {status}",
        "",
        "Generated by `scripts/build_system_one_cases.py`. Edit labels in "
        "`scenarios.json`, not here; this file is regenerated.",
        "",
        f"- Scenarios: **{len(rows)}**",
        f"- Proposed label severity differs from the engine's: **{len(disagree)}** "
        "(expected: the false alarms are the point)",
        f"- Low-confidence labels, review first: "
        f"**{sum(1 for r in rows if r['confidence'] == 'low')}**",
        "",
        "| id | kind | engine says | proposed label (malicious / severity / action) | conf | rules fired | what the model can see |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        flag = " ⚑" if row["labels"]["severity"] != row["engine_severity"] else ""
        multi = f" ({row['incidents']} incidents)" if row["incidents"] > 1 else ""
        lines.append(
            f"| `{row['id']}` | {row['kind']} | {row['engine_severity']} ({row['engine_risk']}){multi} "
            f"| {label_cell(row['labels'])}{flag} | {row['confidence']} | {', '.join(row['rules'])} "
            f"| {row['evidence']} |"
        )
    lines += [
        "",
        "⚑ = the proposed severity differs from the engine's. That is not an error: a label",
        "that always agreed with the engine would let the deterministic baseline score 100%",
        "by construction and the benchmark would measure nothing.",
        "",
        "## Rationale per case",
        "",
    ]
    for row in rows:
        lines.append(f"- **`{row['id']}`** - {row['title']}. {row['rationale']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build System One evaluation cases from the labelled scenarios.")
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--out", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--review", type=Path, default=DEFAULT_REVIEW)
    args = parser.parse_args()

    cases, rows, errors = build(args.scenarios)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    status = json.loads(args.scenarios.read_text(encoding="utf-8")).get("status", "")
    args.out.write_text("".join(json.dumps(case) + "\n" for case in cases), encoding="utf-8")
    args.review.write_text(render_review(rows, status), encoding="utf-8")
    multi = [row["id"] for row in rows if row["incidents"] > 1]
    print(f"wrote {len(cases)} cases to {args.out.relative_to(ROOT)}")
    print(f"wrote the review sheet to {args.review.relative_to(ROOT)}")
    if multi:
        print(f"note: {len(multi)} scenario(s) produced more than one incident; labelled the highest-risk one: {', '.join(multi)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

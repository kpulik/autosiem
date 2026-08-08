"""Parallel, deterministic event-processing workers.

The caller supplies raw JSONL lines (e.g. from ``examples/events.jsonl``). A
``ParserWorkerPool`` splits the lines into contiguous chunks, normalizes and
detects each chunk with a fresh ``AutoSIEMPipeline`` inside a thread pool, then
merges the chunk results deterministically.

Events and findings keep chunk order. Incidents, reports, and investigations
are aggregates over *all* findings, so the merge rebuilds them once from the
merged findings — this keeps the parallel result equivalent to a serial run.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .ai import Investigator
from .detection import evaluate_rules
from .normalization import normalize, parse_raw_line
from .pipeline import AutoSIEMPipeline, PipelineResult
from .risk import build_incidents
from .rules import load_rules
from .schemas import DetectionRule, Finding, NormalizedEvent
from .soc_runtime import AIAnalystRuntime
from .suppression import SuppressionEngine

# workers.py lives at <repo>/src/autosiem/workers.py, so parents[2] is the repo
# root that contains the default `rules/` directory (the same layout cli.py uses).
DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules"


def normalize_line(line: str) -> NormalizedEvent:
    """Normalize a single raw JSONL line into a NormalizedEvent."""
    return normalize(parse_raw_line(line))


def detect_event(event: NormalizedEvent, rules: list[DetectionRule]) -> list[Finding]:
    """Run the stateless rule-detection stage for one event."""
    return evaluate_rules(event, rules)


def suppress_findings(
    findings: list[Finding], engine: SuppressionEngine
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Apply a suppression engine to a list of findings."""
    return engine.apply(findings)


def _split_chunks(lines: list[str], workers: int) -> list[list[str]]:
    """Split ``lines`` into ``workers`` contiguous chunks (deterministic)."""
    if not lines:
        return []
    workers = max(1, min(workers, len(lines)))
    base, extra = divmod(len(lines), workers)
    chunks: list[list[str]] = []
    start = 0
    for index in range(workers):
        size = base + (1 if index < extra else 0)
        chunks.append(lines[start : start + size])
        start += size
    return chunks


class ParserWorkerPool:
    """Deterministically process raw JSONL lines, possibly in parallel."""

    def __init__(
        self,
        workers: int = 4,
        rules: list[DetectionRule] | None = None,
        suppression_engine: SuppressionEngine | None = None,
    ) -> None:
        self.workers = max(1, workers)
        self.rules = rules if rules is not None else load_rules(DEFAULT_RULES)
        self.suppression_engine = suppression_engine

    def process_lines(self, lines: list[str]) -> PipelineResult:
        """Split ``lines`` into contiguous chunks and process each with a pipeline.

        Each chunk is handled by a freshly constructed ``AutoSIEMPipeline`` (with
        this pool's rules and suppression engine) in a thread pool. ``map`` is used
        so the merged chunk results arrive in deterministic (chunk) order.
        """
        chunks = _split_chunks(lines, self.workers)
        if not chunks:
            return PipelineResult()

        def _run(chunk: list[str]) -> PipelineResult:
            pipeline = AutoSIEMPipeline(self.rules, suppression_engine=self.suppression_engine)
            return pipeline.process_lines(chunk)

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            chunk_results = list(executor.map(_run, chunks))
        return _merge_results(chunk_results)


def _merge_results(chunk_results: list[PipelineResult]) -> PipelineResult:
    """Merge per-chunk results deterministically.

    Events, findings, and suppressed records are concatenated in chunk order.
    Incidents/reports/investigations are aggregates of every finding, so they are
    rebuilt once from the merged findings (matching what a serial run produces).
    """
    merged = PipelineResult()
    for result in chunk_results:
        merged.events.extend(result.events)
        merged.findings.extend(result.findings)
        merged.suppressed.extend(result.suppressed)

    merged.incidents = build_incidents(merged.findings)
    investigator = Investigator()
    runtime = AIAnalystRuntime()
    for incident in merged.incidents:
        merged.reports[incident.incident_id] = investigator.explain(incident, merged.findings)
        merged.investigations[incident.incident_id] = runtime.investigate(incident, merged.findings)
    return merged


def process_lines(lines: list[str], workers: int = 4) -> PipelineResult:
    """Convenience wrapper: build a default pool and process ``lines``."""
    return ParserWorkerPool(workers=workers).process_lines(lines)
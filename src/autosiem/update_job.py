"""Hourly update job: reload rules, recompute coverage, refresh threat intel.

Designed to run as a daemon thread inside the SIEM process. ``run_once`` does
one full refresh cycle and returns a report; ``schedule``/``start`` provide the
thread wrapper. Nothing runs on import or at construction time, so tests and
embedders stay in full control of when updates happen.
"""
from __future__ import annotations

import json
import threading
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .coverage import coverage_report
from .rules import load_rules
from .threat_intel import (
    default_intel_state,
    load_stix_bundle,
    parse_stix_bundle,
    save_intel_state,
)

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

INTEL_FETCH_TIMEOUT_SECONDS = 30


@dataclass(slots=True)
class UpdateReport:
    """Outcome of one update cycle."""

    rules_loaded: int = 0
    coverage: dict[str, Any] = field(default_factory=dict)
    intel_refreshed: bool = False
    messages: list[str] = field(default_factory=list)


class UpdateJob:
    """Reloads rules + intel and recomputes coverage on demand."""

    def __init__(
        self,
        rules_dir: str | Path = DEFAULT_RULES_DIR,
        db_path: str | Path | None = None,
        intel_url: str | None = None,
        intel_path: str | Path | None = None,
        intel_state_path: str | Path | None = None,
    ) -> None:
        self.rules_dir = Path(rules_dir)
        self.db_path = Path(db_path) if db_path is not None else None
        self.intel_url = intel_url
        self.intel_path = Path(intel_path) if intel_path is not None else None
        self.intel_state_path = Path(intel_state_path) if intel_state_path is not None else None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # -- one-shot cycle ----------------------------------------------------

    def run_once(self) -> UpdateReport:
        report = UpdateReport()

        rules = load_rules(self.rules_dir)
        report.rules_loaded = len(rules)
        report.coverage = coverage_report(rules)

        indicators = self._load_indicators(report)
        if indicators:
            state_path = self.intel_state_path or default_intel_state(self.db_path or "autosiem.db")
            save_intel_state(state_path, indicators)
            report.intel_refreshed = True
            report.messages.append(f"intel refresh: {len(indicators)} indicator(s) -> {state_path}")

        report.messages.append(
            f"coverage: {report.coverage.get('unique_techniques', 0)} unique techniques across {report.rules_loaded} rules"
        )
        return report

    def _load_indicators(self, report: UpdateReport) -> list[Any]:
        """Fetch indicators from intel_url or intel_path; report failures."""
        if self.intel_url is not None:
            try:
                with urllib.request.urlopen(self.intel_url, timeout=INTEL_FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310 (network is the point of this job)
                    data = json.loads(response.read().decode("utf-8"))
                return parse_stix_bundle(data)
            except Exception as exc:  # network/json failures must not kill the job
                report.intel_refreshed = False
                report.messages.append(f"intel refresh failed: {exc}")
                return []
        if self.intel_path is not None:
            try:
                return load_stix_bundle(self.intel_path)
            except Exception as exc:
                report.intel_refreshed = False
                report.messages.append(f"intel refresh failed: {exc}")
                return []
        return []

    # -- threading ---------------------------------------------------------

    def schedule(self, interval_hours: float = 1.0) -> threading.Thread:
        """Create (but do NOT start) a daemon thread that runs periodic updates.

        The caller starts it when they want; nothing runs on construction.
        """
        self._thread = threading.Thread(
            target=self.periodic,
            kwargs={"interval_hours": interval_hours},
            name="autosiem-update-job",
            daemon=True,
        )
        return self._thread

    def start(self, interval_hours: float = 1.0) -> threading.Thread:
        thread = self.schedule(interval_hours)
        thread.start()
        return thread

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def periodic(self, interval_hours: float) -> None:
        """Run ``run_once`` every ``interval_hours`` until stopped."""
        while not self._stop_event.is_set():
            self.run_once()
            self._stop_event.wait(interval_hours * 3600.0)


def run_update(
    rules_dir: str | Path = DEFAULT_RULES_DIR,
    db_path: str | Path | None = None,
    intel_url: str | None = None,
    intel_path: str | Path | None = None,
    intel_state_path: str | Path | None = None,
) -> UpdateReport:
    """Convenience: run one update cycle and return the report."""
    return UpdateJob(
        rules_dir=rules_dir,
        db_path=db_path,
        intel_url=intel_url,
        intel_path=intel_path,
        intel_state_path=intel_state_path,
    ).run_once()

"""Update job: reload rules, recompute coverage, refresh threat intel and ATT&CK.

Designed to run as a daemon thread inside the SIEM process. ``run_once`` does
one full refresh cycle and returns a report; ``schedule``/``start`` provide the
thread wrapper. Nothing runs on import or at construction time, so tests and
embedders stay in full control of when updates happen.

Every network step is opt-in and off by default: rules are always re-read from
disk, threat intel is fetched only when an ``intel_url``/``intel_path`` is given,
and the ATT&CK matrix is refreshed only when ``refresh_attack`` is set.
"""
from __future__ import annotations

import json
import threading
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .attack_matrix import (
    AttackMatrix,
    AttackMatrixUnavailable,
    Fetcher,
    default_attack_index,
    load_matrix_file,
    refresh_index,
)
from .coverage import coverage_report
from .kev import default_kev_state, refresh_kev
from .net import require_https
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
    #: ATT&CK version the coverage figures were computed against.
    attack_version: str = ""
    #: Newest version MITRE publishes, when a refresh was attempted.
    attack_latest: str = ""
    attack_refreshed: bool = False
    #: CISA KEV catalogue version the cache holds, when a refresh was attempted.
    kev_version: str = ""
    kev_refreshed: bool = False
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
        attack_index_path: str | Path | None = None,
        refresh_attack: bool = False,
        attack_version: str | None = None,
        attack_fetch: Fetcher | None = None,
        kev_path: str | Path | None = None,
        refresh_kev_catalog: bool = False,
        kev_fetch: Fetcher | None = None,
    ) -> None:
        self.rules_dir = Path(rules_dir)
        self.db_path = Path(db_path) if db_path is not None else None
        self.intel_url = intel_url
        self.intel_path = Path(intel_path) if intel_path is not None else None
        self.intel_state_path = Path(intel_state_path) if intel_state_path is not None else None
        self.attack_index_path = Path(attack_index_path) if attack_index_path is not None else None
        self.refresh_attack = refresh_attack
        #: Pin a specific ATT&CK release instead of tracking the newest.
        self.attack_version = attack_version
        #: Injected in tests so the suite never touches the network.
        self.attack_fetch = attack_fetch
        self.kev_path = Path(kev_path) if kev_path is not None else None
        self.refresh_kev_catalog = refresh_kev_catalog
        self.kev_fetch = kev_fetch
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # -- one-shot cycle ----------------------------------------------------

    def run_once(self) -> UpdateReport:
        report = UpdateReport()

        rules = load_rules(self.rules_dir)
        report.rules_loaded = len(rules)
        report.coverage = coverage_report(rules, matrix=self._attack_matrix(report))
        report.attack_version = str(report.coverage.get("matrix", {}).get("attack_version", ""))

        self._refresh_kev(report)
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

    def _attack_index_dest(self) -> Path:
        """Where a refreshed index is written.

        Never the copy inside the installed package: that would make an
        installed wheel diverge from what was built and breaks read-only
        installs. Beside the database instead, matching the intel state file.
        """
        if self.attack_index_path is not None:
            return self.attack_index_path
        return default_attack_index(self.db_path or "autosiem.db")

    def _attack_matrix(self, report: UpdateReport) -> AttackMatrix | None:
        """Refresh the ATT&CK index if asked, and report coverage against it.

        Returns None when there is nothing local to use, which leaves
        ``coverage_report`` on the matrix vendored in the package.
        """
        if not self.refresh_attack and self.attack_index_path is None:
            return None

        dest = self._attack_index_dest()
        if self.refresh_attack:
            try:
                result = refresh_index(
                    dest, version=self.attack_version, fetch=self.attack_fetch
                )
                report.attack_refreshed = result.refreshed
                report.attack_latest = result.latest_version
                report.messages.append(result.message)
            except Exception as exc:  # a flaky feed must not fail the whole cycle
                report.attack_refreshed = False
                report.messages.append(f"attack refresh failed: {exc}")

        try:
            return load_matrix_file(dest)
        except AttackMatrixUnavailable:
            # Nothing refreshed yet; the vendored matrix still answers.
            return None

    def _refresh_kev(self, report: UpdateReport) -> None:
        """Refresh the CISA known-exploited catalogue, if asked.

        Cached beside the database rather than vendored: KEV gains entries
        weekly, and a stale copy would report "not known exploited" for a CVE
        added last Tuesday, which is worse than reporting nothing.
        """
        if not self.refresh_kev_catalog:
            return
        dest = self.kev_path or default_kev_state(self.db_path or "autosiem.db")
        try:
            result = refresh_kev(dest, fetch=self.kev_fetch)
            report.kev_refreshed = result.refreshed
            report.kev_version = result.catalog_version
            report.messages.append(result.message)
        except Exception as exc:  # a flaky feed must not fail the whole cycle
            report.kev_refreshed = False
            report.messages.append(f"kev refresh failed: {exc}")

    def _load_indicators(self, report: UpdateReport) -> list[Any]:
        """Fetch indicators from intel_url or intel_path; report failures."""
        if self.intel_url is not None:
            try:
                # Indicators are bare match strings with no signature, so the
                # transport is the only integrity check there is (SEC-017).
                url = require_https(self.intel_url, what="threat intel")
                with urllib.request.urlopen(url, timeout=INTEL_FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310 (network is the point of this job)
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
    attack_index_path: str | Path | None = None,
    refresh_attack: bool = False,
    attack_version: str | None = None,
    kev_path: str | Path | None = None,
    refresh_kev_catalog: bool = False,
) -> UpdateReport:
    """Convenience: run one update cycle and return the report."""
    return UpdateJob(
        rules_dir=rules_dir,
        db_path=db_path,
        intel_url=intel_url,
        intel_path=intel_path,
        intel_state_path=intel_state_path,
        attack_index_path=attack_index_path,
        refresh_attack=refresh_attack,
        attack_version=attack_version,
        kev_path=kev_path,
        refresh_kev_catalog=refresh_kev_catalog,
    ).run_once()

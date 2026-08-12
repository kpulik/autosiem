"""Sync detection content from the SigmaHQ community ruleset.

SigmaHQ publishes curated rule bundles as release assets, so one HTTPS request
and the stdlib ``zipfile`` module is the whole transport. No git, no third-party
dependency.

The hard part is not fetching, it is being honest about what was imported.
Parsing a rule is not the same as being able to run it: most SigmaHQ rules match
on Windows event fields (``EventID``, ``TargetObject``, ``ParentImage``,
``TargetFilename``) that AutoSIEM's normalized event model does not populate.
Such a rule imports cleanly, contributes its ATT&CK technique to the coverage
report, and then never fires. Importing on "it parsed" would inflate coverage
with detections that cannot detect, which is the same dishonesty as counting
watchlist gaps as full-matrix coverage.

So every candidate lands in exactly one bucket, and the report states all three:

``imported``          parses, and every field it matches on is one AutoSIEM fills
``not_applicable``    parses, but needs fields the event model does not have
``unsupported_syntax`` the zero-dependency Sigma subset parser cannot read it

``not_applicable`` carries a histogram of the missing fields, which turns "why
is coverage low" into a ranked list of what the normalizer would have to learn
next.

Synced rules are written outside ``rules/`` on purpose: that directory is the
curated set this project authors, and ``tests/test_rules.py`` requires a
positive and negative case for every rule in it. Third-party content does not
get to bypass that gate by being dropped in the same folder.
"""
from __future__ import annotations

import dataclasses
import io
import json
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .net import require_https
from .schemas import DetectionRule, NormalizedEvent
from .sigma import SigmaParseError, parse_sigma_yaml, sigma_to_rule

RELEASES_URL = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
USER_AGENT = "autosiem-sigma-sync"
FETCH_TIMEOUT_SECONDS = 300

#: SigmaHQ ships several curated bundles; ``core`` is the highest-signal one.
RULESETS = ("sigma_core.zip", "sigma_core+.zip", "sigma_core++.zip", "sigma_all_rules.zip")
DEFAULT_RULESET = "sigma_core.zip"

#: Written alongside synced rules so a sync is auditable after the fact.
SYNC_MANIFEST = "_sync.json"

Fetcher = Callable[[str], bytes]


def matchable_fields() -> set[str]:
    """Top-level event fields a rule can match on.

    Read off the ``NormalizedEvent`` dataclass rather than hardcoded, so
    teaching the normalizer a new field widens what can be imported without
    anyone remembering to edit a list here. ``raw`` is excluded because it is
    handled separately as a ``raw.<field>`` prefix.
    """
    names = {item.name for item in dataclasses.fields(NormalizedEvent)}
    names.discard("raw")
    return names


def default_sigma_dir(db_path: str | Path) -> Path:
    """``<db>.sigma/``, matching the ``<db>.intel.json`` convention."""
    path = Path(db_path)
    return path.with_name(path.stem + ".sigma")


@dataclass(frozen=True, slots=True)
class SigmaRelease:
    tag: str
    ruleset: str
    url: str
    published: str


@dataclass
class SigmaSyncReport:
    """What one sync actually did, in terms that can be checked."""

    release: str = ""
    ruleset: str = ""
    candidates: int = 0
    imported: int = 0
    not_applicable: int = 0
    unsupported_syntax: int = 0
    techniques: list[str] = field(default_factory=list)
    missing_fields: dict[str, int] = field(default_factory=dict)
    syntax_samples: list[str] = field(default_factory=list)
    destination: str = ""

    def summary(self) -> str:
        return (
            f"SigmaHQ {self.release} ({self.ruleset}): {self.candidates} rules examined, "
            f"{self.imported} imported, {self.not_applicable} need fields the event model "
            f"does not populate, {self.unsupported_syntax} unsupported syntax"
        )


def _default_fetch(url: str) -> bytes:
    request = urllib.request.Request(
        require_https(url, what="SigmaHQ rules"), headers={"User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
        return bytes(response.read())


def latest_release(ruleset: str = DEFAULT_RULESET, fetch: Fetcher | None = None) -> SigmaRelease:
    """Resolve the newest published release and the requested bundle asset."""
    fetcher = fetch or _default_fetch
    payload = json.loads(fetcher(RELEASES_URL))
    assets = {asset["name"]: asset for asset in payload.get("assets", [])}
    if ruleset not in assets:
        available = ", ".join(sorted(assets)) or "none"
        raise ValueError(f"SigmaHQ release {payload.get('tag_name')} has no asset {ruleset!r}; has: {available}")
    asset = assets[ruleset]
    return SigmaRelease(
        tag=str(payload.get("tag_name", "")),
        ruleset=ruleset,
        url=str(asset["browser_download_url"]),
        published=str(payload.get("published_at", ""))[:10],
    )


def selection_field_names(selection: Any, into: set[str]) -> None:
    """Collect every event field a compiled selection reads."""
    if isinstance(selection, dict):
        for key, value in selection.items():
            text = str(key)
            if text.startswith("__") or text in {"any_of", "all_of"}:
                selection_field_names(value, into)
                continue
            into.add(text.split(".", 1)[0])
    elif isinstance(selection, list):
        for item in selection:
            selection_field_names(item, into)


def has_unrepresentable_negation(selection: Any) -> bool:
    """True when a ``not`` filter degraded into comparing against a dict repr.

    ``sigma._negate_expected`` can express ``not equals`` and ``not in``, but the
    engine has no ``not_endswith``/``not_contains``, so an operator-style filter
    falls back to ``{"not_equals": str(<dict>)}``. That comparison can never be
    true, which silently turns the filter into a no-op and makes the rule fire
    more broadly than its author intended.

    Those rules are counted as unsupported rather than imported: a detection
    whose exclusion clause does nothing is not the detection that was written.
    """
    if isinstance(selection, dict):
        for key, value in selection.items():
            if key == "not_equals" and isinstance(value, str):
                text = value.strip()
                if text.startswith("{") and text.endswith("}"):
                    return True
            if has_unrepresentable_negation(value):
                return True
    elif isinstance(selection, list):
        return any(has_unrepresentable_negation(item) for item in selection)
    return False


def classify_rule(rule: DetectionRule, allowed: set[str]) -> tuple[bool, set[str]]:
    """Return ``(is_applicable, fields_the_event_model_lacks)``.

    ``raw.*`` counts as matchable: the original payload is carried on every
    event, so a rule reaching into it can genuinely fire.
    """
    fields: set[str] = set()
    selection_field_names(rule.selection, fields)
    fields.discard("")
    missing = {name for name in fields if name not in allowed and not name.startswith("raw")}
    return (bool(fields) and not missing), missing


def _rule_filename(rule: DetectionRule) -> str:
    safe = "".join(char if char.isalnum() or char in "-_." else "-" for char in rule.rule_id)
    return f"{safe or 'sigma-rule'}.json"


def _rule_to_json(rule: DetectionRule) -> dict[str, Any]:
    # "id", not "rule_id": this must round-trip through rules.rule_from_dict.
    return {
        "id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity.name.lower(),
        "risk_points": rule.risk_points,
        "selection": rule.selection,
        "mitre_attack": list(rule.mitre_attack),
        "tags": list(rule.tags),
        "enabled": rule.enabled,
    }


def sync_rules(
    dest: str | Path,
    ruleset: str = DEFAULT_RULESET,
    fetch: Fetcher | None = None,
    release: SigmaRelease | None = None,
    limit: int | None = None,
) -> SigmaSyncReport:
    """Fetch a SigmaHQ bundle and write the rules AutoSIEM can actually run.

    ``limit`` caps how many applicable rules are written. When it truncates, the
    report still counts every candidate, so a cap never masquerades as "that is
    all there was".
    """
    fetcher = fetch or _default_fetch
    resolved = release or latest_release(ruleset, fetch=fetcher)
    archive = zipfile.ZipFile(io.BytesIO(fetcher(require_https(resolved.url, what="SigmaHQ rules"))))

    allowed = matchable_fields()
    report = SigmaSyncReport(release=resolved.tag, ruleset=resolved.ruleset)
    missing_counter: dict[str, int] = {}
    techniques: set[str] = set()
    keep: list[DetectionRule] = []

    for name in sorted(archive.namelist()):
        if not name.lower().endswith((".yml", ".yaml")):
            continue
        report.candidates += 1
        try:
            text = archive.read(name).decode("utf-8", "replace")
            rule = sigma_to_rule(parse_sigma_yaml(text))
        except (SigmaParseError, ValueError, KeyError, TypeError, IndexError) as exc:
            report.unsupported_syntax += 1
            if len(report.syntax_samples) < 5:
                report.syntax_samples.append(f"{name}: {type(exc).__name__}: {str(exc)[:80]}")
            continue

        if has_unrepresentable_negation(rule.selection):
            report.unsupported_syntax += 1
            if len(report.syntax_samples) < 5:
                report.syntax_samples.append(f"{name}: negation not representable by the selection engine")
            continue

        applicable, missing = classify_rule(rule, allowed)
        if not applicable:
            report.not_applicable += 1
            for field_name in missing:
                missing_counter[field_name] = missing_counter.get(field_name, 0) + 1
            continue
        if limit is None or len(keep) < limit:
            keep.append(rule)
            techniques.update(str(t).strip().upper() for t in rule.mitre_attack if str(t).strip())

    destination = Path(dest)
    destination.mkdir(parents=True, exist_ok=True)
    for existing in destination.glob("*.json"):
        existing.unlink()
    for rule in keep:
        (destination / _rule_filename(rule)).write_text(
            json.dumps(_rule_to_json(rule), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    report.imported = len(keep)
    report.techniques = sorted(techniques)
    report.missing_fields = dict(sorted(missing_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:15])
    report.destination = str(destination)
    (destination / SYNC_MANIFEST).write_text(
        json.dumps(
            {
                "release": report.release,
                "ruleset": report.ruleset,
                "candidates": report.candidates,
                "imported": report.imported,
                "not_applicable": report.not_applicable,
                "unsupported_syntax": report.unsupported_syntax,
                "techniques": report.techniques,
                "missing_fields": report.missing_fields,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report


def load_synced_rules(
    directory: str | Path | None, errors: list[str] | None = None
) -> list[DetectionRule]:
    """Load previously synced rules; empty when the directory is absent.

    A corrupt file is skipped so it cannot stop the rest of detection, but the
    reason is appended to ``errors`` when a list is supplied. Silently returning
    fewer rules than are on disk is how a broken sync looks exactly like a small
    one.
    """
    if not directory:
        return []
    path = Path(directory)
    if not path.is_dir():
        return []
    from .rules import load_rule_file

    rules: list[DetectionRule] = []
    for rule_path in sorted(path.glob("*.json")):
        if rule_path.name == SYNC_MANIFEST:
            continue
        try:
            rules.append(load_rule_file(rule_path))
        except Exception as exc:
            if errors is not None:
                errors.append(f"{rule_path.name}: {type(exc).__name__}: {exc}")
    return rules


def merge_rules(primary: Iterable[DetectionRule], extra: Iterable[DetectionRule]) -> list[DetectionRule]:
    """Curated rules win on a ``rule_id`` collision; synced content never
    silently replaces a rule this project authored and tested."""
    merged = list(primary)
    seen = {rule.rule_id for rule in merged}
    for rule in extra:
        if rule.rule_id not in seen:
            merged.append(rule)
            seen.add(rule.rule_id)
    return merged

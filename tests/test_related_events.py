"""Tests for the analyst runtime's real related-event lookup.

`search_related_events` used to return a fixed description. It now queries an
injected event store, so these tests cover both the wired and unwired paths.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from autosiem.schemas import Finding, Incident, Severity
from autosiem.soc_runtime import AIAnalystRuntime, EventSearcher

BASE_TIME = datetime(2026, 8, 4, 10, 0, 0, tzinfo=timezone.utc)


class FakeStore:
    """Minimal EventSearcher: returns canned rows and records its calls."""

    def __init__(self, rows_by_entity: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.rows_by_entity = rows_by_entity or {}
        self.calls: list[dict[str, Any]] = []

    def search_events(
        self,
        query: str | None = None,
        entity: str | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self.calls.append({"query": query, "entity": entity, "limit": limit, "tenant_id": tenant_id})
        return list(self.rows_by_entity.get(entity or "", []))


class BrokenStore:
    def search_events(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        raise RuntimeError("database is locked")


def _event(event_id: str, **extra: Any) -> dict[str, Any]:
    return {"event_id": event_id, "timestamp": BASE_TIME.isoformat(), **extra}


def _finding(finding_id: str, event_id: str, entities: list[str]) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="RULE-1",
        rule_name="test rule",
        event_id=event_id,
        timestamp=BASE_TIME,
        severity=Severity.MEDIUM,
        risk_points=10,
        entities=entities,
        mitre_attack=[],
        evidence={},
    )


def _incident(entities: list[str], finding_ids: list[str]) -> Incident:
    return Incident(
        incident_id="inc-1",
        title="test incident",
        severity=Severity.MEDIUM,
        risk_score=50,
        entities=entities,
        finding_ids=finding_ids,
        mitre_attack=[],
        summary="test",
    )


def _task(investigation: Any) -> Any:
    return next(task for task in investigation.tasks if task.action == "search_related_events")


def _related_evidence(investigation: Any) -> list[Any]:
    return [item for item in investigation.evidence if item.kind == "related_events"]


# --- unwired path ----------------------------------------------------------


def test_without_a_store_the_task_says_so() -> None:
    runtime = AIAnalystRuntime()
    findings = [_finding("f1", "e1", ["user:alice"])]
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), findings)

    result = _task(investigation).result
    assert result is not None
    assert "No event store configured" in result
    assert _related_evidence(investigation) == []


# --- wired path ------------------------------------------------------------


def test_finds_prior_events_and_attaches_evidence() -> None:
    store = FakeStore({"user:alice": [_event("old-1"), _event("old-2")]})
    runtime = AIAnalystRuntime(event_search=store)
    findings = [_finding("f1", "e1", ["user:alice"])]
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), findings)

    result = _task(investigation).result
    assert result is not None
    assert "2 distinct prior event(s)" in result
    assert "user:alice 2" in result

    evidence = _related_evidence(investigation)
    assert len(evidence) == 1
    assert evidence[0].data["total"] == 2
    assert {row["event_id"] for row in evidence[0].data["events"]} == {"old-1", "old-2"}


def test_events_already_in_the_incident_are_excluded() -> None:
    """The pivot is about what is NOT already in the case."""
    store = FakeStore({"user:alice": [_event("e1"), _event("old-1")]})
    runtime = AIAnalystRuntime(event_search=store)
    findings = [_finding("f1", "e1", ["user:alice"])]
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), findings)

    evidence = _related_evidence(investigation)
    assert {row["event_id"] for row in evidence[0].data["events"]} == {"old-1"}


def test_no_prior_events_reports_cleanly_without_evidence() -> None:
    store = FakeStore({"user:alice": [_event("e1")]})  # only the incident's own event
    runtime = AIAnalystRuntime(event_search=store)
    findings = [_finding("f1", "e1", ["user:alice"])]
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), findings)

    result = _task(investigation).result
    assert result is not None
    assert "no prior events outside this incident" in result
    assert _related_evidence(investigation) == []


def test_shared_events_are_deduped_but_counted_per_entity() -> None:
    """One event on two entities counts once overall, once for each entity.

    Deduping the per-entity counts would credit the event to whichever entity
    was queried first and report zero for the other, which reads as "this user
    had no related activity" when they did.
    """
    shared = _event("old-1")
    store = FakeStore({"user:alice": [shared], "host:ws-1": [shared]})
    runtime = AIAnalystRuntime(event_search=store)
    findings = [_finding("f1", "e1", ["user:alice", "host:ws-1"])]
    investigation = runtime.investigate(_incident(["user:alice", "host:ws-1"], ["f1"]), findings)

    result = _task(investigation).result
    assert result is not None
    assert "1 distinct prior event(s)" in result
    assert "user:alice 1" in result
    assert "host:ws-1 1" in result
    assert _related_evidence(investigation)[0].data["total"] == 1


def test_per_entity_counts_are_ordered_by_volume() -> None:
    store = FakeStore(
        {
            "user:alice": [_event(f"a{i}") for i in range(5)],
            "host:ws-1": [_event("b0")],
            "ip:10.0.0.1": [_event(f"c{i}") for i in range(3)],
        }
    )
    runtime = AIAnalystRuntime(event_search=store)
    findings = [_finding("f1", "e1", ["user:alice"])]
    incident = _incident(["user:alice", "host:ws-1", "ip:10.0.0.1"], ["f1"])
    result = _task(runtime.investigate(incident, findings)).result

    assert result is not None
    assert result.index("user:alice 5") < result.index("ip:10.0.0.1 3") < result.index("host:ws-1 1")


def test_every_incident_entity_is_queried() -> None:
    """Two tasks hit the store: search_related_events, then enrich_entities.

    Both walk the incident's entities in order, so the call log is the entity
    list twice.
    """
    store = FakeStore()
    runtime = AIAnalystRuntime(event_search=store)
    findings = [_finding("f1", "e1", ["user:alice"])]
    entities = ["user:alice", "host:ws-1", "ip:10.0.0.1"]
    runtime.investigate(_incident(entities, ["f1"]), findings)

    assert [call["entity"] for call in store.calls[: len(entities)]] == entities
    assert [call["entity"] for call in store.calls] == entities * 2


def test_tenant_and_limit_are_passed_to_the_store() -> None:
    store = FakeStore()
    runtime = AIAnalystRuntime(event_search=store, tenant_id="acme", related_event_limit=7)
    findings = [_finding("f1", "e1", ["user:alice"])]
    runtime.investigate(_incident(["user:alice"], ["f1"]), findings)

    assert store.calls[0]["tenant_id"] == "acme"
    assert store.calls[0]["limit"] == 7


def test_evidence_payload_is_capped_but_total_is_honest() -> None:
    store = FakeStore({"user:alice": [_event(f"old-{i}") for i in range(20)]})
    runtime = AIAnalystRuntime(event_search=store, related_event_limit=5)
    findings = [_finding("f1", "e1", ["user:alice"])]
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), findings)

    data = _related_evidence(investigation)[0].data
    assert data["total"] == 20
    assert data["returned"] == 5
    assert len(data["events"]) == 5


# --- failure handling ------------------------------------------------------


def test_a_broken_store_does_not_abort_the_investigation() -> None:
    runtime = AIAnalystRuntime(event_search=BrokenStore())
    findings = [_finding("f1", "e1", ["user:alice"])]
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), findings)

    assert investigation.decision is not None
    assert any("task_error action=search_related_events" in entry for entry in investigation.audit_log)
    assert "RuntimeError" in " ".join(investigation.audit_log)


def test_rows_without_an_event_id_are_skipped() -> None:
    store = FakeStore({"user:alice": [{"timestamp": BASE_TIME.isoformat()}, _event("old-1")]})
    runtime = AIAnalystRuntime(event_search=store)
    findings = [_finding("f1", "e1", ["user:alice"])]
    investigation = runtime.investigate(_incident(["user:alice"], ["f1"]), findings)

    assert _related_evidence(investigation)[0].data["total"] == 1


def test_storage_satisfies_the_event_searcher_protocol(tmp_path) -> None:
    from autosiem.storage import AutoSIEMStorage

    assert isinstance(AutoSIEMStorage(tmp_path / "probe.db"), EventSearcher)

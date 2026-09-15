"""Storage contracts shared by the local and optional PostgreSQL implementations.

These ports separate authoritative control-plane work from event and incident
queries. ``AutoSIEMStorage`` is the default SQLite implementation;
``PostgresStorage`` preserves the same tenant-scoped contracts.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class EventQueryStore(Protocol):
    """Search normalized events without exposing storage-specific details."""

    def search_events(
        self,
        query: str | None = ...,
        entity: str | None = ...,
        limit: int = ...,
        tenant_id: str | None = ...,
    ) -> list[dict[str, Any]]: ...


@runtime_checkable
class IncidentQueryStore(Protocol):
    """Read tenant-scoped incident summaries for historical context."""

    def list_incidents(
        self, limit: int = ..., tenant_id: str | None = ...
    ) -> list[dict[str, Any]]: ...


@runtime_checkable
class BaselineStore(Protocol):
    """Persist UEBA baseline state for a tenant."""

    def load_baseline(self, tenant_id: str | None = ...) -> dict[str, Any] | None: ...

    def save_baseline(self, state: dict[str, Any], tenant_id: str | None = ...) -> None: ...


@runtime_checkable
class ControlPlaneStore(IncidentQueryStore, Protocol):
    """Persist and govern incidents, investigations, and analyst decisions."""

    def save_pipeline_result(self, result: Any, tenant_id: str | None = ...) -> None: ...

    def get_incident_bundle(
        self, incident_id: str, tenant_id: str | None = ...
    ) -> dict[str, Any] | None: ...

    def decide_proposal(
        self,
        proposal_id: str,
        decision: str,
        actor: str = ...,
        tenant_id: str | None = ...,
    ) -> dict[str, Any] | None: ...

    def update_incident(
        self,
        incident_id: str,
        status: str | None = ...,
        assignee: str | None = ...,
        resolution: str | None = ...,
        note: str | None = ...,
        actor: str = ...,
        tenant_id: str | None = ...,
    ) -> dict[str, Any] | None: ...

    def add_incident_comment(
        self,
        incident_id: str,
        actor: str,
        body: str,
        tenant_id: str | None = ...,
    ) -> dict[str, Any] | None: ...

    def list_incident_comments(
        self, incident_id: str, tenant_id: str | None = ...
    ) -> list[dict[str, Any]]: ...

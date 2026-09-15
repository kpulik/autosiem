from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .soc_runtime import Investigation
from .suppression import (
    DEFAULT_CREATED_BY,
    DEFAULT_SUPPRESSION_ACTION,
    DEFAULT_SUPPRESSION_NAME,
    DEFAULT_SUPPRESSION_REASON,
    DEFAULT_SUPPRESSION_RULE_ID,
    Suppression,
    validate_suppression_fields,
)
from .storage_ports import BaselineStore, ControlPlaneStore, EventQueryStore

DEFAULT_DB_PATH = Path("data/autosiem.db")
DEFAULT_TENANT = "default"
#: Actor recorded for comments and audit entries the AI analyst writes itself.
AI_ANALYST_ACTOR = "ai-analyst"

INCIDENT_STATUSES = {"open", "investigating", "resolved", "closed"}


class StorageConflict(ValueError):
    """A write conflicts with durable state and requires caller resolution."""


class RelationalStorage(ControlPlaneStore, EventQueryStore, BaselineStore):
    """Shared relational repository; drivers own connections and insert semantics."""

    @contextmanager
    def connect(self) -> Iterator[Any]:
        raise NotImplementedError
        yield  # pragma: no cover

    def _insert(self, conn: Any, table: str, columns: str, values: tuple[Any, ...]) -> bool:
        raise NotImplementedError

    def _event_saved(self, conn: Any, tenant: str, event_id: str, data: str) -> None:
        """Backend hook, called inside the result transaction."""

    def _select_row(self, conn: Any, table: str, key: str, value: str,
                    tenant_id: str | None, *, lock: bool = False) -> Any:
        sql = f"select * from {table} where {key} = ?"
        params = [value]
        if tenant_id:
            sql += " and tenant_id = ?"
            params.append(tenant_id)
        if lock:
            sql += self._row_lock
        rows = conn.execute(sql, params).fetchall()
        if len(rows) > 1:
            raise StorageConflict("tenant_id is required for an ambiguous record ID")
        return rows[0] if rows else None

    _row_lock = ""
    _terminal_decisions = False

    def save_pipeline_result(self, result: Any, tenant_id: str | None = None) -> None:
        """Persist a pipeline run, stamping every row with the owning tenant.

        ``tenant_id`` defaults to :data:`DEFAULT_TENANT` so single-tenant
        deployments (and the CLI) behave exactly as before.
        """
        tenant = tenant_id or DEFAULT_TENANT
        with self.connect() as conn:
            for event in result.events:
                doc = event.to_dict()
                self._insert(
                    conn, "events", 'event_id,timestamp,category,action,user,host,src_ip,severity,data,tenant_id',
                    (
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.category,
                        event.action,
                        event.user,
                        event.host,
                        event.src_ip,
                        event.severity.name.lower(),
                        _json(doc),
                        tenant,
                    ),
                )
                self._event_saved(conn, tenant, event.event_id, _json(doc))
            for finding in result.findings:
                doc = _to_jsonable(finding)
                self._insert(
                    conn, "findings", 'finding_id,rule_id,rule_name,event_id,timestamp,severity,risk_points,data,tenant_id',
                    (
                        finding.finding_id,
                        finding.rule_id,
                        finding.rule_name,
                        finding.event_id,
                        finding.timestamp.isoformat(),
                        finding.severity.name.lower(),
                        finding.risk_points,
                        _json(doc),
                        tenant,
                    ),
                )
            for incident in result.incidents:
                doc = _to_jsonable(incident)
                inserted = self._insert(
                    conn, "incidents", 'incident_id,title,severity,risk_score,status,created_at,data,tenant_id',
                    (
                        incident.incident_id,
                        incident.title,
                        incident.severity.name.lower(),
                        incident.risk_score,
                        "open",
                        incident.created_at.isoformat(),
                        _json(doc),
                        tenant,
                    ),
                )
                investigation = result.investigations.get(incident.incident_id)
                if investigation and inserted:
                    self._save_investigation(conn, incident.incident_id, investigation, tenant_id=tenant)
                    # The runtime drafts the note during the investigation, but the
                    # incident row only exists now, so the comment is written here.
                    note = getattr(investigation, "case_note", None)
                    if note:
                        comment = self._add_comment(conn, incident.incident_id, AI_ANALYST_ACTOR, note, tenant_id=tenant)
                        self.audit(
                            conn,
                            actor=AI_ANALYST_ACTOR,
                            action="incident_commented",
                            target=incident.incident_id,
                            details={"comment_id": comment["comment_id"], "source": "ai_case_note", "tenant_id": tenant},
                            tenant_id=tenant,
                        )
            self.audit(conn, actor="system", action="pipeline_result_saved", target=None, details={"events": len(result.events), "findings": len(result.findings), "incidents": len(result.incidents), "tenant_id": tenant}, tenant_id=tenant)
            if getattr(result, "suppressed", None):
                self.audit(
                    conn,
                    actor="system",
                    action="findings_suppressed",
                    target=None,
                    details={"count": len(result.suppressed), "items": result.suppressed},
                    tenant_id=tenant,
                )

    def _save_investigation(
        self,
        conn: Any,
        incident_id: str,
        investigation: Investigation,
        tenant_id: str | None = None,
    ) -> None:
        tenant = tenant_id or DEFAULT_TENANT
        doc = _to_jsonable(investigation)
        self._insert(
            conn, "investigations", 'investigation_id,incident_id,status,decision,confidence,created_at,data,tenant_id',
            (
                investigation.investigation_id,
                incident_id,
                investigation.status,
                investigation.decision.decision_type.value,
                investigation.decision.confidence,
                investigation.created_at.isoformat(),
                _json(doc),
                tenant,
            ),
        )
        for proposal in investigation.action_proposals:
            self._insert(
                conn, "action_proposals", 'proposal_id,investigation_id,incident_id,action,target,confidence,approval_required,executable_now,status,data,tenant_id',
                (
                    proposal.proposal_id,
                    investigation.investigation_id,
                    incident_id,
                    proposal.action,
                    proposal.target,
                    proposal.confidence,
                    int(proposal.approval_required),
                    int(proposal.executable_now),
                    "pending",
                    _json(_to_jsonable(proposal)),
                    tenant,
                ),
            )

    def list_incidents(self, limit: int = 50, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
            sql = "select incident_id,title,severity,risk_score,status,assignee,resolution,updated_at,created_at,data,tenant_id from incidents"
            params: list[Any] = []
            if tenant_id:
                sql += " where tenant_id = ?"
                params.append(tenant_id)
            sql += " order by risk_score desc, created_at desc limit ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_dict(row) for row in rows]

    def get_incident_bundle(self, incident_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
        with self.connect() as conn:
            incident = self._select_row(conn, "incidents", "incident_id", incident_id, tenant_id)
            if not incident:
                return None
            incident_doc = _row_to_dict(incident)
            tenant = incident["tenant_id"]
            investigation = conn.execute("select * from investigations where incident_id = ? and tenant_id = ? order by created_at desc limit 1", (incident_id, tenant)).fetchone()
            proposals = conn.execute("select * from action_proposals where incident_id = ? and tenant_id = ? order by action", (incident_id, tenant)).fetchall()
            finding_ids = incident_doc.get("data", {}).get("finding_ids", [])
            findings = self._findings_by_ids(conn, finding_ids, tenant)
            event_ids = [finding["event_id"] for finding in findings]
            events = self._events_by_ids(conn, event_ids, tenant)
            return {
                "incident": incident_doc,
                "investigation": _row_to_dict(investigation) if investigation else None,
                "findings": findings,
                "events": events,
                "timeline": _build_timeline(incident_doc, findings, events),
                "proposals": [_row_to_dict(row) for row in proposals],
                "comments": self._list_comments(conn, incident_id, tenant_id=tenant),
            }

    def list_findings(self, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
            sql = "select * from findings"
            params: list[Any] = []
            if tenant_id:
                sql += " where tenant_id = ?"
                params.append(tenant_id)
            sql += " order by timestamp desc limit ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_dict(row) for row in rows]

    def list_events(self, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
            sql = "select * from events"
            params: list[Any] = []
            if tenant_id:
                sql += " where tenant_id = ?"
                params.append(tenant_id)
            sql += " order by timestamp desc limit ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_dict(row) for row in rows]

    def source_stats(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """Per-source ingest health: event count plus first/last seen."""
        with self.connect() as conn:
            where_clause = ""
            params: list[Any] = []
            if tenant_id:
                where_clause = " where tenant_id = ?"
                params = [tenant_id]
            rows = conn.execute(
                f"""
                select coalesce(json_extract(data, '$.source'), 'unknown') as source,
                       count(*) as events,
                       min(timestamp) as first_seen,
                       max(timestamp) as last_seen
                from events{where_clause}
                group by source
                order by last_seen desc
                """,
                params,
            ).fetchall()
            return [_row_to_dict(row) for row in rows]

    def search_events(self, query: str | None = None, entity: str | None = None, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if tenant_id:
            where.append("tenant_id = ?")
            params.append(tenant_id)
        if query:
            like = f"%{query}%"
            where.append("(" + " or ".join(f"lower({column}) like lower(?)" for column in
                                          ('event_id', 'category', 'action', '"user"', 'host', 'src_ip', 'data')) + ")")
            params.extend([like, like, like, like, like, like, like])
        if entity:
            kind, _, value = entity.partition(":")
            if kind == "user" and value:
                where.append('"user" = ?')
                params.append(value)
            elif kind == "host" and value:
                where.append("host = ?")
                params.append(value)
            elif kind == "ip" and value:
                where.append("src_ip = ?")
                params.append(value)
            else:
                like = f"%{entity}%"
                where.append("lower(data) like lower(?)")
                params.append(like)
        sql = "select * from events"
        if where:
            sql += " where " + " and ".join(where)
        sql += " order by timestamp desc limit ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_dict(row) for row in rows]

    def search_incidents(self, query: str | None = None, entity: str | None = None, status: str | None = None, limit: int = 50, tenant_id: str | None = None) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if tenant_id:
            where.append("tenant_id = ?")
            params.append(tenant_id)
        if query:
            like = f"%{query}%"
            where.append("(" + " or ".join(f"lower({column}) like lower(?)" for column in
                                          ("incident_id", "title", "severity", "data")) + ")")
            params.extend([like, like, like, like])
        if entity:
            where.append("lower(data) like lower(?)")
            params.append(f"%{entity}%")
        if status:
            where.append("status = ?")
            params.append(status)
        sql = "select incident_id,title,severity,risk_score,status,assignee,resolution,updated_at,created_at,data,tenant_id from incidents"
        if where:
            sql += " where " + " and ".join(where)
        sql += " order by risk_score desc, created_at desc limit ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_dict(row) for row in rows]

    def incident_timeline(self, incident_id: str, tenant_id: str | None = None) -> list[dict[str, Any]] | None:
        bundle = self.get_incident_bundle(incident_id, tenant_id=tenant_id)
        if not bundle:
            return None
        return bundle["timeline"]

    def _findings_by_ids(self, conn: Any, finding_ids: list[str], tenant: str) -> list[dict[str, Any]]:
        if not finding_ids:
            return []
        placeholders = ",".join("?" for _ in finding_ids)
        rows = conn.execute(f"select * from findings where finding_id in ({placeholders}) and tenant_id = ? order by timestamp", [*finding_ids, tenant]).fetchall()
        return [_row_to_dict(row) for row in rows]

    def _events_by_ids(self, conn: Any, event_ids: list[str], tenant: str) -> list[dict[str, Any]]:
        if not event_ids:
            return []
        placeholders = ",".join("?" for _ in event_ids)
        rows = conn.execute(f"select * from events where event_id in ({placeholders}) and tenant_id = ? order by timestamp", [*event_ids, tenant]).fetchall()
        return [_row_to_dict(row) for row in rows]

    def decide_proposal(self, proposal_id: str, decision: str, actor: str = "analyst", tenant_id: str | None = None) -> dict[str, Any] | None:
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be 'approved' or 'rejected'")
        with self.connect() as conn:
            proposal = self._select_row(conn, "action_proposals", "proposal_id", proposal_id, tenant_id, lock=True)
            if not proposal:
                return None
            if self._terminal_decisions and proposal["status"] != "pending":
                if proposal["status"] != decision:
                    raise StorageConflict("proposal already has a final decision")
                return _row_to_dict(proposal)
            conn.execute("update action_proposals set status = ? where proposal_id = ? and tenant_id = ?", (decision, proposal_id, proposal["tenant_id"]))
            self.audit(
                conn,
                actor=actor,
                action=f"proposal_{decision}",
                target=proposal["target"],
                details={"proposal_id": proposal_id, "action": proposal["action"], "tenant_id": proposal["tenant_id"]},
                tenant_id=proposal["tenant_id"],
            )
            return _row_to_dict(proposal) | {"status": decision}

    def update_incident(
        self,
        incident_id: str,
        status: str | None = None,
        assignee: str | None = None,
        resolution: str | None = None,
        note: str | None = None,
        actor: str = "analyst",
        tenant_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Update triage fields; returns the updated incident row or None.

        When ``tenant_id`` is set, an incident owned by another tenant is
        invisible: the method returns ``None`` exactly as if it did not exist.
        """
        if status is not None and status not in INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {sorted(INCIDENT_STATUSES)}")
        with self.connect() as conn:
            row = self._select_row(conn, "incidents", "incident_id", incident_id, tenant_id, lock=True)
            if not row:
                return None
            current = dict(row)
            if status is not None:
                current["status"] = status
            if assignee is not None:
                current["assignee"] = assignee
            if resolution is not None:
                current["resolution"] = resolution
            current["updated_at"] = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "update incidents set status = ?, assignee = ?, resolution = ?, updated_at = ? where incident_id = ? and tenant_id = ?",
                (current["status"], current["assignee"], current["resolution"], current["updated_at"], incident_id, current["tenant_id"]),
            )
            if note:
                self._add_comment(conn, incident_id, actor, note, tenant_id=current["tenant_id"])
            changed = {"status": current["status"], "assignee": current["assignee"], "resolution": current["resolution"], "tenant_id": current["tenant_id"]}
            self.audit(conn, actor=actor, action="incident_updated", target=incident_id, details=changed, tenant_id=tenant_id)
            return _row_to_dict(self._select_row(conn, "incidents", "incident_id", incident_id, current["tenant_id"]))

    def load_baseline(self, tenant_id: str | None = None) -> dict[str, Any] | None:
        """Return the stored UEBA baseline for a tenant, or None if there is none."""
        tenant = tenant_id or DEFAULT_TENANT
        with self.connect() as conn:
            row = conn.execute("select state from baselines where tenant_id = ?", (tenant,)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["state"])
        except (TypeError, ValueError):
            # A corrupt baseline should relearn, not crash the pipeline.
            return None

    def save_baseline(self, state: dict[str, Any], tenant_id: str | None = None) -> None:
        """Persist the UEBA baseline for a tenant, replacing any previous one."""
        tenant = tenant_id or DEFAULT_TENANT
        with self.connect() as conn:
            self._insert(
                conn, "baselines", "tenant_id,state,updated_at",
                (tenant, _json(state), datetime.now(timezone.utc).isoformat()),
            )

    def add_incident_comment(self, incident_id: str, actor: str, body: str, tenant_id: str | None = None) -> dict[str, Any] | None:
        with self.connect() as conn:
            exists = self._select_row(conn, "incidents", "incident_id", incident_id, tenant_id)
            if not exists:
                return None
            comment = self._add_comment(conn, incident_id, actor, body, tenant_id=exists["tenant_id"])
            self.audit(conn, actor=actor, action="incident_commented", target=incident_id, details={"comment_id": comment["comment_id"], "tenant_id": exists["tenant_id"]}, tenant_id=exists["tenant_id"])
            return comment

    def list_incident_comments(self, incident_id: str, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return self._list_comments(conn, incident_id, tenant_id=tenant_id)

    def _add_comment(self, conn: Any, incident_id: str, actor: str, body: str, tenant_id: str | None = None) -> dict[str, Any]:
        comment = {
            "comment_id": str(uuid4()),
            "incident_id": incident_id,
            "actor": actor,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "body": body,
        }
        conn.execute(
            "insert into incident_comments(comment_id,incident_id,actor,created_at,body) values(?,?,?,?,?)",
            (comment["comment_id"], comment["incident_id"], comment["actor"], comment["created_at"], comment["body"]),
        )
        return comment

    def _list_comments(self, conn: Any, incident_id: str, tenant_id: str | None = None) -> list[dict[str, Any]]:
        # Comments inherit their tenant from the incident they hang off, so the
        # scoped read joins rather than carrying a duplicate tenant column.
        if tenant_id:
            rows = conn.execute(
                "select c.* from incident_comments c join incidents i on i.incident_id = c.incident_id "
                "where c.incident_id = ? and i.tenant_id = ? order by c.created_at asc",
                (incident_id, tenant_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "select * from incident_comments where incident_id = ? order by created_at asc", (incident_id,)
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def list_suppressions(self, enabled_only: bool = False, tenant_id: str | None = None) -> list[dict[str, Any]]:
        sql = "select * from suppressions"
        params: list[Any] = []
        clauses: list[str] = []
        if enabled_only:
            clauses.append("enabled = 1")
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if clauses:
            sql += " where " + " and ".join(clauses)
        sql += " order by created_at desc"
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_dict(row) for row in rows]

    def add_suppression(
        self,
        suppression: Suppression | None = None,
        *,
        rule_id: str | None = None,
        name: str | None = None,
        action: str | None = None,
        reason: str | None = None,
        entity: str | None = None,
        downgrade_to: str | None = None,
        expires_at: str | None = None,
        created_by: str | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Persist a suppression from a Suppression object or raw fields.

        Omitted fields fall back to the shared ``DEFAULT_*`` constants, so
        ``add_suppression(rule_id="X")`` behaves like the web/CLI defaults.
        Returns the stored row.
        """
        if suppression is not None:
            rule_id = suppression.rule_id
            name = suppression.name
            action = suppression.action
            reason = suppression.reason
            entity = suppression.entity
            downgrade_to = suppression.downgrade_to
            expires_at = suppression.expires_at.isoformat() if suppression.expires_at else None
            created_by = suppression.created_by
        action = action or DEFAULT_SUPPRESSION_ACTION
        rule_id = rule_id or DEFAULT_SUPPRESSION_RULE_ID
        name = name or DEFAULT_SUPPRESSION_NAME
        reason = reason or DEFAULT_SUPPRESSION_REASON
        created_by = created_by or DEFAULT_CREATED_BY
        validate_suppression_fields(action, downgrade_to)
        tenant = tenant_id or DEFAULT_TENANT
        row = {
            "suppression_id": str(uuid4()),
            "rule_id": rule_id,
            "name": name,
            "action": action,
            "entity": entity,
            "downgrade_to": downgrade_to,
            "reason": reason,
            "expires_at": expires_at,
            "created_by": created_by,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "enabled": 1,
            "tenant_id": tenant,
        }
        with self.connect() as conn:
            conn.execute(
                "insert into suppressions(suppression_id,rule_id,name,action,entity,downgrade_to,reason,expires_at,created_by,created_at,enabled,tenant_id) "
                "values(?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(row[k] for k in ("suppression_id", "rule_id", "name", "action", "entity", "downgrade_to", "reason", "expires_at", "created_by", "created_at", "enabled", "tenant_id")),
            )
            self.audit(conn, actor=created_by, action="suppression_added", target=str(row["suppression_id"]), details={"rule_id": rule_id, "name": name, "action": action, "tenant_id": tenant}, tenant_id=tenant)
            return row

    def delete_suppression(self, suppression_id: str, actor: str = DEFAULT_CREATED_BY, tenant_id: str | None = None) -> bool:
        with self.connect() as conn:
            if tenant_id is not None:
                cursor = conn.execute(
                    "delete from suppressions where suppression_id = ? and tenant_id = ?",
                    (suppression_id, tenant_id),
                )
            else:
                cursor = conn.execute("delete from suppressions where suppression_id = ?", (suppression_id,))
            if cursor.rowcount == 0:
                return False
            self.audit(conn, actor=actor, action="suppression_deleted", target=suppression_id, details={"tenant_id": tenant_id or DEFAULT_TENANT}, tenant_id=tenant_id)
            return True

    def audit(self, conn: Any, actor: str, action: str, target: str | None,
              details: dict[str, Any], tenant_id: str | None = None) -> None:
        """Append an audit row to the append-only, hash-chained audit log.

        Each row links to the previous row's SHA-256 hash (``prev_hash``), so
        tampering with any historical entry is detectable by
        :meth:`verify_audit_chain`.

        ``tenant_id`` scopes the row for :meth:`list_audit`. It is deliberately
        NOT part of the hashed payload: adding a field would recompute every
        historical digest and make `audit-verify` report tamper on every
        existing database. The chain protects audit CONTENT; the tenant column
        is access-control metadata. Anyone able to rewrite it already has
        direct database access.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        previous = conn.execute("select hash from audit_log order by audit_id desc limit 1").fetchone()
        prev_hash = previous["hash"] if previous is not None and previous["hash"] else ""
        payload = f"{prev_hash}|{timestamp}|{actor}|{action}|{target or ''}|{_json(details)}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        conn.execute(
            "insert into audit_log(timestamp,actor,action,target,details,prev_hash,hash,tenant_id) "
            "values(?,?,?,?,?,?,?,?)",
            (timestamp, actor, action, target, _json(details), prev_hash, digest,
             tenant_id or DEFAULT_TENANT),
        )

    def verify_audit_chain(self) -> list[dict[str, Any]]:
        """Return tamper mismatches in the audit chain (empty = intact)."""
        with self.connect() as conn:
            rows = conn.execute("select * from audit_log order by audit_id asc").fetchall()
        mismatches: list[dict[str, Any]] = []
        previous_hash = ""
        for row in rows:
            row_hash = row["hash"]
            row_prev = row["prev_hash"]
            if row_prev is not None and row_prev != previous_hash:
                mismatches.append({"audit_id": row["audit_id"], "reason": "prev_hash_mismatch"})
            if row_hash:
                payload = f"{row_prev or ''}|{row['timestamp']}|{row['actor']}|{row['action']}|{row['target'] or ''}|{row['details']}"
                digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                if digest != row_hash:
                    mismatches.append({"audit_id": row["audit_id"], "reason": "hash_mismatch"})
                previous_hash = row_hash
        return mismatches

    def set_rule_enabled(self, rule_id: str, enabled: bool, actor: str = DEFAULT_CREATED_BY, tenant_id: str | None = None) -> dict[str, Any]:
        """Persist an enable/disable override for a detection rule."""
        tenant = tenant_id or DEFAULT_TENANT
        with self.connect() as conn:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "insert into rule_state(rule_id, tenant_id, enabled, updated_at) values(?,?,?,?) "
                "on conflict(rule_id, tenant_id) do update set enabled=excluded.enabled, updated_at=excluded.updated_at",
                (rule_id, tenant, 1 if enabled else 0, now),
            )
            self.audit(conn, actor, "rule_state_changed", rule_id, {"enabled": enabled, "tenant_id": tenant}, tenant_id=tenant)
        return {"rule_id": rule_id, "enabled": enabled, "tenant_id": tenant}

    def list_rule_states(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
            if tenant_id is not None:
                rows = conn.execute(
                    "select rule_id, tenant_id, enabled, updated_at from rule_state where tenant_id = ? order by rule_id",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute("select rule_id, tenant_id, enabled, updated_at from rule_state order by rule_id").fetchall()
            return [dict(row) for row in rows]

    def rule_state_dict(self, tenant_id: str | None = None) -> dict[str, bool]:
        """Return enable/disable overrides for the given tenant (or DEFAULT_TENANT)."""
        tenant = tenant_id or DEFAULT_TENANT
        with self.connect() as conn:
            rows = conn.execute(
                "select rule_id, enabled from rule_state where tenant_id = ?",
                (tenant,),
            ).fetchall()
        return {row["rule_id"]: bool(row["enabled"]) for row in rows}

    def counts(self, tenant_id: str | None = None) -> dict[str, int]:
        """Row counts for the metrics endpoint (events/findings/incidents/...)."""
        with self.connect() as conn:
            def _count(sql: str, params: list[Any] | None = None) -> int:
                return next(iter(dict(conn.execute(sql, params or []).fetchone()).values()))

            if tenant_id:
                scope = [tenant_id]
                return {
                    "events": _count("select count(*) from events where tenant_id = ?", scope),
                    "findings": _count("select count(*) from findings where tenant_id = ?", scope),
                    "incidents": _count("select count(*) from incidents where tenant_id = ?", scope),
                    "proposals_pending": _count(
                        "select count(*) from action_proposals where status = 'pending' and tenant_id = ?", scope
                    ),
                    "suppressions": _count("select count(*) from suppressions where tenant_id = ?", scope),
                }
            return {
                "events": _count("select count(*) from events"),
                "findings": _count("select count(*) from findings"),
                "incidents": _count("select count(*) from incidents"),
                "proposals_pending": _count("select count(*) from action_proposals where status = 'pending'"),
                "suppressions": _count("select count(*) from suppressions"),
            }

    def list_audit(self, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """Audit rows, scoped to one tenant unless the caller is cross-tenant.

        ``tenant_id=None`` returns every row and exists for chain verification
        and single-tenant CLI use. API callers must pass their own tenant:
        audit rows name actors and targets, so an unscoped read handed one
        tenant another tenant's activity to anyone holding ``audit:read``.
        """
        with self.connect() as conn:
            if tenant_id is None:
                rows = conn.execute(
                    "select * from audit_log order by audit_id desc limit ?", (limit,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "select * from audit_log where tenant_id = ? order by audit_id desc limit ?",
                    (tenant_id, limit),
                ).fetchall()
            return [_row_to_dict(row) for row in rows]


#: Data-plane tables keyed by (tenant_id, <id>). Two tenants may legitimately
#: carry the same upstream id, so every one of these needs a COMPOSITE primary
#: key; a single-column key plus INSERT OR REPLACE is silent cross-tenant data
#: loss. Add a new tenant-scoped table here and the migration handles it.
_TENANT_KEYED_TABLES = (
    ("events", "event_id"),
    ("findings", "finding_id"),
    ("incidents", "incident_id"),
    ("investigations", "investigation_id"),
    ("action_proposals", "proposal_id"),
)


class AutoSIEMStorage(RelationalStorage):
    """Default, dependency-free SQLite storage."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                create table if not exists events (
                    event_id text not null,
                    timestamp text not null,
                    category text not null,
                    action text not null,
                    user text,
                    host text,
                    src_ip text,
                    severity text,
                    data text not null,
                    -- matches DEFAULT_TENANT; literal kept because this DDL is not an f-string
                    tenant_id text not null default 'default',
                    -- Composite: two tenants may legitimately carry the same
                    -- upstream event_id. A single-column key let one tenant's
                    -- INSERT OR REPLACE destroy another tenant's row.
                    primary key (tenant_id, event_id)
                );
                create table if not exists findings (
                    finding_id text not null,
                    rule_id text not null,
                    rule_name text not null,
                    event_id text not null,
                    timestamp text not null,
                    severity text not null,
                    risk_points integer not null,
                    data text not null,
                    tenant_id text not null default 'default',
                    primary key (tenant_id, finding_id)
                );
                create table if not exists incidents (
                    incident_id text not null,
                    title text not null,
                    severity text not null,
                    risk_score integer not null,
                    status text not null default 'open',
                    created_at text not null,
                    data text not null,
                    tenant_id text not null default 'default',
                    primary key (tenant_id, incident_id)
                );
                create table if not exists investigations (
                    investigation_id text not null,
                    incident_id text not null,
                    status text not null,
                    decision text not null,
                    confidence real not null,
                    created_at text not null,
                    data text not null,
                    tenant_id text not null default 'default',
                    primary key (tenant_id, investigation_id)
                );
                create table if not exists action_proposals (
                    proposal_id text not null,
                    investigation_id text not null,
                    incident_id text not null,
                    action text not null,
                    target text not null,
                    confidence real not null,
                    approval_required integer not null,
                    executable_now integer not null,
                    status text not null default 'pending',
                    data text not null,
                    tenant_id text not null default 'default',
                    primary key (tenant_id, proposal_id)
                );
                create table if not exists audit_log (
                    audit_id integer primary key autoincrement,
                    timestamp text not null,
                    actor text not null,
                    action text not null,
                    target text,
                    details text not null,
                    -- Audit rows name actors and targets belonging to one
                    -- tenant. Without this column list_audit served every
                    -- tenant's history to any caller holding audit:read.
                    tenant_id text not null default 'default'
                );
                create table if not exists suppressions (
                    suppression_id text primary key,
                    rule_id text not null,
                    name text not null,
                    action text not null,
                    entity text,
                    downgrade_to text,
                    reason text not null,
                    expires_at text,
                    created_by text not null,
                    created_at text not null,
                    enabled integer not null default 1,
                    -- matches DEFAULT_TENANT; literal kept because this DDL is not an f-string
                    tenant_id text not null default 'default'
                );
                create table if not exists incident_comments (
                    comment_id text primary key,
                    incident_id text not null,
                    actor text not null,
                    created_at text not null,
                    body text not null
                );
                create table if not exists rule_state (
                    rule_id text not null,
                    tenant_id text not null default 'default',
                    enabled integer not null default 1,
                    updated_at text not null,
                    primary key (rule_id, tenant_id)
                );
                create table if not exists baselines (
                    tenant_id text primary key,
                    state text not null,
                    updated_at text not null
                );
                create index if not exists idx_events_timestamp on events(timestamp);
                create index if not exists idx_events_entities on events(user, host, src_ip);
                create index if not exists idx_findings_event_id on findings(event_id);
                create index if not exists idx_findings_timestamp on findings(timestamp);
                create index if not exists idx_incidents_status on incidents(status);
                create index if not exists idx_proposals_incident_id on action_proposals(incident_id);
                create index if not exists idx_suppressions_rule on suppressions(rule_id);
                create index if not exists idx_comments_incident_id on incident_comments(incident_id);
                """
            )
            # Migration: older databases lack the incident triage columns.
            columns = {row["name"] for row in conn.execute("pragma table_info(incidents)")}
            for column, ddl in (
                ("assignee", "text"),
                ("resolution", "text"),
                ("updated_at", "text"),
            ):
                if column not in columns:
                    conn.execute(f"alter table incidents add column {column} {ddl}")
            # Migration: older databases lack the audit hash-chain columns.
            audit_columns = {row["name"] for row in conn.execute("pragma table_info(audit_log)")}
            for column, ddl in (("hash", "text"), ("prev_hash", "text")):
                if column not in audit_columns:
                    conn.execute(f"alter table audit_log add column {column} {ddl}")
            # Migration: per-tenant data isolation (RBAC depth). Existing rows
            # fall into the '{DEFAULT_TENANT}' tenant so behaviour is unchanged
            # for single-tenant deployments.
            for table, key in _TENANT_KEYED_TABLES:
                table_columns = {row["name"] for row in conn.execute(f"pragma table_info({table})")}
                if "tenant_id" not in table_columns:
                    conn.execute(
                        f"alter table {table} add column tenant_id text not null default '{DEFAULT_TENANT}'"
                    )
                    table_columns.add("tenant_id")
                # Adding the column was not enough. The primary key stayed
                # single-column, and _insert uses INSERT OR REPLACE, so a second
                # tenant writing the same upstream id REPLACED the first
                # tenant's row - silent cross-tenant data loss. SQLite cannot
                # ALTER a primary key, so the table is rebuilt exactly as
                # rule_state already was when it gained tenancy.
                primary_key = [row["name"] for row in conn.execute(f"pragma table_info({table})") if row["pk"]]
                if primary_key != [key, "tenant_id"] and sorted(primary_key) != sorted([key, "tenant_id"]):
                    columns = [row["name"] for row in conn.execute(f"pragma table_info({table})")]
                    definitions = ", ".join(
                        f'"{row["name"]}" {row["type"]}'
                        + (" not null" if row["notnull"] else "")
                        + (f' default {row["dflt_value"]}' if row["dflt_value"] is not None else "")
                        for row in conn.execute(f"pragma table_info({table})")
                    )
                    names = ", ".join(f'"{name}"' for name in columns)
                    conn.executescript(
                        f'create table "_{table}_new" ({definitions}, primary key ("{key}", tenant_id));'
                        f'insert or ignore into "_{table}_new"({names}) select {names} from "{table}";'
                        f'drop table "{table}";'
                        f'alter table "_{table}_new" rename to "{table}";'
                    )
                conn.execute(f"create index if not exists idx_{table}_tenant_id on {table}(tenant_id)")
            # Migration: audit rows name actors and targets inside one tenant.
            audit_tenant = {row["name"] for row in conn.execute("pragma table_info(audit_log)")}
            if "tenant_id" not in audit_tenant:
                conn.execute(
                    f"alter table audit_log add column tenant_id text not null default '{DEFAULT_TENANT}'"
                )
            conn.execute("create index if not exists idx_audit_tenant on audit_log(tenant_id)")
            # Migration: control-plane tenancy — per-tenant suppressions and
            # rule_state.  Existing rows land in 'default' so single-tenant
            # deployments are unaffected.
            supp_columns = {row["name"] for row in conn.execute("pragma table_info(suppressions)")}
            if "tenant_id" not in supp_columns:
                conn.execute(
                    f"alter table suppressions add column tenant_id text not null default '{DEFAULT_TENANT}'"
                )
            conn.execute(f"create index if not exists idx_suppressions_tenant on suppressions(tenant_id)")
            rs_columns = {row["name"] for row in conn.execute("pragma table_info(rule_state)")}
            if "tenant_id" not in rs_columns:
                # SQLite doesn't support ALTER TABLE to change a primary key, so
                # rebuild the table with a composite (rule_id, tenant_id) PK.
                conn.executescript(
                    """
                    create table _rule_state_new (
                        rule_id text not null,
                        tenant_id text not null default 'default',
                        enabled integer not null default 1,
                        updated_at text not null,
                        primary key (rule_id, tenant_id)
                    );
                    insert into _rule_state_new(rule_id, tenant_id, enabled, updated_at)
                        select rule_id, 'default', enabled, updated_at from rule_state;
                    drop table rule_state;
                    alter table _rule_state_new rename to rule_state;
                    """
                )
            conn.execute(f"create index if not exists idx_rule_state_tenant on rule_state(tenant_id)")

    def _insert(self, conn: Any, table: str, columns: str, values: tuple[Any, ...]) -> bool:
        # Table/column names are internal constants, never request input.
        names = ",".join(f'"{name}"' for name in columns.split(","))
        binds = ",".join("?" for _ in values)
        conn.execute(f"insert or replace into {table}({names}) values({binds})", values)
        return True


def open_storage(db_path: str | Path = DEFAULT_DB_PATH) -> RelationalStorage:
    """Select authoritative storage explicitly; never silently fall back."""
    backend = os.environ.get("AUTOSIEM_STORAGE", "sqlite").lower()
    if backend == "sqlite":
        return AutoSIEMStorage(db_path)
    if backend == "postgres":
        from .postgres import PostgresStorage, dsn_from_env
        return PostgresStorage(dsn_from_env())
    raise ValueError("AUTOSIEM_STORAGE must be sqlite or postgres")


def _row_to_dict(row: Any) -> dict[str, Any]:
    data = dict(row)
    for key in ("data", "details"):
        if key in data and isinstance(data[key], str):
            data[key] = json.loads(data[key])
    return data


def _build_timeline(incident: dict[str, Any], findings: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    event_by_id = {event["event_id"]: event for event in events}
    timeline: list[dict[str, Any]] = []
    for finding in findings:
        event = event_by_id.get(finding["event_id"])
        finding_doc = finding.get("data", {})
        event_doc = event.get("data", {}) if event else finding_doc.get("evidence", {}).get("event", {})
        timeline.append(
            {
                "timestamp": finding["timestamp"],
                "kind": "finding",
                "title": finding["rule_name"],
                "severity": finding["severity"],
                "risk_points": finding["risk_points"],
                "event_id": finding["event_id"],
                "finding_id": finding["finding_id"],
                "summary": _event_summary(event_doc),
                "event": event,
                "finding": finding,
            }
        )
    timeline.append(
        {
            "timestamp": incident["created_at"],
            "kind": "incident_created",
            "title": incident["title"],
            "severity": incident["severity"],
            "risk_score": incident["risk_score"],
            "summary": incident.get("data", {}).get("summary", "Incident created."),
            "incident_id": incident["incident_id"],
        }
    )
    return sorted(timeline, key=lambda item: item["timestamp"])


def _event_summary(event: dict[str, Any]) -> str:
    action = event.get("action", "unknown")
    user = event.get("user") or "unknown-user"
    host = event.get("host") or "unknown-host"
    src_ip = event.get("src_ip") or "unknown-ip"
    return f"{action} user={user} host={host} src_ip={src_ip}"


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "name") and hasattr(value, "value"):
        return getattr(value, "name", str(value)).lower()
    return value


def _json(value: Any) -> str:
    return json.dumps(_to_jsonable(value), sort_keys=True)

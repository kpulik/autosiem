from __future__ import annotations

import hashlib
import html
import json
import urllib.parse
import os
import secrets
import time
from pathlib import Path
from typing import Any

def _max_ingest_bytes() -> int:
    return int(os.environ.get("AUTOSIEM_MAX_INGEST_BYTES", 10 * 1024 * 1024))


def _max_ingest_events() -> int:
    return int(os.environ.get("AUTOSIEM_MAX_INGEST_EVENTS", 10000))

# CSRF secret for /ui/* forms (SEC-002). Generated per process when unset, so
# CSRF validation is on by default instead of silently disabled. Read through
# _csrf_secret() rather than directly: reading os.environ at import time meant
# the variable had no effect unless it was set before the module loaded.
_PROCESS_CSRF_SECRET = secrets.token_urlsafe(32)


def _csrf_secret() -> str:
    return os.environ.get("AUTOSIEM_CSRF_SECRET") or _PROCESS_CSRF_SECRET

from autosiem.cli import DEMO_EVENTS, load_suppression_engine
from autosiem.llm import LLMService, config_from_env
from autosiem.metrics import MetricsRegistry, prometheus_text
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.querygen import translate_query, to_cli_flags
from autosiem.enrichment import enrichment_from_env
from autosiem.rag import default_rag_engine
from autosiem.rbac import (
    PERM_APPROVE,
    PERM_AUDIT_READ,
    PERM_DATA_READ,
    PERM_INGEST,
    PERM_INCIDENT_UPDATE,
    PERM_RULES_MANAGE,
    PERM_RULES_READ,
    PERM_RULES_TEST,
    PERM_SEARCH,
    PERM_SUPPRESS_MANAGE,
    PERM_USERS_MANAGE,
    PermissionDenied,
    ROLE_VIEWER,
    Rbac,
    rbac_from_env,
)
from autosiem.rules import apply_rule_state, load_rules
from autosiem.soar import SoarPlanner
from autosiem.suppression import DEFAULT_CREATED_BY
from autosiem.storage import DEFAULT_DB_PATH, RelationalStorage, StorageConflict, open_storage

INCIDENT_STATUSES = ("open", "investigating", "resolved", "closed")

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
except ImportError as exc:  # pragma: no cover - exercised only when optional deps missing
    raise RuntimeError(
        "AutoSIEM API requires optional dependencies. Install with: pip install -e '.[api]'"
    ) from exc

DEFAULT_RULE_PATH = Path(__file__).resolve().parents[3] / "rules"

app = FastAPI(title="AutoSIEM", version="0.1.0")


@app.exception_handler(StorageConflict)
async def storage_conflict_handler(request: Request, exc: StorageConflict) -> JSONResponse:
    return JSONResponse(status_code=409, content={"detail": str(exc)})


def _env_db_path() -> Path:
    """Resolve the storage path from the environment at call time."""
    return Path(os.environ.get("AUTOSIEM_DB", str(DEFAULT_DB_PATH)))


def _env_rule_path() -> Path:
    """Resolve the rule directory from the environment at call time."""
    return Path(os.environ.get("AUTOSIEM_RULES", str(DEFAULT_RULE_PATH)))


def get_store() -> RelationalStorage:
    return open_storage(_env_db_path())


def _form_str(form: Any, key: str) -> str | None:
    """Coerce a form value (str or UploadFile) into a plain string or None."""
    value = form.get(key)
    if value is None:
        return None
    text = str(value)
    return text or None


#: Cookie a browser can carry so the rendered UI works under RBAC. Browsers
#: cannot set an Authorization header on a plain navigation, and the UI pages
#: are authenticated now, so without this the web UI would be unusable whenever
#: auth is configured. CSRF protection below is what makes cookie auth safe.
TOKEN_COOKIE = "autosiem_token"


def _bearer_token(request: Request) -> str | None:
    """API token from ``Authorization: Bearer``, ``x-api-key``, or the cookie."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[len("bearer "):].strip()
    header_key = request.headers.get("x-api-key")
    if header_key:
        return header_key
    return request.cookies.get(TOKEN_COOKIE)


def _require_permission(request: Request, permission: str) -> None:
    """Enforce a role permission in RBAC mode; legacy mode grants everything.

    The middleware authenticates (resolves the token to a user); this is the
    per-endpoint authorization step. When RBAC is not configured the legacy
    single-token guard already ran, so the caller is implicitly admin.
    """
    rbac: Any = getattr(request.state, "rbac", None)
    if rbac is None or not rbac.is_enabled():
        return
    user: Any = getattr(request.state, "user", None)
    if user is None:
        if _is_readonly_ui_get(request.url.path, request.method):
            return
        raise HTTPException(status_code=401, detail="unauthorized")
    try:
        rbac.require(user, permission)
    except PermissionDenied as exc:
        raise HTTPException(status_code=403, detail="forbidden") from exc


def _csrf_token(path: str) -> str:
    """Stateless per-path CSRF token: sha256(secret, path).

    Bound to the form's target path so a token minted for one action cannot be
    replayed against another.
    """
    return hashlib.sha256(f"{_csrf_secret()}:{path}".encode()).hexdigest()[:32]


def _validate_csrf(request: Request, form: Any) -> None:
    """Reject a /ui/* form POST that does not carry the expected token."""
    token = _form_str(form, "csrf_token") or ""
    expected = _csrf_token(request.url.path)
    if not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=403, detail="invalid csrf token")


def _actor(request: Request, default: str = "analyst") -> str:
    """Audit actor: the authenticated RBAC user, else the caller-supplied default."""
    user: Any = getattr(request.state, "user", None)
    name = getattr(user, "name", None)
    return name or default


def _tenant(request: Request) -> str | None:
    """Tenant scope for this request, or None for "every tenant".

    Returns the authenticated user's tenant when RBAC is enforcing, so each
    request only ever reads and writes its own tenant's rows. Returns ``None``
    in legacy single-token/open mode (and on the unauthenticated read-only UI
    GET pages), which preserves the original single-tenant behaviour.
    """
    user: Any = getattr(request.state, "user", None)
    if user is None:
        return None
    return getattr(user, "tenant", None) or None


#: Rendered HTML pages. These read incident, event and audit data, so they are
#: authenticated exactly like /api/* - an unauthenticated /audit would hand the
#: whole tamper-evident log to anyone who can reach the port.
UI_PAGES = frozenset({"/", "/events", "/findings", "/sources", "/audit", "/rules", "/suppressions", "/search"})


def _is_readonly_ui_get(path: str, method: str) -> bool:
    """True for a rendered UI page request (exact match, not a loose prefix)."""
    if method != "GET":
        return False
    return path in UI_PAGES or path.startswith("/incidents/")


def _is_guarded_path(path: str, method: str) -> bool:
    """Every path the auth middleware protects."""
    if path.startswith("/api"):
        return True
    if path.startswith("/ui"):
        return True
    return _is_readonly_ui_get(path, method)


@app.middleware("http")
async def _api_auth_middleware(request: Request, call_next: Any) -> Any:
    """Fail-closed auth for /api/*, /ui/* and every rendered UI page.

    SEC-001: with neither a users file nor AUTOSIEM_API_TOKEN, everything guarded
    returns 401 unless AUTOSIEM_AUTH_INSECURE=1 is set for local development.

    SEC-005: the rendered UI pages used to bypass auth entirely so a workstation
    install stayed convenient. That also served /audit, /events and every
    incident detail page to any unauthenticated caller that could reach the
    port. They are now guarded exactly like /api/*; the open local-workstation
    mode is what AUTOSIEM_AUTH_INSECURE=1 is for.
    """
    path = request.url.path
    method = request.method

    # Always open: liveness, scrape endpoint, and the generated API docs.
    if path in ("/health", "/metrics", "/openapi.json") or path.startswith("/docs"):
        return await call_next(request)

    if not _is_guarded_path(path, method):
        return await call_next(request)

    rbac = rbac_from_env()
    request.state.rbac = rbac
    token = _bearer_token(request)

    # RBAC mode
    if rbac.is_enabled():
        user = rbac.authenticate(token)
        if user is None:
            return _unauthorized(request, "unauthorized")
        request.state.user = user
        return await call_next(request)

    # Legacy mode: single shared token, caller is implicitly admin.
    api_token = os.environ.get("AUTOSIEM_API_TOKEN")
    if api_token:
        if not secrets.compare_digest(token or "", api_token):
            return _unauthorized(request, "unauthorized")
        return await call_next(request)

    # No auth configured: fail closed unless explicitly insecure (SEC-001)
    if os.environ.get("AUTOSIEM_AUTH_INSECURE") != "1":
        return _unauthorized(
            request,
            "unauthorized: set AUTOSIEM_RBAC_FILE or AUTOSIEM_API_TOKEN "
            "(or AUTOSIEM_AUTH_INSECURE=1 for local development)",
        )

    return await call_next(request)


def _unauthorized(request: Request, detail: str) -> Any:
    """401 as HTML for a browser page request, JSON everywhere else."""
    if _is_readonly_ui_get(request.url.path, request.method):
        return HTMLResponse(
            f"<h1>401 Unauthorized</h1><p>{html.escape(detail)}</p>"
            "<p>Send the token as <code>Authorization: Bearer &lt;token&gt;</code>, "
            "<code>x-api-key</code>, or an <code>autosiem_token</code> cookie.</p>",
            status_code=401,
        )
    return JSONResponse(status_code=401, content={"detail": detail})


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "db": str(_env_db_path()), "rules": str(_env_rule_path())}


@app.get("/api/incidents")
def api_incidents(request: Request, limit: int = 50, query: str | None = None, entity: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    _require_permission(request, PERM_DATA_READ)
    tenant = _tenant(request)
    if query or entity or status:
        return get_store().search_incidents(query=query, entity=entity, status=status, limit=limit, tenant_id=tenant)
    return get_store().list_incidents(limit=limit, tenant_id=tenant)


@app.get("/api/incidents/{incident_id}")
def api_incident(request: Request, incident_id: str) -> dict[str, Any]:
    _require_permission(request, PERM_DATA_READ)
    bundle = get_store().get_incident_bundle(incident_id, tenant_id=_tenant(request))
    if not bundle:
        raise HTTPException(status_code=404, detail="incident_not_found")
    return bundle


@app.get("/api/incidents/{incident_id}/timeline")
def api_incident_timeline(request: Request, incident_id: str) -> list[dict[str, Any]]:
    _require_permission(request, PERM_DATA_READ)
    timeline = get_store().incident_timeline(incident_id, tenant_id=_tenant(request))
    if timeline is None:
        raise HTTPException(status_code=404, detail="incident_not_found")
    return timeline


@app.get("/api/events")
def api_events(request: Request, limit: int = 100, query: str | None = None, entity: str | None = None) -> list[dict[str, Any]]:
    _require_permission(request, PERM_DATA_READ)
    tenant = _tenant(request)
    if query or entity:
        return get_store().search_events(query=query, entity=entity, limit=limit, tenant_id=tenant)
    return get_store().list_events(limit=limit, tenant_id=tenant)


@app.get("/api/findings")
def api_findings(request: Request, limit: int = 100) -> list[dict[str, Any]]:
    _require_permission(request, PERM_DATA_READ)
    return get_store().list_findings(limit=limit, tenant_id=_tenant(request))


@app.get("/api/sources")
def api_sources(request: Request) -> list[dict[str, Any]]:
    _require_permission(request, PERM_DATA_READ)
    return get_store().source_stats(tenant_id=_tenant(request))


@app.get("/api/audit")
def api_audit(request: Request, limit: int = 100) -> list[dict[str, Any]]:
    _require_permission(request, PERM_AUDIT_READ)
    # Scoped: audit rows name actors and targets inside one tenant.
    return get_store().list_audit(limit=limit, tenant_id=_tenant(request))


def _rbac_store(request: Request) -> Rbac:
    """Load the writable RBAC store for user-management endpoints.

    Requires ``AUTOSIEM_RBAC_FILE`` so mutations can be persisted; without it
    there is nowhere to save users and the endpoints are a no-op surface.
    """
    path = os.environ.get("AUTOSIEM_RBAC_FILE")
    if not path:
        raise HTTPException(status_code=503, detail="user management requires AUTOSIEM_RBAC_FILE")
    return Rbac.load(path)


def _audit_user_change(request: Request, action: str, target: str, details: dict[str, Any]) -> None:
    """Record a user-store mutation in the hash-chained audit log."""
    store = get_store()
    with store.connect() as conn:
        store.audit(conn, actor=_actor(request, "admin"), action=action, target=target, details=details, tenant_id=_tenant(request))


@app.get("/api/users")
def api_list_users(request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_USERS_MANAGE)
    rbac = _rbac_store(request)
    return {"users": rbac.list_users(), "enabled": rbac.is_enabled()}


@app.post("/api/users")
async def api_add_user(request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_USERS_MANAGE)
    rbac = _rbac_store(request)
    body = await request.json()
    name = str(body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    role = str(body.get("role") or ROLE_VIEWER)
    tenant = str(body.get("tenant") or "default")
    token = body.get("token")
    try:
        user = rbac.add_user(name, role=role, tenant=tenant, token=token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rbac.save()
    _audit_user_change(request, "rbac_user_added", name, {"role": user.role, "tenant": user.tenant})
    return {"name": user.name, "role": user.role, "tenant": user.tenant, "token_set": bool(token)}


@app.delete("/api/users/{name}")
def api_remove_user(request: Request, name: str) -> dict[str, Any]:
    _require_permission(request, PERM_USERS_MANAGE)
    rbac = _rbac_store(request)
    if not rbac.remove_user(name):
        raise HTTPException(status_code=404, detail="user_not_found")
    rbac.save()
    _audit_user_change(request, "rbac_user_removed", name, {})
    return {"removed": True, "name": name}


@app.post("/api/users/{name}/rotate-token")
async def api_rotate_token(request: Request, name: str) -> dict[str, Any]:
    """Issue a fresh API token. The plaintext is returned exactly once."""
    _require_permission(request, PERM_USERS_MANAGE)
    rbac = _rbac_store(request)
    try:
        token = rbac.rotate_token(name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="user_not_found") from exc
    rbac.save()
    _audit_user_change(request, "rbac_token_rotated", name, {})
    return {"name": name, "token": token}


@app.post("/api/users/{name}/revoke-token")
def api_revoke_token(request: Request, name: str) -> dict[str, Any]:
    """Revoke the user's token; the account stays but cannot authenticate."""
    _require_permission(request, PERM_USERS_MANAGE)
    rbac = _rbac_store(request)
    if not rbac.revoke_token(name):
        raise HTTPException(status_code=404, detail="user_not_found")
    rbac.save()
    _audit_user_change(request, "rbac_token_revoked", name, {})
    return {"revoked": True, "name": name}


@app.post("/api/proposals/{proposal_id}/approve")
def api_approve(request: Request, proposal_id: str, actor: str = "analyst") -> dict[str, Any]:
    _require_permission(request, PERM_APPROVE)
    actor = _actor(request, actor)
    proposal = get_store().decide_proposal(proposal_id, "approved", actor=actor, tenant_id=_tenant(request))
    if not proposal:
        raise HTTPException(status_code=404, detail="proposal_not_found")
    return proposal


@app.post("/api/proposals/{proposal_id}/reject")
def api_reject(request: Request, proposal_id: str, actor: str = "analyst") -> dict[str, Any]:
    _require_permission(request, PERM_APPROVE)
    actor = _actor(request, actor)
    proposal = get_store().decide_proposal(proposal_id, "rejected", actor=actor, tenant_id=_tenant(request))
    if not proposal:
        raise HTTPException(status_code=404, detail="proposal_not_found")
    return proposal


@app.get("/api/suppressions")
def api_suppressions(request: Request) -> list[dict[str, Any]]:
    _require_permission(request, PERM_DATA_READ)
    return get_store().list_suppressions(tenant_id=_tenant(request))


@app.post("/api/suppressions")
async def api_add_suppression(request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_SUPPRESS_MANAGE)
    body = await request.json()
    # None passes through to the storage-layer DEFAULT_* constants.
    return get_store().add_suppression(
        rule_id=str(body["rule_id"]) if body.get("rule_id") else None,
        name=str(body["name"]) if body.get("name") else None,
        action=str(body["action"]) if body.get("action") else None,
        reason=str(body["reason"]) if body.get("reason") else None,
        entity=body.get("entity"),
        downgrade_to=body.get("downgrade_to"),
        expires_at=body.get("expires_at"),
        created_by=str(body["created_by"]) if body.get("created_by") else None,
        tenant_id=_tenant(request),
    )


@app.delete("/api/suppressions/{suppression_id}")
def api_delete_suppression(request: Request, suppression_id: str, actor: str = DEFAULT_CREATED_BY) -> dict[str, Any]:
    _require_permission(request, PERM_SUPPRESS_MANAGE)
    actor = _actor(request, actor)
    deleted = get_store().delete_suppression(suppression_id, actor=actor, tenant_id=_tenant(request))
    if not deleted:
        raise HTTPException(status_code=404, detail="suppression_not_found")
    return {"deleted": True, "suppression_id": suppression_id}


@app.post("/api/incidents/{incident_id}/update")
async def api_update_incident(incident_id: str, request: Request, actor: str = "analyst") -> dict[str, Any]:
    _require_permission(request, PERM_INCIDENT_UPDATE)
    actor = _actor(request, actor)
    body = await request.json()
    updated = get_store().update_incident(
        incident_id,
        status=body.get("status"),
        assignee=body.get("assignee"),
        resolution=body.get("resolution"),
        note=body.get("note"),
        actor=actor,
        tenant_id=_tenant(request),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="incident_not_found")
    return updated


@app.get("/api/incidents/{incident_id}/comments")
def api_incident_comments(request: Request, incident_id: str) -> list[dict[str, Any]]:
    _require_permission(request, PERM_DATA_READ)
    return get_store().list_incident_comments(incident_id, tenant_id=_tenant(request))


@app.post("/api/incidents/{incident_id}/comments")
async def api_add_incident_comment(incident_id: str, request: Request, actor: str = "analyst") -> dict[str, Any]:
    _require_permission(request, PERM_INCIDENT_UPDATE)
    actor = _actor(request, actor)
    body = await request.json()
    comment = get_store().add_incident_comment(incident_id, actor, str(body.get("body", "")), tenant_id=_tenant(request))
    if not comment:
        raise HTTPException(status_code=404, detail="incident_not_found")
    return comment


def _pipeline(tenant_id: str | None = None) -> AutoSIEMPipeline:
    service = LLMService(config=config_from_env())
    if not service.enabled:
        service = None
    store = get_store()
    rules = load_rules(_env_rule_path())
    state = store.rule_state_dict(tenant_id=tenant_id)
    if state:
        rules = apply_rule_state(rules, state)
    engine = load_suppression_engine(store, tenant_id=tenant_id)
    return AutoSIEMPipeline(
        rules,
        llm=service,
        suppression_engine=engine,
        rag=default_rag_engine(store, tenant_id=tenant_id),
        soar=SoarPlanner(),
        event_search=store,
        tenant_id=tenant_id,
        baseline_store=store,
        enrichment=enrichment_from_env(),
    )


@app.post("/api/ingest/demo")
async def api_ingest_demo(request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_INGEST)
    tenant = _tenant(request)
    lines = [json.dumps(event) for event in DEMO_EVENTS]
    pipeline = _pipeline(tenant_id=tenant)
    result = pipeline.process_lines(lines)
    get_store().save_pipeline_result(result, tenant_id=tenant)
    return {"events": len(result.events), "findings": len(result.findings), "incidents": len(result.incidents), "llm_enabled": pipeline.llm is not None}


def _parse_ingest_payload(raw: bytes, content_type: str) -> list[dict[str, Any]]:
    """Decode an ingest body into a flat list of events.

    Supports NDJSON (one JSON object per line) for streamed/agent collectors,
    plus a single JSON object or an array of objects for API clients. Raises
    ``ValueError`` on any payload that is not valid JSON in a supported shape.
    """
    text = raw.decode("utf-8")
    stripped = text.strip()
    if not stripped:
        raise ValueError("empty event payload")
    if "ndjson" in content_type:
        events: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
        return events
    data = json.loads(stripped)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("event payload must be a JSON object or an array of objects")


def _ingest_authorized(request: Request) -> bool:
    """Allow when no token is configured, or the request presents it."""
    token = os.environ.get("AUTOSIEM_INGEST_TOKEN")
    if not token:
        return True
    if request.headers.get("x-api-key") == token:
        return True
    return request.headers.get("authorization", "") == f"Bearer {token}"


@app.post("/api/ingest")
async def api_ingest(request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_INGEST)
    if not _ingest_authorized(request):
        raise HTTPException(status_code=401, detail="unauthorized")
    # SEC-003: Enforce max body size
    max_bytes = _max_ingest_bytes()
    max_events = _max_ingest_events()
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_bytes:
        raise HTTPException(status_code=413, detail=f"payload too large: max {max_bytes} bytes")
    raw = await request.body()
    if len(raw) > max_bytes:
        raise HTTPException(status_code=413, detail=f"payload too large: max {max_bytes} bytes")
    try:
        events = _parse_ingest_payload(raw, request.headers.get("content-type", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid event payload") from exc
    # SEC-003: Enforce max event count
    if len(events) > max_events:
        raise HTTPException(status_code=413, detail=f"too many events: max {max_events}")
    tenant = _tenant(request)
    lines = [json.dumps(event) for event in events]
    pipeline = _pipeline(tenant_id=tenant)
    result = pipeline.process_lines(lines)
    get_store().save_pipeline_result(result, tenant_id=tenant)
    return {
        "accepted": len(events),
        "events": len(result.events),
        "findings": len(result.findings),
        "incidents": len(result.incidents),
        "llm_enabled": pipeline.llm is not None,
    }


@app.get("/api/rules")
def api_rules(request: Request, rule_id: str | None = None) -> dict[str, Any]:
    _require_permission(request, PERM_RULES_READ)
    tenant = _tenant(request)
    rules = load_rules(_env_rule_path())
    state = get_store().rule_state_dict(tenant_id=tenant)
    rules = apply_rule_state(rules, state)
    items = [
        {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity.name.lower(),
            "risk_points": rule.risk_points,
            "mitre_attack": rule.mitre_attack,
            "tags": rule.tags,
            "enabled": rule.enabled,
        }
        for rule in rules
        if not rule_id or rule.rule_id == rule_id
    ]
    if rule_id and not items:
        raise HTTPException(status_code=404, detail="rule_not_found")
    return {"rules": items, "overrides": get_store().list_rule_states(tenant_id=tenant)}


@app.post("/api/rules/test")
async def api_test_rule(request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_RULES_TEST)
    body = await request.json()
    event = body.get("event")
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="event_required")
    pipeline = _pipeline(tenant_id=_tenant(request))
    result = pipeline.process_lines([json.dumps(event)])
    return {
        "events": len(result.events),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "severity": finding.severity.name.lower(),
                "risk_points": finding.risk_points,
                "mitre_attack": finding.mitre_attack,
            }
            for finding in result.findings
        ],
        "incidents": len(result.incidents),
    }


@app.post("/api/rules/{rule_id}")
async def api_set_rule(rule_id: str, request: Request, actor: str = "analyst") -> dict[str, Any]:
    _require_permission(request, PERM_RULES_MANAGE)
    actor = _actor(request, actor)
    body = await request.json()
    enabled = bool(body.get("enabled"))
    return get_store().set_rule_enabled(rule_id, enabled, actor=actor, tenant_id=_tenant(request))


@app.get("/api/search-nl")
def api_search_nl(request: Request, q: str, target: str = "incidents") -> dict[str, Any]:
    _require_permission(request, PERM_SEARCH)
    dsl = translate_query(q)
    limit = dsl.get("limit") or 50
    tenant = _tenant(request)
    if target == "events":
        rows = get_store().search_events(query=dsl.get("query"), entity=dsl.get("entity"), limit=limit, tenant_id=tenant)
    else:
        rows = get_store().search_incidents(query=dsl.get("query"), entity=dsl.get("entity"), status=dsl.get("status"), limit=limit, tenant_id=tenant)
    return {"translation": dsl, "cli": to_cli_flags(dsl), "target": target, "results": rows, "total": len(rows)}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request) -> str:
    registry = MetricsRegistry()
    store = get_store()
    for key, value in store.counts(tenant_id=_tenant(request)).items():
        registry.gauge(f"autosiem_{key}").set(value)
    from autosiem.postgres import PostgresStorage
    if isinstance(store, PostgresStorage) and os.environ.get("AUTOSIEM_BACKEND") in {"opensearch", "clickhouse"}:
        from autosiem.projections import projection_from_env
        projection = projection_from_env()
        for key, value in store.outbox_stats(projection.destination, tenant_id=_tenant(request)).items():
            registry.gauge(f"autosiem_outbox_{key}").set(value)
    return prometheus_text(registry)


@app.get("/", response_class=HTMLResponse)
def index(request: Request, query: str | None = None, entity: str | None = None) -> str:
    incidents = api_incidents(request, limit=50, query=query, entity=entity)
    return _page(
        "AutoSIEM Incident Queue",
        f"""
        <section class="hero">
          <div>
            <p class="eyebrow">AI-native SIEM MVP</p>
            <h1>Incident Queue</h1>
            <p>Deterministic detections first. AI analyst automation stays policy-gated and auditable.</p>
          </div>
          <form method="post" action="/ui/ingest/demo"><input type="hidden" name="csrf_token" value="{_csrf_token("/ui/ingest/demo")}"><button>Load demo telemetry</button></form>
        </section>
        <form class="search" method="get" action="/">
          <input name="query" placeholder="Search incidents: PowerShell, alice, high...">
          <input name="entity" placeholder="Entity: user:alice, ip:198.51.100.25">
          <button>Search</button>
        </form>
        <section class="grid">
          {''.join(_incident_card(item) for item in incidents) or '<div class="empty">No incidents yet. Load demo telemetry to populate the queue.</div>'}
        </section>
        <p class="links"><a href="/search">Ask a question</a> · <a href="/events">Events</a> · <a href="/findings">Findings</a> · <a href="/rules">Rules</a> · <a href="/sources">Sources</a> · <a href="/suppressions">Suppressions</a> · <a href="/audit">Audit log</a> · <a href="/docs">API docs</a></p>
        """,
    )


def _confidence_source(investigation: dict[str, Any]) -> str:
    """Where the decision's confidence came from, per the stored investigation."""
    decision = (investigation.get("data") or {}).get("decision") or {}
    return str(decision.get("confidence_source") or "deterministic")


def _provenance_badge(investigation: dict[str, Any]) -> str:
    """Say plainly whether a language model produced this decision.

    Without this the page shows a confidence number with no indication of who
    asserted it, which is the first thing a reviewer asks about an "AI analyst".
    """
    if not investigation:
        return ""
    if _confidence_source(investigation) == "model":
        return '<span class="prov prov-model" title="A language model produced this decision">LLM-assisted</span>'
    return '<span class="prov prov-local" title="Derived by AutoSIEM from the evidence; no model involved">Deterministic</span>'


def _provenance_note(investigation: dict[str, Any]) -> str:
    if not investigation:
        return ""
    if _confidence_source(investigation) == "model":
        return (
            "Decision and confidence were reported by a language model. A model-reported "
            "score cannot authorize autonomous response: high-risk actions stay "
            "approval-gated regardless of the number."
        )
    return (
        "Decision and confidence were derived by AutoSIEM from the evidence. "
        "No language model was involved."
    )


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(request: Request, incident_id: str) -> str:
    bundle = get_store().get_incident_bundle(incident_id, tenant_id=_tenant(request))
    if not bundle:
        raise HTTPException(status_code=404, detail="incident_not_found")
    incident = bundle["incident"]
    investigation = bundle["investigation"] or {}
    data = incident.get("data", {})
    proposals = bundle["proposals"]
    timeline = bundle["timeline"]
    comments = bundle["comments"]
    status = incident.get("status") or "open"
    status_buttons = "".join(
        f'<form method="post" action="/ui/incidents/{_esc(incident_id)}/update">' + f'<input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/incidents/{incident_id}/update")}"><input type="hidden" name="status" value="{_esc(s)}">' + f'<button class="chipbtn{" active" if s == status else ""}">{_esc(s)}</button></form>'
        for s in INCIDENT_STATUSES
    )
    return _page(
        html.escape(incident["title"]),
        f"""
        <p class="links"><a href="/">← Incident queue</a></p>
        <section class="panel">
          <p class="eyebrow">{_esc(incident['severity'])} · risk {_esc(incident['risk_score'])} · {_esc(status)}</p>
          <h1>{_esc(incident['title'])}</h1>
          <p>{_esc(data.get('summary', 'No summary available.'))}</p>
          <div class="chips">{''.join(f'<span>{_esc(entity)}</span>' for entity in data.get('entities', []))}</div>
          <h2>AI analyst decision</h2>
          <p><strong>{_esc(investigation.get('decision', 'none'))}</strong> confidence {_esc(round(float(investigation.get('confidence', 0)), 2))} {_provenance_badge(investigation)}</p>
          <p class="provenance-note">{_provenance_note(investigation)}</p>
        </section>
        <section class="panel">
          <h2>Triage</h2>
          <div class="chiprow">{status_buttons}</div>
          <form method="post" action="/ui/incidents/{_esc(incident_id)}/update" class="sups-form">
            <input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/incidents/{incident_id}/update")}">
            <input name="assignee" value="{_esc(incident.get('assignee') or '')}" placeholder="Assignee">
            <input name="resolution" value="{_esc(incident.get('resolution') or '')}" placeholder="Resolution / outcome">
            <button>Save triage</button>
          </form>
        </section>
        <section class="panel">
          <h2>Timeline</h2>
          {''.join(_timeline_row(item) for item in timeline) or '<p>No timeline events.</p>'}
        </section>
        <section class="panel">
          <h2>Policy-gated action proposals</h2>
          {''.join(_proposal_row(request, item) for item in proposals) or '<p>No action proposals.</p>'}
        </section>
        <section class="panel">
          <h2>Comments</h2>
          {''.join(_comment_row(item) for item in comments) or '<p>No comments yet.</p>'}
          <form method="post" action="/ui/incidents/{_esc(incident_id)}/comment" class="sups-form">
            <input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/incidents/{incident_id}/comment")}">
            <input name="body" placeholder="Add a comment...">
            <button>Comment</button>
          </form>
        </section>
        <section class="panel">
          <h2>Raw incident bundle</h2>
          <pre>{_esc(json.dumps(bundle, indent=2, sort_keys=True))}</pre>
        </section>
        """,
    )


@app.get("/events", response_class=HTMLResponse)
def events_page(request: Request, query: str | None = None, entity: str | None = None) -> str:
    rows = api_events(request, limit=100, query=query, entity=entity)
    return _page(
        "AutoSIEM Events",
        f"""
        <p class='links'><a href='/'>← Incident queue</a></p><h1>Events</h1>
        <form class="search" method="get" action="/events">
          <input name="query" placeholder="Search action, user, host, IP, raw JSON...">
          <input name="entity" placeholder="Entity: user:alice, host:vpn-1, ip:198.51.100.25">
          <button>Search</button>
        </form>
        {_table(rows)}
        """,
    )


#: Shown on an empty search page. The parser is a small keyword translator, not
#: a language model, so the examples double as documentation of what it knows.
SEARCH_EXAMPLES = (
    "failed logins by user alice last 24h",
    "open critical incidents",
    "events from ip 198.51.100.25",
    "incidents for host workstation-7",
    "resolved incidents from rule AUTO-CLOUD-001",
)


def _translation_panel(dsl: dict[str, Any], cli: list[str], target: str) -> str:
    """Show what the query became, not just what it returned.

    `translate_query` is a keyword translator: it moves recognised terms into
    structured fields and leaves the rest in a free-text `query`. Hiding that
    would make a crude parser look like comprehension, so every extracted field
    is shown with its value, and the leftover free text is shown as leftover.
    The CLI line is the same search as a command, which is what makes the page
    teachable rather than magic.
    """
    understood = "".join(
        f"<span><strong>{_esc(key)}</strong> {_esc(str(value))}</span>"
        for key, value in dsl.items() if value not in (None, "")
    ) or "<span>nothing recognised</span>"
    command = "autosiem search-nl " + " ".join(cli) if cli else "autosiem search-nl"
    return f"""
    <div class="panel translation">
      <span class="eyebrow">How this was read</span>
      <div class="chips">{understood}</div>
      <p class="provenance-note">
        Recognised terms become structured filters; anything left over is matched as
        free text. Searching <strong>{_esc(target)}</strong>.
      </p>
      <button class="secondary copy" type="button" data-copy="{_esc(command)}"
              title="Copy to run the same search from the terminal">{_esc(command)}</button>
    </div>
    """


@app.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str | None = None, target: str = "incidents") -> str:
    target = "events" if target == "events" else "incidents"
    examples = "".join(
        f"<a class='chipbtn chip-link' href='/search?q={urllib.parse.quote(example)}&target={target}'>"
        f"{_esc(example)}</a>" for example in SEARCH_EXAMPLES
    )
    quoted = urllib.parse.quote(q or "")
    toggle = "".join(
        "<a class='chipbtn{active}' href='/search?q={q}&target={name}'>{name}</a>".format(
            active=" active" if target == name else "", q=quoted, name=name)
        for name in ("incidents", "events")
    )
    body = [
        "<p class='links'><a href='/'>← Incident queue</a></p><h1>Natural-language search</h1>",
        f"""
        <form class="search search-nl" method="get" action="/search">
          <input name="q" value="{_esc(q or '')}" autofocus
                 placeholder="Ask in plain English: failed logins by user alice last 24h">
          <input type="hidden" name="target" value="{_esc(target)}">
          <button>Search</button>
        </form>
        <div class="chiprow">{toggle}</div>
        """,
    ]
    if not q:
        body.append(f"<div class='panel'><span class='eyebrow'>Try one</span>"
                    f"<div class='chiprow'>{examples}</div></div>")
    else:
        found = api_search_nl(request, q=q, target=target)
        body.append(_translation_panel(found["translation"], found["cli"], target))
        total = found["total"]
        noun = target if total != 1 else target.rstrip("s")
        body.append(f"<p class='links'><strong>{total}</strong> {_esc(noun)} matched.</p>")
        body.append(_table(found["results"]))
        body.append(f"<div class='panel'><span class='eyebrow'>Other examples</span>"
                    f"<div class='chiprow'>{examples}</div></div>")
    body.append("""
    <script>
      // One interaction: the CLI line copies itself, so a search found in the
      // browser can be rerun in a terminal or a cron job.
      document.querySelectorAll('.copy').forEach(function (node) {
        node.addEventListener('click', function () {
          var text = node.getAttribute('data-copy');
          var done = function () {
            var was = node.textContent;
            node.textContent = 'copied';
            setTimeout(function () { node.textContent = was; }, 1200);
          };
          if (navigator.clipboard) { navigator.clipboard.writeText(text).then(done, function () {}); }
        });
      });
    </script>
    """)
    return _page("AutoSIEM Search", "".join(body))


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request) -> str:
    rows = api_findings(request, limit=100)
    return _page("AutoSIEM Findings", f"<p class='links'><a href='/'>← Incident queue</a></p><h1>Findings</h1>{_table(rows)}")


@app.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request) -> str:
    rows = api_sources(request)
    cards = "".join(
        f'<div class="card"><span class="badge">{_esc(row["source"])}</span><h2>{_esc(row["events"])} events</h2>'
        f'<p>first {_esc(row["first_seen"])}</p><p>last {_esc(row["last_seen"])}</p></div>'
        for row in rows
    ) or '<div class="empty">No events yet. Ingest something (demo, /api/ingest, or the syslog listener) to see per-source health.</div>'
    return _page(
        "AutoSIEM Sources",
        f"<p class='links'><a href='/'>← Incident queue</a></p><h1>Sources</h1>"
        f"<p class='eyebrow'>Per-source ingest health from the events store.</p>"
        f"<section class='grid'>{cards}</section>",
    )


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request) -> str:
    rows = get_store().list_audit(limit=100, tenant_id=_tenant(request))
    return _page("AutoSIEM Audit", f"<p class='links'><a href='/'>← Incident queue</a></p><h1>Audit Log</h1>{_table(rows)}")


@app.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request) -> str:
    rules = api_rules(request)
    rows = "".join(_rule_row(request, item) for item in rules["rules"])
    return _page(
        "AutoSIEM Detection Rules",
        f"""
        <p class='links'><a href='/'>← Incident queue</a></p>
        <h1>Detection Rules</h1>
        <p class="eyebrow">{len(rules['rules'])} rules · {len(rules['overrides'])} persisted state override(s) · enable/disable takes effect on the next ingest.</p>
        {rows or '<div class="empty">No rules found.</div>'}
        """,
    )


def _rule_row(request: Request, item: dict[str, Any]) -> str:
    button = "Disable" if item["enabled"] else "Enable"
    cls = "" if item["enabled"] else "secondary"
    toggle = f"""
    <form method="post" action="/ui/rules/{_esc(item['rule_id'])}/toggle" class="inline">
      <input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/rules/{item['rule_id']}/toggle")}">
      <input type="hidden" name="enabled" value="{'0' if item['enabled'] else '1'}">
      <button class="{cls}">{button}</button>
    </form>
    """
    return f"""
    <div class="proposal">
      <div>
        <strong>{_esc(item['rule_id'])}</strong> — {_esc(item['name'])}<br>
        <small>{_esc(item['description'])}</small>
        <div class="chips">{''.join(f'<span>{_esc(t)}</span>' for t in item.get('mitre_attack', []))}</div>
      </div>
      <span class="badge">{_esc('enabled' if item['enabled'] else 'disabled')}</span>
      {toggle}
    </div>
    """


@app.post("/ui/rules/{rule_id}/toggle")
async def ui_toggle_rule(rule_id: str, request: Request) -> RedirectResponse:
    _require_permission(request, PERM_RULES_MANAGE)
    form = await request.form()
    _validate_csrf(request, form)
    enabled = _form_str(form, "enabled") == "1"
    actor = _actor(request, "analyst")
    get_store().set_rule_enabled(rule_id, enabled, actor=actor, tenant_id=_tenant(request))
    return RedirectResponse("/rules", status_code=303)


@app.post("/ui/ingest-demo")
async def ui_ingest_demo(request: Request) -> RedirectResponse:
    form = await request.form()
    _validate_csrf(request, form)
    await api_ingest_demo(request)
    return RedirectResponse("/", status_code=303)


@app.post("/ui/proposals/{proposal_id}/approve")
async def ui_approve(request: Request, proposal_id: str) -> RedirectResponse:
    form = await request.form()
    _validate_csrf(request, form)
    proposal = api_approve(request, proposal_id)
    return RedirectResponse(f"/incidents/{proposal['incident_id']}", status_code=303)


@app.post("/ui/proposals/{proposal_id}/reject")
async def ui_reject(request: Request, proposal_id: str) -> RedirectResponse:
    form = await request.form()
    _validate_csrf(request, form)
    proposal = api_reject(request, proposal_id)
    return RedirectResponse(f"/incidents/{proposal['incident_id']}", status_code=303)


@app.get("/suppressions", response_class=HTMLResponse)
def suppressions_page(request: Request) -> str:
    rows = api_suppressions(request)
    return _page(
        "AutoSIEM Suppressions",
        f"""
        <p class='links'><a href='/'>← Incident queue</a></p>
        <h1>Suppressions & Exceptions</h1>
        <p class="eyebrow">Suppress or downgrade noisy-but-benign detections. Applied at ingest, fully audited.</p>
        <section class="panel">
          <h2>Add exception</h2>
          <form method="post" action="/ui/suppressions/add" class="sups-form">
            <input type="hidden" name="csrf_token" value="{_csrf_token("/ui/suppressions/add")}">
            <input name="name" placeholder="Name" required>
            <input name="rule_id" placeholder="Rule ID or *" value="*">
            <input name="entity" placeholder="Entity (opt): user:alice, host:x, ip:...">
            <select name="action"><option value="suppress">Suppress</option><option value="downgrade">Downgrade</option></select>
            <input name="downgrade_to" placeholder="Downgrade to (low/med/high)">
            <input name="expires_at" placeholder="Expires (ISO, opt)">
            <input name="reason" placeholder="Reason" required>
            <button>Add</button>
          </form>
        </section>
        {''.join(_suppression_row(request, item) for item in rows) or '<div class="empty">No suppressions yet.</div>'}
        """,
    )


@app.post("/ui/suppressions/add")
async def ui_add_suppression(request: Request) -> RedirectResponse:
    _require_permission(request, PERM_SUPPRESS_MANAGE)
    form = await request.form()
    _validate_csrf(request, form)
    actor = _actor(request, DEFAULT_CREATED_BY)
    get_store().add_suppression(
        rule_id=_form_str(form, "rule_id"),
        name=_form_str(form, "name"),
        action=_form_str(form, "action"),
        reason=_form_str(form, "reason"),
        entity=_form_str(form, "entity"),
        downgrade_to=_form_str(form, "downgrade_to"),
        expires_at=_form_str(form, "expires_at"),
        created_by=actor,
        tenant_id=_tenant(request),
    )
    return RedirectResponse("/suppressions", status_code=303)


@app.post("/ui/suppressions/{suppression_id}/delete")
async def ui_delete_suppression(request: Request, suppression_id: str) -> RedirectResponse:
    _require_permission(request, PERM_SUPPRESS_MANAGE)
    form = await request.form()
    _validate_csrf(request, form)
    actor = _actor(request, DEFAULT_CREATED_BY)
    get_store().delete_suppression(suppression_id, actor=actor, tenant_id=_tenant(request))
    return RedirectResponse("/suppressions", status_code=303)


@app.post("/ui/incidents/{incident_id}/update")
async def ui_update_incident(incident_id: str, request: Request) -> RedirectResponse:
    _require_permission(request, PERM_INCIDENT_UPDATE)
    form = await request.form()
    _validate_csrf(request, form)
    actor = _actor(request, "analyst")
    get_store().update_incident(
        incident_id,
        status=_form_str(form, "status"),
        assignee=_form_str(form, "assignee"),
        resolution=_form_str(form, "resolution"),
        actor=actor,
        tenant_id=_tenant(request),
    )
    return RedirectResponse(f"/incidents/{incident_id}", status_code=303)


@app.post("/ui/incidents/{incident_id}/comment")
async def ui_add_comment(incident_id: str, request: Request) -> RedirectResponse:
    _require_permission(request, PERM_INCIDENT_UPDATE)
    form = await request.form()
    _validate_csrf(request, form)
    actor = _actor(request, "analyst")
    body = (_form_str(form, "body") or "").strip()
    if body:
        get_store().add_incident_comment(incident_id, actor, body)
    return RedirectResponse(f"/incidents/{incident_id}", status_code=303)


def _incident_card(item: dict[str, Any]) -> str:
    return f"""
    <a class="card" href="/incidents/{_esc(item['incident_id'])}">
      <span class="badge">{_esc(item['severity'])}</span>
      <h2>{_esc(item['title'])}</h2>
      <p>Risk {_esc(item['risk_score'])} · {_esc(item['status'])}</p>
      <small>{_esc(item['created_at'])}</small>
    </a>
    """


def _proposal_row(request: Request, item: dict[str, Any]) -> str:
    status = item["status"]
    controls = ""
    if status == "pending":
        controls = f"""
        <form method="post" action="/ui/proposals/{_esc(item['proposal_id'])}/approve"><input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/proposals/{item['proposal_id']}/approve")}"><button>Approve</button></form>
        <form method="post" action="/ui/proposals/{_esc(item['proposal_id'])}/reject"><input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/proposals/{item['proposal_id']}/reject")}"><button class="secondary">Reject</button></form>
        """
    return f"""
    <div class="proposal">
      <div><strong>{_esc(item['action'])}</strong> → {_esc(item['target'])}<br><small>{_esc(item['data'].get('policy_reason', ''))}</small></div>
      <span class="badge">{_esc(status)}</span>
      {controls}
    </div>
    """


def _timeline_row(item: dict[str, Any]) -> str:
    score = item.get("risk_points", item.get("risk_score", ""))
    score_label = f" · risk {score}" if score != "" else ""
    return f"""
    <div class="timeline-item">
      <div class="dot"></div>
      <div>
        <small>{_esc(item.get('timestamp', ''))} · {_esc(item.get('kind', 'event'))}{_esc(score_label)}</small>
        <h3>{_esc(item.get('title', 'Untitled'))}</h3>
        <p>{_esc(item.get('summary', ''))}</p>
      </div>
    </div>
    """


def _comment_row(item: dict[str, Any]) -> str:
    return f"""
    <div class="comment">
      <div><strong>{_esc(item.get('actor', 'analyst'))}</strong> <small>{_esc(item.get('created_at', ''))}</small></div>
      <p>{_esc(item.get('body', ''))}</p>
    </div>
    """


def _suppression_row(request: Request, item: dict[str, Any]) -> str:
    target = f"{_esc(item['rule_id'])}"
    if item.get("entity"):
        target += f" / {_esc(item['entity'])}"
    downgrade = f" → {_esc(item['downgrade_to'])}" if item.get("downgrade_to") else ""
    return f"""
    <div class="proposal">
      <div>
        <strong>{_esc(item['action'])}{downgrade}</strong> {target}<br>
        <small>{_esc(item.get('name', ''))} — {_esc(item.get('reason', ''))}</small>
      </div>
      <span class="badge">{_esc('enabled' if item.get('enabled') else 'disabled')}</span>
      <form method="post" action="/ui/suppressions/{_esc(item['suppression_id'])}/delete"><input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/suppressions/{item['suppression_id']}/delete")}"><button class="secondary">Delete</button></form>
    </div>
    """


def _table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<div class='empty'>No rows.</div>"
    return "".join(f"<pre class='row'>{_esc(json.dumps(row, indent=2, sort_keys=True))}</pre>" for row in rows)


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_esc(title)}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#09111f; --panel:#111c2f; --card:#17243a; --text:#e9f0ff; --muted:#9fb0cc; --accent:#7dd3fc; --danger:#fb7185; --ok:#86efac; }}
    body {{ margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background: radial-gradient(circle at top left, #18375f, var(--bg) 42%); color:var(--text); }}
    main {{ width:min(1120px, calc(100% - 32px)); margin:32px auto; }}
    .hero, .panel {{ background:rgba(17,28,47,.88); border:1px solid rgba(125,211,252,.18); border-radius:24px; padding:28px; box-shadow:0 24px 80px rgba(0,0,0,.25); }}
    .hero {{ display:flex; align-items:center; justify-content:space-between; gap:24px; }}
    h1 {{ font-size:42px; line-height:1; margin:8px 0 12px; }} h2 {{ margin:0 0 10px; }}
    p, small {{ color:var(--muted); }} a {{ color:inherit; text-decoration:none; }}
    .eyebrow {{ color:var(--accent); text-transform:uppercase; letter-spacing:.14em; font-size:12px; font-weight:700; }}
    button {{ background:linear-gradient(135deg,#38bdf8,#818cf8); color:white; border:0; border-radius:999px; padding:10px 16px; font-weight:700; cursor:pointer; }}
    button.secondary {{ background:#27364f; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:16px; margin:20px 0; }}
    .card {{ background:rgba(23,36,58,.92); border:1px solid rgba(255,255,255,.08); border-radius:20px; padding:20px; transition:.15s ease; }} .card:hover {{ transform:translateY(-2px); border-color:var(--accent); }}
    .badge {{ display:inline-block; background:rgba(125,211,252,.14); color:var(--accent); border:1px solid rgba(125,211,252,.26); border-radius:999px; padding:4px 10px; font-size:12px; font-weight:700; }}
    .chips span {{ display:inline-block; margin:4px; padding:6px 10px; border-radius:999px; background:#23324c; color:#cfe0ff; }}
    .proposal {{ display:grid; grid-template-columns:1fr auto auto auto; align-items:center; gap:12px; padding:14px 0; border-top:1px solid rgba(255,255,255,.08); }}
    .search {{ display:grid; grid-template-columns:1fr 1fr auto; gap:10px; margin:18px 0; }}
    .sups-form {{ display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; margin:14px 0; }}
    .sups-form button {{ grid-column:1 / -1; }}
    .chiprow {{ display:flex; gap:8px; flex-wrap:wrap; margin:10px 0; }}
    .prov {{ display:inline-block; margin-left:8px; padding:3px 9px; border-radius:999px; font-size:12px; font-weight:700; letter-spacing:.04em; vertical-align:middle; }}
    .prov-local {{ background:#17324a; color:#8fd0ff; border:1px solid #2b587d; }}
    .prov-model {{ background:#3d2f14; color:#ffcf7a; border:1px solid #6d5220; }}
    .provenance-note {{ color:#93a4bf; font-size:13px; margin-top:6px; max-width:70ch; }}
    .chipbtn {{ background:#23324c; color:#cfe0ff; }}
    .chipbtn.active {{ background:linear-gradient(135deg,#38bdf8,#818cf8); color:white; }}
    .comment {{ padding:12px 0; border-top:1px solid rgba(255,255,255,.08); }}
    select {{ background:#101b2f; color:var(--text); border:1px solid rgba(255,255,255,.12); border-radius:999px; padding:11px 14px; }}
    input {{ background:#101b2f; color:var(--text); border:1px solid rgba(255,255,255,.12); border-radius:999px; padding:11px 14px; }}
    .timeline-item {{ display:grid; grid-template-columns:18px 1fr; gap:14px; padding:14px 0; border-top:1px solid rgba(255,255,255,.08); }}
    .timeline-item h3 {{ margin:4px 0; }} .dot {{ width:10px; height:10px; margin-top:7px; border-radius:999px; background:var(--accent); box-shadow:0 0 18px var(--accent); }}
    .links {{ margin:18px 0; }} .empty, .row {{ background:rgba(17,28,47,.8); border:1px solid rgba(255,255,255,.08); border-radius:16px; padding:16px; overflow:auto; }}
    pre {{ white-space:pre-wrap; color:#dbeafe; }}
    .search-nl {{ grid-template-columns:1fr auto; }}
    .translation {{ margin:18px 0; padding:22px; }}
    .translation .chips span {{ background:#1b2a43; border:1px solid rgba(125,211,252,.22); }}
    .translation .chips strong {{ color:var(--accent); margin-right:6px; font-weight:700;
      text-transform:uppercase; letter-spacing:.08em; font-size:11px; }}
    .copy {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px;
      border-radius:12px; margin-top:12px; max-width:100%; overflow:hidden;
      text-overflow:ellipsis; white-space:nowrap; }}
    .copy:hover {{ background:#33445f; }}
    /* .chipbtn only carried colour; the pill shape came from the `button`
       element selector, so the same class on an <a> rendered flat. */
    a.chipbtn {{ display:inline-block; border-radius:999px; padding:10px 16px;
      font-weight:700; border:1px solid rgba(255,255,255,.08); }}
    a.chipbtn:hover {{ border-color:var(--accent); }}
    a.chipbtn.active {{ background:linear-gradient(135deg,#38bdf8,#818cf8); color:white;
      border-color:transparent; }}
  </style>
</head>
<body><main>{body}</main></body>
</html>"""


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)

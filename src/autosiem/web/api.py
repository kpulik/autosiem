from __future__ import annotations

import hashlib
import html
import json
import re
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
from autosiem.normalization import load_json_bounded
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


def _tokens_equal(presented: str, expected: str) -> bool:
    """Constant-time token comparison that cannot raise on odd input.

    Starlette decodes headers as latin-1, so a single non-ASCII byte arrives
    as a non-ASCII ``str``, and ``secrets.compare_digest`` refuses to compare
    those with a TypeError, which surfaced as a 500 rather than a 401.
    Comparing the UTF-8 bytes accepts any input.
    """
    return secrets.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def _ingest_token_matches(request: Request) -> bool:
    """True when AUTOSIEM_INGEST_TOKEN is set and the request presents it.

    Checked in ``x-api-key`` and ``Authorization: Bearer`` independently, so a
    client can send the API token in one header and the ingest token in the
    other. Never the cookie: this is a machine endpoint.
    """
    token = os.environ.get("AUTOSIEM_INGEST_TOKEN")
    if not token:
        return False
    presented = [request.headers.get("x-api-key", "")]
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        presented.append(auth[len("bearer "):].strip())
    return any(_tokens_equal(value, token) for value in presented if value)


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


#: Audit actor recorded when a request authenticated without a named user.
_UNNAMED_ACTORS = {"api_token": "api-token", "ingest_token": "ingest-token"}


def _actor(request: Request) -> str:
    """Audit actor, derived only from how the request authenticated (SEC-009).

    Never from caller input. Endpoints used to take an ``?actor=`` parameter
    that shared-token mode wrote to the audit log verbatim, so any caller could
    record an approval under someone else's name. Without an RBAC user the
    actor names the credential that was used, which is all that is known.
    """
    user: Any = getattr(request.state, "user", None)
    name = getattr(user, "name", None)
    if name:
        return name
    return _UNNAMED_ACTORS.get(getattr(request.state, "auth_mode", ""), "unauthenticated")


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

    try:
        rbac = rbac_from_env()
    except ValueError:
        # An unreadable users file must deny access, but the caller is not the
        # problem and the message names a server path, so answer with a
        # generic 503 rather than a 401 or a leaked traceback.
        return _misconfigured(request)
    request.state.rbac = rbac
    token = _bearer_token(request)

    # RBAC mode
    if rbac.is_enabled():
        user = rbac.authenticate(token)
        if user is None:
            return _unauthorized(request, "unauthorized")
        request.state.user = user
        return await call_next(request)

    # SEC-007: a log collector should hold a write-only credential, not the
    # admin-equivalent API token. Outside RBAC mode the ingest token alone
    # authenticates POST /api/ingest, and nothing else.
    if path == "/api/ingest" and method == "POST" and _ingest_token_matches(request):
        request.state.auth_mode = "ingest_token"
        return await call_next(request)

    # Legacy mode: single shared token, caller is implicitly admin.
    api_token = os.environ.get("AUTOSIEM_API_TOKEN")
    if api_token:
        if not _tokens_equal(token or "", api_token):
            return _unauthorized(request, "unauthorized")
        request.state.auth_mode = "api_token"
        return await call_next(request)

    # No auth configured: fail closed unless explicitly insecure (SEC-001)
    if os.environ.get("AUTOSIEM_AUTH_INSECURE") != "1":
        return _unauthorized(
            request,
            "unauthorized: set AUTOSIEM_RBAC_FILE or AUTOSIEM_API_TOKEN "
            "(or AUTOSIEM_AUTH_INSECURE=1 for local development)",
        )

    request.state.auth_mode = "insecure"
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


def _misconfigured(request: Request) -> Any:
    """503 when the users file cannot be loaded (e.g. a plaintext token).

    Fails closed: no route runs. The detail stays generic because the
    underlying message names a filesystem path and the caller is not
    authenticated.
    """
    detail = "server auth configuration is invalid; see the AutoSIEM logs"
    if _is_readonly_ui_get(request.url.path, request.method):
        return HTMLResponse(
            f"<h1>503 Service Unavailable</h1><p>{html.escape(detail)}</p>",
            status_code=503,
        )
    return JSONResponse(status_code=503, content={"detail": detail})


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness only. Deliberately unauthenticated, so it says nothing else.

    It used to return the absolute database and rules paths, which told any
    caller about the host's directory layout (SEC-015). Operators who need the
    paths have the CLI and their own configuration.
    """
    return {"status": "ok"}


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
        store.audit(conn, actor=_actor(request), action=action, target=target, details=details, tenant_id=_tenant(request))


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
def api_approve(request: Request, proposal_id: str) -> dict[str, Any]:
    _require_permission(request, PERM_APPROVE)
    actor = _actor(request)
    proposal = get_store().decide_proposal(proposal_id, "approved", actor=actor, tenant_id=_tenant(request))
    if not proposal:
        raise HTTPException(status_code=404, detail="proposal_not_found")
    return proposal


@app.post("/api/proposals/{proposal_id}/reject")
def api_reject(request: Request, proposal_id: str) -> dict[str, Any]:
    _require_permission(request, PERM_APPROVE)
    actor = _actor(request)
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
def api_delete_suppression(request: Request, suppression_id: str) -> dict[str, Any]:
    _require_permission(request, PERM_SUPPRESS_MANAGE)
    actor = _actor(request)
    deleted = get_store().delete_suppression(suppression_id, actor=actor, tenant_id=_tenant(request))
    if not deleted:
        raise HTTPException(status_code=404, detail="suppression_not_found")
    return {"deleted": True, "suppression_id": suppression_id}


@app.post("/api/incidents/{incident_id}/update")
async def api_update_incident(incident_id: str, request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_INCIDENT_UPDATE)
    actor = _actor(request)
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
async def api_add_incident_comment(incident_id: str, request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_INCIDENT_UPDATE)
    actor = _actor(request)
    body = await request.json()
    comment = get_store().add_incident_comment(incident_id, actor, str(body.get("body", "")), tenant_id=_tenant(request))
    if not comment:
        raise HTTPException(status_code=404, detail="incident_not_found")
    return comment


def _pipeline(tenant_id: str | None = None, merge: bool = True) -> AutoSIEMPipeline:
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
        incident_store=store if merge else None,
    )


@app.post("/api/ingest/demo")
async def api_ingest_demo(request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_INGEST)
    tenant = _tenant(request)
    lines = [json.dumps(event) for event in DEMO_EVENTS]
    # Fixed timestamps: a replayed demo is not a continuation of the last one.
    pipeline = _pipeline(tenant_id=tenant, merge=False)
    result = pipeline.process_lines(lines)
    get_store().save_pipeline_result(result, tenant_id=tenant)
    return {"events": len(result.events), "findings": len(result.findings), "incidents": len(result.incidents), "llm_enabled": pipeline.llm is not None}


def _parse_ingest_payload(raw: bytes, content_type: str) -> list[dict[str, Any]]:
    """Decode an ingest body into a flat list of events.

    Supports NDJSON (one JSON object per line) for streamed/agent collectors,
    plus a single JSON object or an array of objects for API clients. Raises
    ``ValueError`` on any payload that is not valid JSON in a supported shape,
    or that nests deeper than ``MAX_JSON_DEPTH`` (SEC-016).
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
            events.append(load_json_bounded(line))
        return events
    data = load_json_bounded(stripped)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("event payload must be a JSON object or an array of objects")


def _ingest_authorized(request: Request) -> bool:
    """Allow when no ingest token is configured, or the request presents it.

    "No token configured" is not open: the middleware has already required
    RBAC, the API token, or an explicit AUTOSIEM_AUTH_INSECURE=1.
    """
    if not os.environ.get("AUTOSIEM_INGEST_TOKEN"):
        return True
    return _ingest_token_matches(request)


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
    pipeline = _pipeline(tenant_id=_tenant(request), merge=False)
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
async def api_set_rule(rule_id: str, request: Request) -> dict[str, Any]:
    _require_permission(request, PERM_RULES_MANAGE)
    actor = _actor(request)
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
    count = len(incidents)
    rows = "".join(_incident_row(item) for item in incidents)
    queue = (
        f"""
        <div class="tablewrap">
          <table class="queue">
            <thead><tr><th scope="col">Severity</th><th scope="col">Incident</th><th scope="col">Risk</th>
              <th scope="col">Status</th><th scope="col">Assignee</th><th scope="col">Opened</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
        """
        if incidents
        else '<div class="empty">No incidents yet. Load demo telemetry to replay a full attack chain against '
        '<span class="mono">user:alice</span>, or send events to <span class="mono">/api/ingest</span>.</div>'
    )
    filtered = bool(query or entity)
    noun = "incident" if count == 1 else "incidents"
    summary = f"<strong>{count}</strong> {noun}{' match' if filtered else ''}" if incidents or filtered else ""
    return _page(
        "AutoSIEM Incident Queue",
        f"""
        <section class="head">
          <div>
            <h1>Incidents</h1>
            <p class="lede">Detections are deterministic. The AI analyst only proposes actions, and anything
              that needs approval waits for a person. Every decision is audited.</p>
          </div>
          <form method="post" action="/ui/ingest-demo"><input type="hidden" name="csrf_token" value="{_csrf_token("/ui/ingest-demo")}"><button>Load demo telemetry</button></form>
        </section>
        <form class="search" method="get" action="/" role="search">
          <label class="sr-only" for="q-query">Search incidents</label>
          <input id="q-query" name="query" value="{_esc(query or '')}" placeholder="Search incidents: PowerShell, alice, high">
          <label class="sr-only" for="q-entity">Entity</label>
          <input id="q-entity" name="entity" value="{_esc(entity or '')}" placeholder="Entity: user:alice, ip:198.51.100.25">
          <button>Search</button>
        </form>
        <p class="meta count">{summary}</p>
        {queue}
        """,
        current="/",
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
    update_token = _csrf_token(f"/ui/incidents/{incident_id}/update")
    status_buttons = ""
    for s in INCIDENT_STATUSES:
        pressed = ' class="chipbtn active" aria-pressed="true"' if s == status else ' class="chipbtn"'
        status_buttons += (
            f'<form method="post" action="/ui/incidents/{_esc(incident_id)}/update">'
            f'<input type="hidden" name="csrf_token" value="{update_token}">'
            f'<input type="hidden" name="status" value="{_esc(s)}">'
            f'<button{pressed}>{_esc(s)}</button></form>'
        )
    entities = "".join(f"<span>{_esc(entity)}</span>" for entity in data.get("entities", []))
    techniques = "".join(f"<span>{_esc(t)}</span>" for t in data.get("mitre_attack", []))
    decision = investigation.get("decision", "none")
    confidence = round(float(investigation.get("confidence", 0)), 2)
    steps = len(timeline)
    return _page(
        html.escape(incident["title"]),
        f"""
        <p class="crumb"><a href="/">Incidents</a> <span aria-hidden="true">/</span> <span class="mono">{_esc(incident_id)}</span></p>
        <header class="incident-head row-{_sev_class(incident['severity'])}">
          <h1>{_esc(incident['title'])}</h1>
          <dl class="facts">
            <div><dt>Severity</dt><dd>{_sev(incident['severity'])}</dd></div>
            <div><dt>Risk</dt><dd class="risk">{_esc(incident['risk_score'])}</dd></div>
            <div><dt>Status</dt><dd>{_esc(status)}</dd></div>
            <div><dt>Assignee</dt><dd>{_esc(incident.get('assignee') or 'Unassigned')}</dd></div>
            <div><dt>Opened</dt><dd>{_ts(incident.get('created_at'))}</dd></div>
          </dl>
          <p class="lede">{_esc(data.get('summary', 'No summary available.'))}</p>
          {f'<div class="tagline"><span class="taglabel">Entities</span><div class="chips">{entities}</div></div>' if entities else ''}
          {f'<div class="tagline"><span class="taglabel">ATT&amp;CK techniques</span><div class="chips">{techniques}</div></div>' if techniques else ''}
        </header>
        <div class="incident">
          <section aria-labelledby="timeline-h">
            <h2 id="timeline-h">Attack timeline</h2>
            <p class="meta">{steps} {'step' if steps == 1 else 'steps'}, oldest first. Node colour is the step's severity.</p>
            {f'<ol class="timeline">{_timeline_rows(timeline)}</ol>' if timeline else '<p class="empty">No timeline events.</p>'}
          </section>
          <aside>
            <section class="block decision">
              <h2>AI analyst decision</h2>
              <p><strong class="mono">{_esc(decision)}</strong> confidence {_esc(confidence)} {_provenance_badge(investigation)}</p>
              <p class="provenance-note">{_provenance_note(investigation)}</p>
            </section>
            <section class="block">
              <h2>Triage</h2>
              <div class="chiprow" role="group" aria-label="Status">{status_buttons}</div>
              <form method="post" action="/ui/incidents/{_esc(incident_id)}/update" class="sups-form">
                <input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/incidents/{incident_id}/update")}">
                <label class="sr-only" for="t-assignee">Assignee</label>
                <input id="t-assignee" name="assignee" value="{_esc(incident.get('assignee') or '')}" placeholder="Assignee">
                <label class="sr-only" for="t-resolution">Resolution</label>
                <input id="t-resolution" name="resolution" value="{_esc(incident.get('resolution') or '')}" placeholder="Resolution or outcome">
                <button>Save triage</button>
              </form>
            </section>
            <section class="block">
              <h2>Proposed actions</h2>
              <p class="meta">Policy-gated: an action that needs approval waits here until someone approves or rejects it.</p>
              {''.join(_proposal_row(request, item) for item in proposals) or '<p class="empty">No action proposals.</p>'}
            </section>
            <section class="block">
              <h2>Comments</h2>
              {''.join(_comment_row(item) for item in comments) or '<p class="meta">No comments yet.</p>'}
              <form method="post" action="/ui/incidents/{_esc(incident_id)}/comment" class="sups-form">
                <input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/incidents/{incident_id}/comment")}">
                <label class="sr-only" for="c-body">Comment</label>
                <input id="c-body" name="body" placeholder="Add a comment">
                <button>Comment</button>
              </form>
            </section>
          </aside>
        </div>
        <details class="raw">
          <summary>Raw incident bundle (JSON)</summary>
          <pre>{_esc(json.dumps(bundle, indent=2, sort_keys=True))}</pre>
        </details>
        """,
        current="/",
    )


@app.get("/events", response_class=HTMLResponse)
def events_page(request: Request, query: str | None = None, entity: str | None = None) -> str:
    rows = api_events(request, limit=100, query=query, entity=entity)
    return _page(
        "AutoSIEM Events",
        f"""
        <h1>Events</h1>
        <p class="lede">The 100 most recent normalized events. Open a row's raw view for every field.</p>
        <form class="search" method="get" action="/events" role="search">
          <label class="sr-only" for="e-query">Search events</label>
          <input id="e-query" name="query" value="{_esc(query or '')}" placeholder="Search action, user, host, IP, raw JSON">
          <label class="sr-only" for="e-entity">Entity</label>
          <input id="e-entity" name="entity" value="{_esc(entity or '')}" placeholder="Entity: user:alice, host:vpn-1, ip:198.51.100.25">
          <button>Search</button>
        </form>
        {_table(rows)}
        """,
        current="/events",
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
      <h2>How this was read</h2>
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
        "<h1>Natural-language search</h1>"
        "<p class='lede'>Ask in plain English. The page shows which words became filters, so you can see "
        "exactly what was searched.</p>",
        f"""
        <form class="search search-nl" method="get" action="/search" role="search">
          <label class="sr-only" for="nl-q">Question</label>
          <input id="nl-q" name="q" value="{_esc(q or '')}" autofocus
                 placeholder="Ask in plain English: failed logins by user alice last 24h">
          <input type="hidden" name="target" value="{_esc(target)}">
          <button>Search</button>
        </form>
        <div class="chiprow" role="group" aria-label="Search target">{toggle}</div>
        """,
    ]
    if not q:
        body.append(f"<div class='panel'><h2>Try one</h2>"
                    f"<div class='chiprow'>{examples}</div></div>")
    else:
        found = api_search_nl(request, q=q, target=target)
        body.append(_translation_panel(found["translation"], found["cli"], target))
        total = found["total"]
        noun = target if total != 1 else target.rstrip("s")
        body.append(f"<p class='meta count'><strong>{total}</strong> {_esc(noun)} matched.</p>")
        body.append(_table(found["results"]))
        body.append(f"<div class='panel'><h2>Other examples</h2>"
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
    return _page("AutoSIEM Search", "".join(body), current="/search")


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request) -> str:
    rows = api_findings(request, limit=100)
    return _page(
        "AutoSIEM Findings",
        "<h1>Findings</h1><p class='lede'>The 100 most recent rule and behavioral detections, before they are grouped into incidents.</p>"
        f"{_table(rows)}",
        current="/findings",
    )


@app.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request) -> str:
    rows = api_sources(request)
    table = _table(rows) if rows else (
        '<div class="empty">No events yet. Ingest something (the demo, <span class="mono">/api/ingest</span>, '
        'or the syslog listener) to see per-source health.</div>'
    )
    return _page(
        "AutoSIEM Sources",
        "<h1>Sources</h1><p class='lede'>Per-source ingest health from the events store. A source whose "
        f"last event is old has probably stopped sending.</p>{table}",
        current="/sources",
    )


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request) -> str:
    rows = get_store().list_audit(limit=100, tenant_id=_tenant(request))
    return _page(
        "AutoSIEM Audit",
        "<h1>Audit log</h1><p class='lede'>The 100 most recent entries in the hash-chained audit log. "
        "Run <span class='mono'>autosiem audit-verify</span> to check the chain.</p>"
        f"{_table(rows)}",
        current="/audit",
    )


@app.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request) -> str:
    rules = api_rules(request)
    rows = "".join(_rule_row(request, item) for item in rules["rules"])
    total = len(rules["rules"])
    overrides = len(rules["overrides"])
    return _page(
        "AutoSIEM Detection Rules",
        f"""
        <h1>Detection rules</h1>
        <p class="lede">{total} {'rule' if total == 1 else 'rules'}, {overrides} saved
          {'override' if overrides == 1 else 'overrides'}. Turning a rule on or off takes effect on the next ingest.</p>
        <div class="list">{rows or '<div class="empty">No rules found.</div>'}</div>
        """,
        current="/rules",
    )


def _rule_row(request: Request, item: dict[str, Any]) -> str:
    button = "Disable" if item["enabled"] else "Enable"
    cls = "secondary" if item["enabled"] else ""
    toggle = f"""
    <form method="post" action="/ui/rules/{_esc(item['rule_id'])}/toggle" class="inline">
      <input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/rules/{item['rule_id']}/toggle")}">
      <input type="hidden" name="enabled" value="{'0' if item['enabled'] else '1'}">
      <button class="{cls}">{button}</button>
    </form>
    """
    state = "enabled" if item["enabled"] else "disabled"
    techniques = "".join(f"<span>{_esc(t)}</span>" for t in item.get("mitre_attack", []))
    return f"""
    <div class="item{'' if item['enabled'] else ' is-off'}">
      <div>
        <h3><span class="mono">{_esc(item['rule_id'])}</span> {_esc(item['name'])}</h3>
        <p class="meta">{_esc(item['description'])}</p>
        {f'<div class="chips">{techniques}</div>' if techniques else ''}
      </div>
      <div class="actions"><span class="state state-{state}">{state}</span>{toggle}</div>
    </div>
    """


@app.post("/ui/rules/{rule_id}/toggle")
async def ui_toggle_rule(rule_id: str, request: Request) -> RedirectResponse:
    _require_permission(request, PERM_RULES_MANAGE)
    form = await request.form()
    _validate_csrf(request, form)
    enabled = _form_str(form, "enabled") == "1"
    actor = _actor(request)
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
        <h1>Suppressions and exceptions</h1>
        <p class="lede">Suppress or downgrade detections that are noisy but benign. They apply at ingest and every change is audited.</p>
        <section class="panel">
          <h2>Add an exception</h2>
          <form method="post" action="/ui/suppressions/add" class="sups-form">
            <input type="hidden" name="csrf_token" value="{_csrf_token("/ui/suppressions/add")}">
            <label class="sr-only" for="s-name">Name</label><input id="s-name" name="name" placeholder="Name" required>
            <label class="sr-only" for="s-rule">Rule ID</label><input id="s-rule" name="rule_id" placeholder="Rule ID or *" value="*">
            <label class="sr-only" for="s-entity">Entity</label><input id="s-entity" name="entity" placeholder="Entity (optional): user:alice, host:x">
            <label class="sr-only" for="s-action">Action</label><select id="s-action" name="action"><option value="suppress">Suppress</option><option value="downgrade">Downgrade</option></select>
            <label class="sr-only" for="s-to">Downgrade to</label><input id="s-to" name="downgrade_to" placeholder="Downgrade to (low, medium, high)">
            <label class="sr-only" for="s-exp">Expires</label><input id="s-exp" name="expires_at" placeholder="Expires (ISO date, optional)">
            <label class="sr-only" for="s-reason">Reason</label><input id="s-reason" name="reason" placeholder="Reason" required>
            <button>Add exception</button>
          </form>
        </section>
        <div class="list">{''.join(_suppression_row(request, item) for item in rows) or '<div class="empty">No suppressions yet.</div>'}</div>
        """,
        current="/suppressions",
    )


@app.post("/ui/suppressions/add")
async def ui_add_suppression(request: Request) -> RedirectResponse:
    _require_permission(request, PERM_SUPPRESS_MANAGE)
    form = await request.form()
    _validate_csrf(request, form)
    actor = _actor(request)
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
    actor = _actor(request)
    get_store().delete_suppression(suppression_id, actor=actor, tenant_id=_tenant(request))
    return RedirectResponse("/suppressions", status_code=303)


@app.post("/ui/incidents/{incident_id}/update")
async def ui_update_incident(incident_id: str, request: Request) -> RedirectResponse:
    _require_permission(request, PERM_INCIDENT_UPDATE)
    form = await request.form()
    _validate_csrf(request, form)
    actor = _actor(request)
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
    actor = _actor(request)
    body = (_form_str(form, "body") or "").strip()
    if body:
        get_store().add_incident_comment(incident_id, actor, body)
    return RedirectResponse(f"/incidents/{incident_id}", status_code=303)


#: Severities the UI colours. Anything else renders neutral rather than being
#: interpolated into a class name.
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})


def _sev_class(severity: Any) -> str:
    value = str(severity or "").lower()
    return value if value in _SEVERITIES else "none"


def _sev(severity: Any) -> str:
    return f'<span class="sev sev-{_sev_class(severity)}">{_esc(severity or "unknown")}</span>'


_ISO_TIME = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?")


def _ts(value: Any) -> str:
    """An ISO timestamp as `2026-08-04 10:00:00 UTC`, keeping the original in `datetime`.

    A naive timestamp gets no zone label: calling it UTC would be a guess.
    """
    text = str(value or "")
    match = _ISO_TIME.fullmatch(text)
    if not match:
        return _esc(text)
    date, clock, zone = match.groups()
    label = " UTC" if zone in ("Z", "+00:00") else (f" {zone}" if zone else "")
    return f'<time datetime="{_esc(text)}">{_esc(date)} {_esc(clock)}{_esc(label)}</time>'


def _incident_row(item: dict[str, Any]) -> str:
    sev = _sev_class(item["severity"])
    return f"""
    <tr class="row-{sev}">
      <td>{_sev(item['severity'])}</td>
      <td><a class="title" href="/incidents/{_esc(item['incident_id'])}">{_esc(item['title'])}</a></td>
      <td class="risk">{_esc(item['risk_score'])}</td>
      <td>{_esc(item['status'])}</td>
      <td class="{'' if item.get('assignee') else 'meta'}">{_esc(item.get('assignee') or 'Unassigned')}</td>
      <td class="mono">{_ts(item.get('created_at'))}</td>
    </tr>
    """


def _proposal_row(request: Request, item: dict[str, Any]) -> str:
    status = item["status"]
    controls = ""
    if status == "pending":
        controls = f"""
        <form method="post" action="/ui/proposals/{_esc(item['proposal_id'])}/approve"><input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/proposals/{item['proposal_id']}/approve")}"><button>Approve</button></form>
        <form method="post" action="/ui/proposals/{_esc(item['proposal_id'])}/reject"><input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/proposals/{item['proposal_id']}/reject")}"><button class="secondary">Reject</button></form>
        """
    reason = item["data"].get("policy_reason", "")
    return f"""
    <div class="item">
      <div>
        <h3><span class="mono">{_esc(item['action'])}</span> on <span class="mono">{_esc(item['target'])}</span></h3>
        {f'<p class="meta">{_esc(reason)}</p>' if reason else ''}
      </div>
      <div class="actions"><span class="state state-{_esc(status)}">{_esc(status)}</span>{controls}</div>
    </div>
    """


def _timeline_time(value: Any, show_date: bool) -> str:
    """Time of day on every step; the date only where it changes.

    A kill chain usually spans minutes, so repeating the date on each of twenty
    steps is noise that pushes the zone onto a second line.
    """
    text = str(value or "")
    match = _ISO_TIME.fullmatch(text)
    if not match:
        return _esc(text)
    date, clock, zone = match.groups()
    label = " UTC" if zone in ("Z", "+00:00") else (f" {zone}" if zone else "")
    day = f'<span class="tl-date">{_esc(date)}</span>' if show_date else ""
    return f'{day}<time datetime="{_esc(text)}">{_esc(clock)}{_esc(label)}</time>'


def _timeline_rows(timeline: list[dict[str, Any]]) -> str:
    rows, previous = [], None
    for item in timeline:
        match = _ISO_TIME.fullmatch(str(item.get("timestamp") or ""))
        day = match.group(1) if match else None
        rows.append(_timeline_row(item, show_date=day != previous))
        previous = day
    return "".join(rows)


def _timeline_row(item: dict[str, Any], show_date: bool = True) -> str:
    score = item.get("risk_points", item.get("risk_score", ""))
    kind = str(item.get("kind", "event"))
    kind_label = "Incident opened" if kind == "incident_created" else kind.replace("_", " ").capitalize()
    risk_label = f", +{score} risk" if score not in ("", None) else ""
    summary = item.get("summary", "")
    return f"""
    <li class="tl-item tl-{_sev_class(item.get('severity'))}">
      <span class="tl-node" aria-hidden="true"></span>
      <span class="tl-time mono">{_timeline_time(item.get('timestamp', ''), show_date)}</span>
      <div class="tl-body">
        <h3>{_esc(item.get('title', 'Untitled'))}</h3>
        {f'<p class="mono">{_esc(summary)}</p>' if summary else ''}
        <p class="meta">{_esc(kind_label)}{_esc(risk_label)}</p>
      </div>
    </li>
    """


def _comment_row(item: dict[str, Any]) -> str:
    return f"""
    <div class="comment">
      <p><strong>{_esc(item.get('actor', 'analyst'))}</strong> <span class="meta mono">{_ts(item.get('created_at', ''))}</span></p>
      <p>{_esc(item.get('body', ''))}</p>
    </div>
    """


def _suppression_row(request: Request, item: dict[str, Any]) -> str:
    target = f"{_esc(item['rule_id'])}"
    if item.get("entity"):
        target += f" / {_esc(item['entity'])}"
    downgrade = f" to {_esc(item['downgrade_to'])}" if item.get("downgrade_to") else ""
    state = "enabled" if item.get("enabled") else "disabled"
    name = _esc(item.get("name", ""))
    reason = _esc(item.get("reason", ""))
    return f"""
    <div class="item">
      <div>
        <h3>{_esc(item['action']).capitalize()}{downgrade} <span class="mono">{target}</span></h3>
        <p class="meta">{name}{': ' + reason if reason else ''}</p>
      </div>
      <div class="actions"><span class="state state-{state}">{state}</span><form method="post" action="/ui/suppressions/{_esc(item['suppression_id'])}/delete"><input type="hidden" name="csrf_token" value="{_csrf_token(f"/ui/suppressions/{item['suppression_id']}/delete")}"><button class="secondary">Delete</button></form></div>
    </div>
    """


#: Columns a generic table shows when a row has them, in this order. Every row
#: still carries its full JSON behind "Raw", so nothing is hidden, only folded.
_TABLE_COLUMNS = (
    "timestamp", "created_at", "severity", "risk_score", "risk_points", "rule_id", "rule_name",
    "title", "status", "action", "actor", "target", "user", "host", "src_ip", "category",
    "source", "events", "first_seen", "last_seen",
)
_COLUMN_LABELS = {
    "timestamp": "Time", "created_at": "Created", "risk_score": "Risk", "risk_points": "Risk",
    "rule_id": "Rule", "rule_name": "Rule name", "src_ip": "Source IP", "first_seen": "First seen",
    "last_seen": "Last seen",
}
_TIME_COLUMNS = frozenset({"timestamp", "created_at", "updated_at", "first_seen", "last_seen"})
_MONO_COLUMNS = frozenset({"rule_id", "action", "actor", "target", "user", "host", "src_ip", "source", "category"})
_MAX_COLUMNS = 7


def _cell(key: str, row: dict[str, Any]) -> str:
    value = row.get(key)
    if key == "severity":
        return f"<td>{_sev(value)}</td>"
    if key in _TIME_COLUMNS:
        return f"<td class='mono'>{_ts(value)}</td>"
    if key == "title" and row.get("incident_id"):
        return f"<td><a class='title' href='/incidents/{_esc(row['incident_id'])}'>{_esc(value)}</a></td>"
    text = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else ("" if value is None else str(value))
    if len(text) > 90:
        text = text[:87] + "..."
    cls = " class='mono'" if key in _MONO_COLUMNS else (" class='risk'" if key in ("risk_score", "risk_points", "events") else "")
    return f"<td{cls}>{_esc(text)}</td>"


def _table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<div class='empty'>No rows.</div>"
    columns = [c for c in _TABLE_COLUMNS if any(c in row for row in rows)][:_MAX_COLUMNS]
    if not columns:
        columns = list(rows[0])[:_MAX_COLUMNS - 1]
    head = "".join(f"<th scope='col'>{_esc(_COLUMN_LABELS.get(c, c.replace('_', ' ').capitalize()))}</th>" for c in columns)
    body = "".join(
        "<tr>" + "".join(_cell(c, row) for c in columns)
        + f"<td><details class='raw'><summary>Raw</summary><pre class='row'>{_esc(json.dumps(row, indent=2, sort_keys=True))}</pre></details></td></tr>"
        for row in rows
    )
    return f"<div class='tablewrap'><table><thead><tr>{head}<th scope='col'><span class='sr-only'>Raw JSON</span></th></tr></thead><tbody>{body}</tbody></table></div>"


#: The top bar. Paths match the routes above; the active one gets aria-current.
_NAV = (
    ("/", "Incidents"), ("/search", "Search"), ("/events", "Events"), ("/findings", "Findings"),
    ("/rules", "Rules"), ("/sources", "Sources"), ("/suppressions", "Suppressions"),
    ("/audit", "Audit log"), ("/docs", "API docs"),
)


def _nav(current: str | None) -> str:
    links = []
    for href, label in _NAV:
        marker = ' aria-current="page"' if href == current else ""
        links.append(f'<a href="{href}"{marker}>{label}</a>')
    return "".join(links)


def _page(title: str, body: str, current: str | None = None) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_esc(title)}</title>
  <style>
    /* Palette in OKLCH. Every surface shares one hue (261) and its lightness
       steps are evenly spaced 0.05 apart - that even spacing is the whole
       point, and it is what the old hex ramp could not express, because sRGB
       lightness is not perceptual. Each token carries a hex fallback first:
       a browser that does not parse oklch() keeps the earlier declaration, so
       an older pinned SOC browser still renders the intended colours. */
    :root {{
      color-scheme: dark;
      --bg:#08101e;            --bg:oklch(0.175 0.032 261);
      --panel:#111c2e;         --panel:oklch(0.225 0.040 261);
      --card:#1b283e;          --card:oklch(0.275 0.046 261);
      --raised:#25344e;        --raised:oklch(0.325 0.050 261);
      --text:#e8f0ff;          --text:oklch(0.954 0.022 261);
      --dim:#d1e0fb;           --dim:oklch(0.904 0.040 261);
      --muted:#9fb0cc;         --muted:oklch(0.753 0.045 261);
      /* One accent, used for links, focus and the primary button only. Colour
         everywhere else is severity: danger carries the most chroma because it
         is the alarm and has to win against everything else on screen. */
      --accent:#7dd3fc;        --accent:oklch(0.828 0.101 230);
      --accent-deep:#818cf8;   --accent-deep:oklch(0.680 0.158 277);
      --danger:#fb7186;        --danger:oklch(0.719 0.169 13);
      --ok:#87efab;            --ok:oklch(0.871 0.136 154);
      --warn:#ffcf7a;          --warn:oklch(0.879 0.117 81);
      /* Lines and washes are derived from the accent and the text rather than
         from white, so nothing drifts grey against the blue surfaces. */
      --line:oklch(0.828 0.101 230 / 0.22);
      --line-soft:oklch(0.954 0.022 261 / 0.10);
      --wash:oklch(0.828 0.101 230 / 0.14);
      --wash-edge:oklch(0.828 0.101 230 / 0.30);
      /* A console, not a dashboard: technical faces for anything that names
         a thing (headings, labels, identifiers), a humanist face for prose.
         System stacks only - no webfont request, so this renders the same in
         an air-gapped SOC as it does here. */
      --font-display: ui-monospace, "SF Mono", "JetBrains Mono", "Cascadia Mono", Menlo, Consolas, monospace;
      --font-body: ui-sans-serif, system-ui, -apple-system, "Segoe UI Variable Text", "Segoe UI", "Helvetica Neue", sans-serif;
      --radius: 6px;
      --time-col: 8.5rem;
    }}
    body {{ margin:0; font-family: var(--font-body); background:var(--bg); color:var(--text); font-size:15px; line-height:1.55; }}
    * {{ box-sizing:border-box; }}
    a {{ color:var(--accent); text-underline-offset:3px; text-decoration-thickness:1px; }}
    :focus-visible {{ outline:2px solid var(--accent); outline-offset:2px; }}
    .sr-only {{ position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }}
    .skip {{ position:absolute; left:-999px; top:8px; background:var(--accent); color:var(--bg); padding:8px 12px; border-radius:var(--radius); z-index:10; }}
    .skip:focus {{ left:12px; }}

    /* shell: one persistent bar instead of a link strip at the foot of each page */
    .top {{ position:sticky; top:0; z-index:5; display:flex; align-items:center; gap:28px; padding:10px 32px;
      background:var(--panel); border-bottom:1px solid var(--line-soft); }}
    .brand {{ font-family:var(--font-display); font-weight:700; color:var(--text); text-decoration:none; letter-spacing:-.01em; }}
    .top nav {{ display:flex; flex-wrap:wrap; gap:2px; }}
    .top nav a {{ color:var(--muted); text-decoration:none; font-size:14px; padding:6px 10px; border-radius:var(--radius); }}
    .top nav a:hover {{ color:var(--text); background:var(--card); }}
    .top nav a[aria-current="page"] {{ color:var(--text); background:var(--card); box-shadow:inset 0 -2px 0 var(--accent); }}
    main {{ width:min(1200px, calc(100% - 48px)); margin:28px auto 72px; }}

    /* type */
    h1 {{ font-family:var(--font-display); font-size:28px; line-height:1.15; letter-spacing:-.02em; margin:0 0 6px; }}
    h2 {{ font-family:var(--font-display); font-size:16px; letter-spacing:-.01em; margin:0 0 10px; }}
    h3 {{ font-family:var(--font-display); font-size:15px; margin:0; font-weight:600; }}
    p {{ margin:0 0 8px; }}
    .lede {{ color:var(--muted); max-width:72ch; }}
    .meta, small {{ color:var(--muted); font-size:14px; }}
    .mono {{ font-family:var(--font-display); font-size:13px; }}
    .risk {{ font-family:var(--font-display); font-weight:700; font-variant-numeric:tabular-nums; }}
    .crumb {{ color:var(--muted); font-size:14px; margin-bottom:10px; }}
    .crumb .mono {{ color:var(--muted); }}
    .count {{ margin:0 0 10px; }}

    /* controls */
    button {{ font:inherit; font-size:14px; font-weight:600; background:var(--accent); color:var(--bg);
      border:1px solid var(--accent); border-radius:var(--radius); padding:8px 14px; cursor:pointer; }}
    button:hover {{ background:var(--accent-deep); border-color:var(--accent-deep); }}
    button.secondary, .chipbtn {{ background:var(--raised); color:var(--dim); border-color:var(--line-soft); }}
    button.secondary:hover, .chipbtn:hover {{ background:var(--card); border-color:var(--accent); }}
    .chipbtn.active, a.chipbtn.active {{ background:var(--accent); color:var(--bg); border-color:var(--accent); }}
    a.chipbtn {{ display:inline-block; font-size:14px; font-weight:600; padding:6px 12px; border:1px solid var(--line-soft);
      border-radius:var(--radius); text-decoration:none; }}
    input, select {{ font:inherit; font-size:14px; min-width:0; background:var(--bg); color:var(--text);
      border:1px solid var(--line); border-radius:var(--radius); padding:8px 10px; }}
    input::placeholder {{ color:var(--muted); }}
    .search {{ display:grid; grid-template-columns:2fr 1.4fr auto; gap:8px; margin:0 0 18px; }}
    .search-nl {{ grid-template-columns:1fr auto; }}
    .sups-form {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(190px, 1fr)); gap:8px; margin:12px 0 0; }}
    .sups-form button {{ justify-self:start; }}
    .chiprow {{ display:flex; flex-wrap:wrap; gap:6px; margin:8px 0; }}
    .chiprow form, .actions form {{ margin:0; }}

    /* page head */
    .head {{ display:flex; justify-content:space-between; align-items:flex-end; gap:20px 32px; flex-wrap:wrap; margin-bottom:22px; }}
    .head form {{ margin:0; }}

    /* severity: the only place colour carries meaning */
    .sev {{ display:inline-block; font-family:var(--font-display); font-size:12px; font-weight:700; line-height:1.4;
      padding:1px 7px; border:1px solid currentColor; border-radius:4px; white-space:nowrap; }}
    .sev-critical {{ color:var(--danger); }} .sev-high {{ color:var(--warn); }} .sev-medium {{ color:var(--accent); }}
    .sev-low, .sev-informational, .sev-none {{ color:var(--muted); }}
    .row-critical {{ --stripe:var(--danger); }} .row-high {{ --stripe:var(--warn); }} .row-medium {{ --stripe:var(--accent); }}
    .row-low, .row-informational, .row-none {{ --stripe:var(--raised); }}

    /* tables */
    .tablewrap {{ overflow-x:auto; border:1px solid var(--line-soft); border-radius:var(--radius); background:var(--bg); }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }}
    th {{ text-align:left; font-weight:600; color:var(--muted); background:var(--panel); padding:9px 12px;
      border-bottom:1px solid var(--line); white-space:nowrap; }}
    td {{ padding:10px 12px; border-bottom:1px solid var(--line-soft); vertical-align:top; }}
    tbody tr:last-child td {{ border-bottom:0; }}
    tbody tr:hover {{ background:var(--panel); }}
    td.mono {{ color:var(--dim); white-space:nowrap; }}
    .queue td:first-child {{ box-shadow:inset 3px 0 0 var(--stripe); }}
    a.title {{ color:var(--text); font-weight:600; text-decoration:none; }}
    a.title:hover {{ color:var(--accent); text-decoration:underline; }}
    details.raw summary {{ cursor:pointer; color:var(--accent); font-size:13px; }}
    pre {{ font-family:var(--font-display); font-size:12.5px; line-height:1.5; white-space:pre-wrap; word-break:break-word;
      color:var(--dim); background:var(--panel); border:1px solid var(--line-soft); border-radius:var(--radius);
      padding:12px; margin:8px 0 0; max-height:440px; overflow:auto; }}
    td pre {{ min-width:min(60ch, 70vw); }}
    .empty {{ color:var(--muted); padding:18px; border:1px dashed var(--line); border-radius:var(--radius); }}

    /* incident page */
    .incident-head {{ border-left:3px solid var(--stripe); padding-left:18px; margin-bottom:28px; }}
    .facts {{ display:flex; flex-wrap:wrap; gap:8px 32px; margin:14px 0 14px; }}
    .facts div {{ display:flex; flex-direction:column; gap:2px; }}
    .facts dt {{ color:var(--muted); font-size:13px; }}
    .facts dd {{ margin:0; font-family:var(--font-display); font-size:14px; font-weight:700; }}
    .tagline {{ display:flex; flex-wrap:wrap; align-items:baseline; gap:6px 12px; margin-top:8px; }}
    .taglabel {{ color:var(--muted); font-size:13px; min-width:9rem; }}
    .chips {{ display:flex; flex-wrap:wrap; gap:6px; }}
    .chips span {{ font-family:var(--font-display); font-size:13px; color:var(--dim); background:var(--card);
      border:1px solid var(--line-soft); border-radius:4px; padding:2px 8px; }}
    .incident {{ display:grid; grid-template-columns:minmax(0, 1.55fr) minmax(300px, 1fr); gap:24px 40px; align-items:start; }}
    .block {{ border-top:1px solid var(--line-soft); padding-top:16px; margin-bottom:26px; }}
    .block:first-child {{ border-top:0; padding-top:0; }}
    .decision p strong {{ color:var(--text); }}
    .prov {{ display:inline-block; margin-left:6px; padding:1px 8px; border-radius:4px; font-size:12px; font-weight:700; vertical-align:middle; }}
    /* Provenance reads at a glance: local analysis in the brand hue, a
       model-reported result in the warning hue, because the autonomy gate
       treats them differently and the badge should say so. */
    .prov-local {{ background:var(--wash); color:var(--accent); border:1px solid var(--wash-edge); }}
    .prov-model {{ background:oklch(0.879 0.117 81 / 0.16); color:var(--warn); border:1px solid oklch(0.879 0.117 81 / 0.34); }}
    .provenance-note {{ color:var(--muted); font-size:13px; margin-top:6px; max-width:70ch; }}

    /* the attack timeline: the one bold element. A rail with the time on the
       left and each step's severity on its node, so the kill chain reads in
       order and the dangerous steps stand out without reading a word. */
    .timeline {{ list-style:none; margin:10px 0 0; padding:0; position:relative; }}
    .timeline::before {{ content:""; position:absolute; left:calc(var(--time-col) + 11px); top:8px; bottom:8px; width:2px; background:var(--line); }}
    .tl-item {{ position:relative; display:grid; grid-template-columns:var(--time-col) 1fr; gap:0 34px; padding:9px 0; }}
    .tl-time {{ color:var(--muted); text-align:right; padding-top:2px; line-height:1.35; white-space:nowrap; }}
    .tl-date {{ display:block; color:var(--dim); font-weight:700; margin-bottom:2px; }}
    .tl-node {{ position:absolute; left:calc(var(--time-col) + 6px); top:14px; width:12px; height:12px; border-radius:50%;
      background:var(--node, var(--muted)); box-shadow:0 0 0 3px var(--bg); }}
    .tl-critical {{ --node:var(--danger); }} .tl-high {{ --node:var(--warn); }} .tl-medium {{ --node:var(--accent); }}
    .tl-critical .tl-node {{ width:14px; height:14px; left:calc(var(--time-col) + 5px); top:13px; }}
    .tl-body p.mono {{ color:var(--dim); margin:2px 0; overflow-wrap:anywhere; }}
    .tl-body .meta {{ font-size:13px; }}

    /* list rows: proposals, rules, suppressions, comments */
    .item {{ display:grid; grid-template-columns:minmax(0, 1fr) auto; gap:8px 16px; align-items:center; padding:12px 0;
      border-top:1px solid var(--line-soft); }}
    .list .item:first-child {{ border-top:0; }}
    .item h3 {{ font-weight:600; margin-bottom:3px; }}
    .item .meta {{ margin:0 0 4px; max-width:90ch; }}
    .item.is-off h3 {{ color:var(--muted); }}
    .actions {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; justify-content:flex-end; }}
    .state {{ font-family:var(--font-display); font-size:12px; color:var(--muted); }}
    .state-enabled, .state-approved {{ color:var(--ok); }} .state-pending {{ color:var(--warn); }} .state-rejected {{ color:var(--danger); }}
    .comment {{ padding:10px 0; border-top:1px solid var(--line-soft); }}
    .comment p {{ margin:0 0 4px; }}
    .panel {{ background:var(--panel); border:1px solid var(--line-soft); border-radius:var(--radius); padding:16px 18px; margin:16px 0; }}
    .translation .chips strong {{ color:var(--accent); margin-right:6px; font-weight:700; }}
    .copy {{ font-family:var(--font-display); font-size:13px; margin-top:10px; max-width:100%; overflow:hidden;
      text-overflow:ellipsis; white-space:nowrap; }}
    details.raw > summary {{ margin-top:4px; }}
    main > details.raw {{ margin-top:8px; border-top:1px solid var(--line-soft); padding-top:16px; }}

    @media (max-width: 900px) {{
      .incident {{ grid-template-columns:1fr; }}
    }}
    @media (max-width: 720px) {{
      .top {{ flex-wrap:wrap; gap:6px 16px; padding:10px 16px; }}
      main {{ width:calc(100% - 32px); margin-top:20px; }}
      .search, .search-nl {{ grid-template-columns:1fr; }}
      .queue th:nth-child(5), .queue td:nth-child(5), .queue th:nth-child(6), .queue td:nth-child(6) {{ display:none; }}
      :root {{ --time-col:0px; }}
      .timeline::before {{ left:5px; }}
      .tl-item {{ grid-template-columns:1fr; padding-left:28px; }}
      .tl-time {{ text-align:left; }}
      .tl-node, .tl-critical .tl-node {{ left:0; }}
      .item {{ grid-template-columns:1fr; }}
      .actions {{ justify-content:flex-start; }}
    }}
    @media (prefers-reduced-motion: reduce) {{ * {{ transition:none !important; scroll-behavior:auto !important; }} }}
  </style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top">
  <a class="brand" href="/">AutoSIEM</a>
  <nav aria-label="Sections">{_nav(current)}</nav>
</header>
<main id="main">{body}</main>
</body>
</html>"""


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)

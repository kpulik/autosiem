# Security Policy & Vulnerability Disclosure

## Supported Versions

AutoSIEM is currently in alpha (`v0.1.0`). Security updates are applied directly to the `main` branch.

| Version | Supported |
|---|---|
| 0.1.x (main) | :white_check_mark: Yes |
| < 0.1.0 | :x: No |

## Reporting a Vulnerability

If you discover a security vulnerability in AutoSIEM, please report it privately:

1. **GitHub Security Advisory**: Please report vulnerabilities privately through GitHub Security Advisories.
2. **Details**: Include affected component, steps to reproduce, impact, and proposed fix if available.
3. **Response Time**: We acknowledge reports within 48 hours and aim for a fix within 7 days.

Please do **not** disclose vulnerabilities publicly until a fix is released.

## Security Architecture & Hardening Status

AutoSIEM follows zero-trust and defense-in-depth principles:

### Core Protections (Implemented)

1. **Authentication & RBAC (`src/autosiem/rbac.py`)**
   - Fine-grained role permissions (`admin`, `analyst`, `ingest`, `viewer`).
   - Default-closed middleware covering `/api/*`, `/ui/*` and every rendered UI page. Only `/health`, `/metrics` and the generated API docs stay open. `AUTOSIEM_AUTH_INSECURE=1` reopens everything for local development.
   - Secure token hashing (`sha256`); tokens are never stored or written in plaintext.
   - Token rotation and revocation (`users rotate|revoke`, `POST /api/users/{name}/rotate-token|revoke-token`), gated on `users:manage`.
   - Tokens are accepted as `Authorization: Bearer`, `x-api-key`, or an `autosiem_token` cookie, so the browser UI is usable under RBAC.

2. **UI Protection (`src/autosiem/web/api.py`)**
   - Rendered UI pages (`/`, `/events`, `/findings`, `/sources`, `/audit`, `/rules`, `/suppressions`, `/incidents/{id}`) require authentication. They were previously open so a workstation install stayed convenient, which also served the audit log and every incident detail to any unauthenticated caller that could reach the port.
   - State-changing UI POST routes additionally require the caller's role permission.
   - CSRF validation is **on by default**: the secret is `AUTOSIEM_CSRF_SECRET` or a per-process random value when unset, and tokens are bound to the form's target path so one cannot be replayed against a different action.

3. **Ingest Protection (`src/autosiem/web/api.py`)**
   - Payload size limit (`AUTOSIEM_MAX_INGEST_BYTES`, default 10MB).
   - Maximum event count per batch (`AUTOSIEM_MAX_INGEST_EVENTS`, default 10,000).

4. **Listener Hardening (`src/autosiem/listeners.py`)**
   - UDP Syslog/CEF listener IP allowlisting (`allowed_hosts`).
   - Asynchronous `ThreadPoolExecutor` worker pool to prevent socket thread starvation.

5. **SQL & Command Security (`src/autosiem/storage.py`, `src/autosiem/querygen.py`)**
   - Parameterized queries (`?` placeholders) across all storage search endpoints.
   - Zero shell execution in core analysis modules.

6. **Tamper-Evident Audit Log (`src/autosiem/storage.py`)**
   - SHA-256 hash-chained audit records (`prev_hash` + `hash`).
   - Integrity verification via `autosiem audit-verify`.
   - Every user-store mutation (`rbac_user_added`, `rbac_user_removed`, `rbac_token_rotated`, `rbac_token_revoked`) is recorded with the acting principal.
   - The audit log is deliberately **global, not tenant-scoped** — a tenant must not be able to hide its own actions from an operator.

7. **Multi-Tenant Isolation (`src/autosiem/storage.py`, `src/autosiem/web/api.py`)**
   - **Data plane:** `events`, `findings`, `incidents`, `investigations`, and `action_proposals` each carry an indexed `tenant_id`; in RBAC mode reads *and* writes are scoped to the authenticated user's tenant.
   - **Control plane:** `rule_state` uses a composite `(rule_id, tenant_id)` primary key and `suppressions` carries a `tenant_id`, so one tenant's rule toggle or suppression cannot change detection for another.
   - Cross-tenant fetches return **404 rather than 403**, so callers cannot probe for the existence of other tenants' records.
   - Existing single-tenant deployments are unaffected: an automatic migration back-fills `default`, and unscoped callers (CLI, legacy single-token mode) still see every row.

For a full historical threat model and audit history, see [`docs/security-review.md`](docs/security-review.md).

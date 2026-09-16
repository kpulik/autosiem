"""Multi-tenant role-based access control (Phase 3).

Pure stdlib. Defines the role/permission model and a JSON-backed user store
keyed by hashed API tokens. Roles: ``admin`` (everything), ``analyst`` (triage
+ approvals + rule management), ``ingest`` (machine accounts: ingest only),
``viewer`` (read-only). Users carry a tenant label for future data scoping.

The web layer (:mod:`autosiem.web.api`) uses this behind its token guard:
when a users file is configured (``AUTOSIEM_RBAC_FILE``) and contains at least
one user, every ``/api/*`` request must authenticate to a user and each action
is permission-checked; otherwise the legacy single-token
``AUTOSIEM_API_TOKEN`` guard applies unchanged. Tokens are only ever stored
as salted PBKDF2-HMAC-SHA256 verifiers (``token_hash`` in the users file);
plaintext tokens are never stored and are refused on load (SEC-008).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

# --- Permissions -----------------------------------------------------------
PERM_INGEST = "ingest:events"
PERM_DATA_READ = "data:read"
PERM_RULES_READ = "rules:read"
PERM_RULES_MANAGE = "rules:manage"
PERM_RULES_TEST = "rules:test"
PERM_INCIDENT_UPDATE = "incidents:update"
PERM_APPROVE = "approve:proposals"
PERM_SUPPRESS_MANAGE = "suppressions:manage"
PERM_SEARCH = "search:execute"
PERM_AUDIT_READ = "audit:read"
PERM_METRICS_READ = "metrics:read"
PERM_USERS_MANAGE = "users:manage"
PERM_ADMIN = "admin"

ALL_PERMISSIONS = frozenset(
    {
        PERM_INGEST,
        PERM_DATA_READ,
        PERM_RULES_READ,
        PERM_RULES_MANAGE,
        PERM_RULES_TEST,
        PERM_INCIDENT_UPDATE,
        PERM_APPROVE,
        PERM_SUPPRESS_MANAGE,
        PERM_SEARCH,
        PERM_AUDIT_READ,
        PERM_METRICS_READ,
        PERM_USERS_MANAGE,
        PERM_ADMIN,
    }
)

# --- Roles -----------------------------------------------------------------
ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_INGEST = "ingest"
ROLE_VIEWER = "viewer"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_INGEST, ROLE_VIEWER)

READ_ONLY_PERMISSIONS = frozenset(
    {PERM_DATA_READ, PERM_RULES_READ, PERM_SEARCH, PERM_AUDIT_READ, PERM_METRICS_READ}
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    ROLE_VIEWER: READ_ONLY_PERMISSIONS,
    ROLE_INGEST: frozenset({PERM_INGEST}),
    ROLE_ANALYST: READ_ONLY_PERMISSIONS
    | frozenset(
        {
            PERM_RULES_MANAGE,
            PERM_RULES_TEST,
            PERM_INCIDENT_UPDATE,
            PERM_APPROVE,
            PERM_SUPPRESS_MANAGE,
        }
    ),
    ROLE_ADMIN: ALL_PERMISSIONS,
}


def role_permissions(role: str) -> frozenset[str]:
    """Return the permission set granted by a role (empty for unknown roles)."""
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_role_permission(role: str, permission: str) -> bool:
    return permission in role_permissions(role)


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


# --- Token hashing (SEC-008) ----------------------------------------------
# API tokens are 256-bit random strings (``secrets.token_urlsafe(32)``), not
# passwords, so key stretching buys little: there is no brute-force surface on
# a secret with that much entropy. The per-user *salt* is the part that matters
# — it defeats precomputation and stops two users with the same token sharing a
# digest. 100k iterations is a conventional floor that costs ~15ms per verify.
#
# Cost note: because each user has their own salt, a token cannot be looked up
# by digest. :meth:`Rbac.authenticate` therefore verifies against each stored
# user in turn, so a *failed* authentication costs one PBKDF2 pass per user.
PBKDF2_ITERATIONS = 100_000
PBKDF2_ALGORITHM = "pbkdf2_sha256"
_SALT_BYTES = 16


def hash_token(
    token: str, *, salt: bytes | None = None, iterations: int = PBKDF2_ITERATIONS
) -> str:
    """Return a salted PBKDF2 verifier for *token* (never store plaintext).

    The format is ``pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>``. A
    fresh random salt is generated unless one is supplied, so calling this
    twice with the same token returns two different strings — compare with
    :func:`verify_token`, never with ``==``.
    """
    if salt is None:
        salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, iterations)
    return f"{PBKDF2_ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def verify_token(token: str, stored: str) -> bool:
    """Constant-time check of *token* against a *stored* verifier (SEC-006).

    Accepts both the current ``pbkdf2_sha256$...`` format and the legacy bare
    sha256 hex digest, so users files written before SEC-008 keep working until
    their tokens are rotated. Returns ``False`` for anything unparseable rather
    than raising, so one malformed record cannot break authentication for
    everyone else.
    """
    if not token or not stored:
        return False
    if _is_sha256_hex(stored):  # legacy, unsalted — upgraded by ``users rotate``
        legacy = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return secrets.compare_digest(legacy, stored)
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != PBKDF2_ALGORITHM:
        return False
    _, raw_iterations, salt_hex, digest_hex = parts
    try:
        iterations = int(raw_iterations)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    if iterations < 1 or not salt:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, iterations)
    return secrets.compare_digest(candidate.hex(), digest_hex)


class PermissionDenied(Exception):
    """Raised by :meth:`Rbac.require` when a user cannot perform an action."""

    def __init__(self, user: str, permission: str) -> None:
        self.user = user
        self.permission = permission
        super().__init__(f"user '{user}' lacks permission '{permission}'")


@dataclass(frozen=True)
class User:
    """A principal: role + tenant label + optional per-user permission override."""

    name: str
    role: str = ROLE_VIEWER
    tenant: str = "default"
    permissions: frozenset[str] | None = None  # None = role defaults

    @property
    def effective_permissions(self) -> frozenset[str]:
        if self.permissions is not None:
            return self.permissions
        return role_permissions(self.role)

    def has(self, permission: str) -> bool:
        return permission in self.effective_permissions


class Rbac:
    """Role store: users + token hashes + optional JSON persistence.

    The users file format::

        {"users": [{"name": "alice", "role": "analyst", "tenant": "acme",
                    "token_hash": "pbkdf2_sha256$100000$<salt>$<digest>"}]}

    :meth:`save` always writes ``token_hash``. :meth:`load` also accepts the
    legacy ``token_sha256`` key so files written before SEC-008 keep working;
    ``users rotate`` re-writes those in the salted format. A plaintext
    ``token`` key is **refused** — use ``users add``/``users rotate``, which
    generate a token and print it once.
    """

    def __init__(
        self,
        users: Iterable[User] = (),
        token_hashes: Mapping[str, str] | None = None,
        path: str | Path | None = None,
    ) -> None:
        self._users: dict[str, User] = {user.name: user for user in users}
        self._token_hashes: dict[str, str] = dict(token_hashes or {})
        self._path: Path | None = Path(path) if path else None
        self._lock = threading.Lock()

    # -- construction ------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "Rbac":
        """Load a users file; an absent file yields an empty (disabled) store."""
        file_path = Path(path)
        if not file_path.exists():
            return cls(path=file_path)
        data = json.loads(file_path.read_text(encoding="utf-8"))
        users: list[User] = []
        token_hashes: dict[str, str] = {}
        for item in data.get("users", []):
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            raw_permissions = item.get("permissions")
            users.append(
                User(
                    name=name,
                    role=str(item.get("role", ROLE_VIEWER)),
                    tenant=str(item.get("tenant", "default")),
                    permissions=frozenset(raw_permissions) if raw_permissions else None,
                )
            )
            if item.get("token"):
                raise ValueError(
                    f"user '{name}' has a plaintext 'token' field in {file_path}; "
                    "store only 'token_hash' (issue tokens with `cli users add` "
                    "or `cli users rotate`)"
                )
            stored = item.get("token_hash") or item.get("token_sha256")
            if stored:
                token_hashes[name] = str(stored)
        return cls(users=users, token_hashes=token_hashes, path=file_path)

    def is_enabled(self) -> bool:
        """True when the store has users, i.e. RBAC is being enforced."""
        return bool(self._users)

    # -- authentication ----------------------------------------------------
    def authenticate(self, token: str | None) -> User | None:
        """Resolve a bearer token to a user, or None when it matches no one.

        The verifier snapshot is taken under the lock but the PBKDF2 passes run
        outside it, so one slow authentication does not serialize every other
        request.
        """
        if not token:
            return None
        with self._lock:
            candidates = list(self._token_hashes.items())
        for name, stored in candidates:
            if verify_token(token, stored):
                return self._users.get(name)
        return None

    def user(self, name: str) -> User | None:
        return self._users.get(name)

    # -- authorization -----------------------------------------------------
    def user_permissions(self, user: User) -> frozenset[str]:
        return user.effective_permissions

    def has(self, user: User, permission: str) -> bool:
        return user.has(permission)

    def require(self, user: User, permission: str) -> None:
        """Raise :class:`PermissionDenied` unless ``user`` holds ``permission``."""
        if not user.has(permission):
            raise PermissionDenied(user.name, permission)

    # -- management --------------------------------------------------------
    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "name": user.name,
                    "role": user.role,
                    "tenant": user.tenant,
                    "permissions": sorted(user.effective_permissions),
                }
                for user in sorted(self._users.values(), key=lambda u: u.name)
            ]

    def add_user(
        self,
        name: str,
        role: str = ROLE_VIEWER,
        tenant: str = "default",
        token: str | None = None,
    ) -> User:
        """Add a user; ``token`` is stored hashed. Raises on duplicates/unknown roles."""
        if name in self._users:
            raise ValueError(f"user '{name}' already exists")
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown role '{role}' (valid: {', '.join(ROLES)})")
        user = User(name=name, role=role, tenant=tenant)
        with self._lock:
            self._users[name] = user
            if token:
                self._token_hashes[name] = hash_token(token)
        return user

    def remove_user(self, name: str) -> bool:
        """Remove a user; returns False when no such user existed."""
        with self._lock:
            existed = self._users.pop(name, None) is not None
            self._token_hashes.pop(name, None)
        return existed

    def rotate_token(self, name: str, new_token: str | None = None) -> str:
        """Generate (or accept) a new API token for *name*, store the hash,
        and return the **plaintext** token once for display.

        Raises ``ValueError`` if the user does not exist.
        """
        if name not in self._users:
            raise ValueError(f"user '{name}' does not exist")
        token = new_token or secrets.token_urlsafe(32)
        with self._lock:
            self._token_hashes[name] = hash_token(token)
        return token

    def revoke_token(self, name: str) -> bool:
        """Clear the stored token hash so the user cannot authenticate until
        a new token is issued via :meth:`rotate_token`.

        Returns ``False`` when the user did not exist.
        """
        with self._lock:
            if name not in self._users:
                return False
            self._token_hashes.pop(name, None)
        return True

    def save(self, path: str | Path | None = None) -> None:
        """Persist users to JSON (token hashes only). Requires a configured path."""
        target = Path(path) if path else self._path
        if target is None:
            raise ValueError("no path configured for rbac store")
        with self._lock:
            payload = {
                "users": [
                    {
                        "name": user.name,
                        "role": user.role,
                        "tenant": user.tenant,
                        "token_hash": self._token_hashes.get(user.name),
                    }
                    for user in sorted(self._users.values(), key=lambda u: u.name)
                ]
            }
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def rbac_from_env(env: Mapping[str, str] | None = None) -> Rbac:
    """Build the RBAC store from ``AUTOSIEM_RBAC_FILE``; empty when unset/absent.

    An empty (disabled) store means the web layer falls back to the legacy
    single-token guard.
    """
    values = dict(os.environ) if env is None else dict(env)
    path = values.get("AUTOSIEM_RBAC_FILE")
    if not path:
        return Rbac()
    return Rbac.load(path)

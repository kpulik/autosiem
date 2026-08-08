from __future__ import annotations

import json

import pytest

from autosiem.rbac import (
    ALL_PERMISSIONS,
    PERM_ADMIN,
    PERM_APPROVE,
    PERM_DATA_READ,
    PERM_INGEST,
    PERM_RULES_MANAGE,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_INGEST,
    ROLE_VIEWER,
    PermissionDenied,
    Rbac,
    User,
    hash_token,
    rbac_from_env,
    role_permissions,
)


def test_role_hierarchy_and_permissions() -> None:
    viewer = role_permissions(ROLE_VIEWER)
    analyst = role_permissions(ROLE_ANALYST)
    # Every viewer permission is also an analyst permission.
    assert viewer <= analyst
    # Analyst triages and manages; viewer does not.
    assert PERM_RULES_MANAGE in analyst
    assert PERM_APPROVE in analyst
    assert PERM_RULES_MANAGE not in viewer
    assert PERM_APPROVE not in viewer
    # Ingest accounts may only ingest.
    assert role_permissions(ROLE_INGEST) == frozenset({PERM_INGEST})
    # Admin gets everything.
    assert role_permissions(ROLE_ADMIN) == ALL_PERMISSIONS
    assert PERM_ADMIN in role_permissions(ROLE_ADMIN)
    # Unknown roles get nothing.
    assert role_permissions("superuser") == frozenset()


def test_user_permission_override() -> None:
    base = User(name="a", role=ROLE_VIEWER)
    assert base.has(PERM_DATA_READ)
    assert not base.has(PERM_INGEST)
    limited = User(name="a", role=ROLE_ADMIN, permissions=frozenset({PERM_INGEST}))
    assert limited.effective_permissions == frozenset({PERM_INGEST})
    assert not limited.has(PERM_ADMIN)


def test_hash_token_is_deterministic_sha256() -> None:
    assert len(hash_token("sekret")) == 64
    assert hash_token("sekret") == hash_token("sekret")
    assert hash_token("sekret") != hash_token("sekret2")
    assert all(c in "0123456789abcdef" for c in hash_token("sekret"))


def test_authenticate_matches_plaintext_token() -> None:
    rbac = Rbac(users=[User(name="alice", role=ROLE_ANALYST, tenant="acme")], token_hashes={"alice": hash_token("tok-1")})
    user = rbac.authenticate("tok-1")
    assert user is not None and user.name == "alice"
    assert user.tenant == "acme"
    assert rbac.authenticate("tok-2") is None
    assert rbac.authenticate(None) is None


def test_require_enforces_permission() -> None:
    rbac = Rbac(users=[User(name="bob", role=ROLE_VIEWER)], token_hashes={"bob": hash_token("bob-tok")})
    bob = rbac.authenticate("bob-tok")
    assert bob is not None
    rbac.require(bob, PERM_DATA_READ)  # viewer may read
    with pytest.raises(PermissionDenied) as excinfo:
        rbac.require(bob, PERM_APPROVE)
    assert excinfo.value.user == "bob"
    assert excinfo.value.permission == PERM_APPROVE
    assert rbac.has(bob, PERM_DATA_READ) and not rbac.has(bob, PERM_APPROVE)


def test_add_remove_and_duplicate_guard() -> None:
    rbac = Rbac()
    assert not rbac.is_enabled()
    rbac.add_user("carol", role=ROLE_ANALYST, token="carol-tok")
    assert rbac.is_enabled()
    assert rbac.authenticate("carol-tok") is not None
    with pytest.raises(ValueError, match="already exists"):
        rbac.add_user("carol", role=ROLE_ANALYST)
    with pytest.raises(ValueError, match="unknown role"):
        rbac.add_user("dave", role="boss")
    assert rbac.remove_user("carol") is True
    assert rbac.remove_user("carol") is False
    assert not rbac.is_enabled()


def test_load_accepts_plaintext_and_hashed_tokens(tmp_path) -> None:
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            {
                "users": [
                    {"name": "admin", "role": "admin", "tenant": "acme", "token": "admin-tok"},
                    {"name": "svc", "role": "ingest", "tenant": "acme", "token_sha256": hash_token("svc-tok")},
                ]
            }
        )
    )
    rbac = Rbac.load(path)
    assert rbac.is_enabled()
    assert rbac.authenticate("admin-tok") is not None
    assert rbac.authenticate("svc-tok") is not None
    assert rbac.authenticate("nope") is None
    assert len(rbac.list_users()) == 2


def test_load_missing_file_is_disabled(tmp_path) -> None:
    rbac = Rbac.load(tmp_path / "does-not-exist.json")
    assert not rbac.is_enabled()
    assert rbac.authenticate("anything") is None
    assert rbac.list_users() == []


def test_save_roundtrip_never_writes_plaintext(tmp_path) -> None:
    path = tmp_path / "users.json"
    rbac = Rbac.load(path)
    rbac.add_user("erin", role=ROLE_ANALYST, tenant="beta", token="erin-sekret")
    rbac.save(path)
    raw = path.read_text(encoding="utf-8")
    assert "erin-sekret" not in raw
    assert "token_sha256" in raw
    reloaded = Rbac.load(path)
    user = reloaded.authenticate("erin-sekret")
    assert user is not None and user.role == ROLE_ANALYST and user.tenant == "beta"


def test_rbac_from_env(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AUTOSIEM_RBAC_FILE", raising=False)
    assert not rbac_from_env().is_enabled()
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps({"users": [{"name": "a", "role": "viewer", "token": "t"}]}))
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", str(users_file))
    assert rbac_from_env().is_enabled()
    monkeypatch.setenv("AUTOSIEM_RBAC_FILE", str(tmp_path / "absent.json"))
    assert not rbac_from_env().is_enabled()


def test_rotate_token_generates_and_persists(tmp_path) -> None:
    path = tmp_path / "users.json"
    rbac = Rbac.load(path)
    rbac.add_user("erin", role=ROLE_ANALYST, tenant="beta", token="old-erin-tok")
    rbac.save(path)
    new_token = rbac.rotate_token("erin")
    assert len(new_token) > 16  # secrets.token_urlsafe(32) produces ~43 chars
    # Old token no longer works; new one does.
    assert rbac.authenticate("old-erin-tok") is None
    user = rbac.authenticate(new_token)
    assert user is not None and user.name == "erin"
    # Persist + reload round-trip.
    rbac.save(path)
    reloaded = Rbac.load(path)
    assert reloaded.authenticate(new_token) is not None
    assert reloaded.authenticate("old-erin-tok") is None


def test_rotate_token_raises_for_missing_user() -> None:
    rbac = Rbac()
    with pytest.raises(ValueError, match="does not exist"):
        rbac.rotate_token("nobody")


def test_revoke_token_prevents_authentication(tmp_path) -> None:
    path = tmp_path / "users.json"
    rbac = Rbac.load(path)
    rbac.add_user("bob", role=ROLE_VIEWER, token="bob-tok")
    rbac.save(path)
    assert rbac.authenticate("bob-tok") is not None
    assert rbac.revoke_token("bob") is True
    assert rbac.authenticate("bob-tok") is None
    # User record still exists; only the token hash is gone.
    assert rbac.user("bob") is not None
    # Persists through save/reload.
    rbac.save(path)
    reloaded = Rbac.load(path)
    assert reloaded.authenticate("bob-tok") is None
    assert reloaded.user("bob") is not None


def test_revoke_token_returns_false_for_missing_user() -> None:
    rbac = Rbac()
    assert rbac.revoke_token("ghost") is False


def test_rotate_token_after_revoke_creates_new_token(tmp_path) -> None:
    path = tmp_path / "users.json"
    rbac = Rbac.load(path)
    rbac.add_user("carol", role=ROLE_ANALYST, tenant="acme", token="carol-v1")
    rbac.save(path)
    rbac.revoke_token("carol")
    assert rbac.authenticate("carol-v1") is None
    new_token = rbac.rotate_token("carol")
    user = rbac.authenticate(new_token)
    assert user is not None and user.tenant == "acme"

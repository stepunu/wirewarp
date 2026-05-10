"""LDAP login: bind probe + group→role + JIT user creation, all with a
monkeypatched ldap3 layer (no real LDAP server)."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.models.user import User
from app.services.ldap_auth import map_groups_to_role


def _setup_ldap_config(client_fixture):
    cfg = {
        "url": "ldaps://ldap.example",
        "user_dn_template": "uid={username},ou=people,dc=example,dc=com",
        "group_search_base": "ou=groups,dc=example,dc=com",
        "group_role_map": {"wg-admins": "admin", "wg-ops": "operator"},
        "default_role": "viewer",
    }
    return client_fixture.patch(
        "/api/settings", json={"auth_provider": "ldap", "ldap_config": cfg}
    )


def test_map_groups_admin_wins():
    role = map_groups_to_role(
        ["cn=wg-ops,ou=groups,dc=example,dc=com", "cn=wg-admins,ou=groups,dc=example,dc=com"],
        {"wg-admins": "admin", "wg-ops": "operator"},
        "viewer",
    )
    assert role == "admin"


def test_map_groups_no_match_returns_default():
    role = map_groups_to_role(
        ["cn=wg-other,dc=example,dc=com"],
        {"wg-admins": "admin"},
        "viewer",
    )
    assert role == "viewer"


@pytest.mark.asyncio
async def test_ldap_login_jit_creates_user(client, db):
    await _setup_ldap_config(client)

    from app.services import ldap_auth as svc
    from app.services.ldap_auth import LdapResult

    async def _fake_auth(username, password, config):
        assert username == "alice"
        assert password == "right-pw"
        return LdapResult(
            user_dn="uid=alice,ou=people,dc=example,dc=com",
            role="operator",
            groups=["cn=wg-ops,ou=groups,dc=example,dc=com"],
        )

    with patch.object(svc, "ldap_authenticate", side_effect=_fake_auth):
        # Patch the version imported into the router too.
        from app.routers import ldap as ldap_router

        with patch.object(ldap_router, "ldap_authenticate", side_effect=_fake_auth):
            resp = await client.post(
                "/api/auth/ldap/login",
                json={"username": "alice", "password": "right-pw"},
            )
    assert resp.status_code == 200
    assert resp.json()["access_token"]

    user = await db.scalar(
        select(User).where(
            User.auth_provider == "ldap",
            User.external_id == "uid=alice,ou=people,dc=example,dc=com",
        )
    )
    assert user is not None
    assert user.role == "operator"


@pytest.mark.asyncio
async def test_ldap_login_invalid_credentials_returns_401(client, db):
    await _setup_ldap_config(client)

    from app.routers import ldap as ldap_router

    async def _none(username, password, config):
        return None

    with patch.object(ldap_router, "ldap_authenticate", side_effect=_none):
        resp = await client.post(
            "/api/auth/ldap/login", json={"username": "bob", "password": "wrong"}
        )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ldap_login_disabled_user_blocked(client, db):
    await _setup_ldap_config(client)

    db.add(
        User(
            username="disabled-ldap",
            email="dl@x",
            password_hash=None,
            role="viewer",
            is_active=False,
            auth_provider="ldap",
            external_id="uid=disabled-ldap,ou=people,dc=example,dc=com",
        )
    )
    await db.commit()

    from app.routers import ldap as ldap_router
    from app.services.ldap_auth import LdapResult

    async def _ok(username, password, config):
        return LdapResult(
            user_dn="uid=disabled-ldap,ou=people,dc=example,dc=com",
            role="viewer",
            groups=[],
        )

    with patch.object(ldap_router, "ldap_authenticate", side_effect=_ok):
        resp = await client.post(
            "/api/auth/ldap/login",
            json={"username": "disabled-ldap", "password": "x"},
        )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ldap_login_when_provider_not_configured(client):
    """No active LDAP config — endpoint refuses with 400."""
    resp = await client.post(
        "/api/auth/ldap/login", json={"username": "x", "password": "y"}
    )
    assert resp.status_code == 400

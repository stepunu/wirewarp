"""LDAP/OIDC `vpn_group` mapping flips users.vpn_enabled on JIT login."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.models.system_settings import SystemSettings
from app.models.user import User
from app.services.ldap_auth import _groups_contain
from app.services.oidc_auth import claims_grant_vpn


def test_claims_grant_vpn_match():
    assert (
        claims_grant_vpn(
            {"groups": ["wg-admins", "wg-vpn"]},
            "groups",
            "wg-vpn",
        )
        is True
    )


def test_claims_grant_vpn_case_insensitive():
    assert claims_grant_vpn({"groups": ["WG-VPN"]}, "groups", "wg-vpn") is True


def test_claims_grant_vpn_no_match():
    assert claims_grant_vpn({"groups": ["other"]}, "groups", "wg-vpn") is False
    assert claims_grant_vpn({"groups": []}, "groups", "wg-vpn") is False
    assert claims_grant_vpn({}, "groups", None) is False


def test_groups_contain_cn_or_dn():
    groups = ["cn=sso_wirewarp_vpn,ou=groups,dc=example,dc=com"]
    assert _groups_contain(groups, "sso_wirewarp_vpn") is True
    assert _groups_contain(
        groups, "cn=sso_wirewarp_vpn,ou=groups,dc=example,dc=com"
    ) is True
    assert _groups_contain(groups, "other-group") is False
    assert _groups_contain(groups, None) is False


@pytest.mark.asyncio
async def test_oidc_jit_sets_vpn_enabled_when_group_matches(client, db):
    cfg = {
        "issuer": "https://idp.example",
        "client_id": "wirewarp",
        "client_secret": "shh",
        "redirect_url": "http://test/api/auth/oidc/callback",
        "claim_role_map": {"wg-admins": "admin"},
        "default_role": "viewer",
        "role_claim": "groups",
        "vpn_group": "wg-vpn",
    }
    await client.patch(
        "/api/settings", json={"auth_provider": "oidc", "oidc_config": cfg}
    )

    from app.models.oauth_state import OAuthState

    db.add(OAuthState(state="STATE-V1", nonce="NONCE-V1"))
    await db.commit()

    fake_claims = {
        "sub": "ext-vpn-1",
        "preferred_username": "alice-vpn",
        "email": "alice-vpn@example.com",
        "groups": ["wg-vpn", "everyone"],
    }
    with patch(
        "app.routers.oidc.exchange_code_for_userinfo", return_value=fake_claims
    ):
        await client.get(
            "/api/auth/oidc/callback?code=C&state=STATE-V1", follow_redirects=False
        )

    user = await db.scalar(
        select(User).where(User.auth_provider == "oidc", User.external_id == "ext-vpn-1")
    )
    assert user is not None
    assert user.vpn_enabled is True


@pytest.mark.asyncio
async def test_oidc_jit_clears_vpn_enabled_when_group_drops(client, db):
    """If the user is later removed from the VPN group on the IdP, the
    next JIT login flips vpn_enabled back to False."""
    cfg = {
        "issuer": "https://idp.example",
        "client_id": "wirewarp",
        "client_secret": "shh",
        "redirect_url": "http://test/api/auth/oidc/callback",
        "claim_role_map": {},
        "default_role": "viewer",
        "role_claim": "groups",
        "vpn_group": "wg-vpn",
    }
    await client.patch(
        "/api/settings", json={"auth_provider": "oidc", "oidc_config": cfg}
    )

    db.add(
        User(
            username="bob-vpn",
            email="bob-vpn@example.com",
            password_hash=None,
            role="viewer",
            is_active=True,
            auth_provider="oidc",
            external_id="ext-vpn-2",
            vpn_enabled=True,  # was previously granted
        )
    )
    from app.models.oauth_state import OAuthState

    db.add(OAuthState(state="STATE-V2", nonce="NONCE-V2"))
    await db.commit()

    # Now claims no longer carry wg-vpn.
    with patch(
        "app.routers.oidc.exchange_code_for_userinfo",
        return_value={
            "sub": "ext-vpn-2",
            "preferred_username": "bob-vpn",
            "groups": ["everyone"],
        },
    ):
        await client.get(
            "/api/auth/oidc/callback?code=C&state=STATE-V2", follow_redirects=False
        )

    refreshed = await db.scalar(
        select(User).where(User.auth_provider == "oidc", User.external_id == "ext-vpn-2")
    )
    assert refreshed.vpn_enabled is False


@pytest.mark.asyncio
async def test_admin_patch_local_user_vpn_enabled(client, db):
    """Admin can flip vpn_enabled for a local user via PATCH /api/users/{id}."""
    resp = await client.post(
        "/api/users",
        json={
            "username": "carol-vpn",
            "email": "c@x",
            "password": "passwordpassword",
            "role": "viewer",
        },
    )
    assert resp.status_code == 201
    user_id = resp.json()["id"]

    resp = await client.patch(f"/api/users/{user_id}", json={"vpn_enabled": True})
    assert resp.status_code == 200
    assert resp.json()["vpn_enabled"] is True


@pytest.mark.asyncio
async def test_admin_cannot_toggle_vpn_for_external_user(client, db):
    """OIDC/LDAP-driven `vpn_enabled` is determined by the IdP group; admin
    cannot override locally — they must edit the provider config."""
    db.add(
        User(
            username="ldap-user",
            email="l@x",
            password_hash=None,
            role="viewer",
            is_active=True,
            auth_provider="ldap",
            external_id="uid=ldap-user,ou=people,dc=example,dc=com",
        )
    )
    await db.commit()
    user = await db.scalar(select(User).where(User.username == "ldap-user"))

    resp = await client.patch(
        f"/api/users/{user.id}", json={"vpn_enabled": True}
    )
    assert resp.status_code == 400

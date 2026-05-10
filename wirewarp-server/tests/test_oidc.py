"""OIDC login + callback flow with mocked discovery / token / userinfo."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.models.system_settings import SystemSettings
from app.models.user import User


def _setup_oidc_config(secret: str = "shh") -> dict:
    return {
        "issuer": "https://idp.example",
        "client_id": "wirewarp",
        "client_secret": secret,
        "redirect_url": "http://test/api/auth/oidc/callback",
        "scopes": ["openid", "email", "profile", "groups"],
        "claim_role_map": {"wg-admins": "admin", "wg-ops": "operator"},
        "default_role": "viewer",
        "role_claim": "groups",
    }


@pytest.mark.asyncio
async def test_oidc_login_redirects_with_state_and_nonce(client, db):
    cfg = _setup_oidc_config()
    await client.patch(
        "/api/settings", json={"auth_provider": "oidc", "oidc_config": cfg}
    )

    fake_discovery = {
        "authorization_endpoint": "https://idp.example/auth",
        "token_endpoint": "https://idp.example/token",
        "userinfo_endpoint": "https://idp.example/userinfo",
        "jwks_uri": "https://idp.example/jwks",
    }
    with patch(
        "app.routers.oidc.discover", return_value=fake_discovery
    ):
        resp = await client.get("/api/auth/oidc/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert location.startswith("https://idp.example/auth?")
    assert "state=" in location
    assert "nonce=" in location

    # State row written.
    from app.models.oauth_state import OAuthState

    states = (await db.execute(select(OAuthState))).scalars().all()
    assert len(states) == 1


@pytest.mark.asyncio
async def test_oidc_callback_jit_creates_admin_when_group_matches(client, db):
    cfg = _setup_oidc_config()
    await client.patch(
        "/api/settings", json={"auth_provider": "oidc", "oidc_config": cfg}
    )

    # Pre-seed an OAuthState row that we'll reference in the callback.
    from app.models.oauth_state import OAuthState

    state_row = OAuthState(state="STATE-XYZ", nonce="NONCE-XYZ")
    db.add(state_row)
    await db.commit()

    fake_claims = {
        "sub": "external-1",
        "preferred_username": "alice",
        "email": "alice@example.com",
        "groups": ["wg-admins", "everyone"],
    }

    async def _fake_exchange(cfg_arg, code, state, expected_nonce):
        assert state == "STATE-XYZ"
        assert expected_nonce == "NONCE-XYZ"
        return fake_claims

    with patch(
        "app.routers.oidc.exchange_code_for_userinfo", side_effect=_fake_exchange
    ):
        resp = await client.get(
            "/api/auth/oidc/callback?code=CODE&state=STATE-XYZ",
            follow_redirects=False,
        )
    assert resp.status_code in (302, 307)
    assert resp.headers["location"].startswith("/#token=")

    user = await db.scalar(
        select(User).where(User.auth_provider == "oidc", User.external_id == "external-1")
    )
    assert user is not None
    assert user.role == "admin"
    assert user.username == "alice"


@pytest.mark.asyncio
async def test_oidc_callback_default_role_when_group_missing(client, db):
    cfg = _setup_oidc_config()
    await client.patch(
        "/api/settings", json={"auth_provider": "oidc", "oidc_config": cfg}
    )

    from app.models.oauth_state import OAuthState

    db.add(OAuthState(state="S2", nonce="N2"))
    await db.commit()

    fake_claims = {"sub": "ext-2", "preferred_username": "bob", "email": "b@x", "groups": ["random"]}

    with patch(
        "app.routers.oidc.exchange_code_for_userinfo", return_value=fake_claims
    ):
        await client.get(
            "/api/auth/oidc/callback?code=C&state=S2", follow_redirects=False
        )

    u = await db.scalar(
        select(User).where(User.auth_provider == "oidc", User.external_id == "ext-2")
    )
    assert u is not None
    assert u.role == "viewer"


@pytest.mark.asyncio
async def test_oidc_callback_unknown_state_rejected(client):
    resp = await client.get(
        "/api/auth/oidc/callback?code=C&state=NOPE", follow_redirects=False
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_oidc_callback_disabled_user_blocked(client, db):
    """A previously-JIT'd user that was later disabled must not be able
    to log back in via OIDC."""
    cfg = _setup_oidc_config()
    await client.patch(
        "/api/settings", json={"auth_provider": "oidc", "oidc_config": cfg}
    )

    db.add(
        User(
            username="dis-oidc",
            email="d@x",
            password_hash=None,
            role="viewer",
            is_active=False,
            auth_provider="oidc",
            external_id="ext-d",
        )
    )
    from app.models.oauth_state import OAuthState

    db.add(OAuthState(state="S3", nonce="N3"))
    await db.commit()

    with patch(
        "app.routers.oidc.exchange_code_for_userinfo",
        return_value={"sub": "ext-d", "preferred_username": "dis-oidc"},
    ):
        resp = await client.get(
            "/api/auth/oidc/callback?code=C&state=S3", follow_redirects=False
        )
    assert resp.status_code == 401


def test_map_claims_to_role_picks_highest_priority():
    from app.services.oidc_auth import map_claims_to_role

    role = map_claims_to_role(
        {"groups": ["x", "wg-ops", "wg-admins"]},
        "groups",
        {"wg-ops": "operator", "wg-admins": "admin"},
        "viewer",
    )
    assert role == "admin"

    role = map_claims_to_role(
        {"groups": "wg-ops"},  # singleton not list — supported
        "groups",
        {"wg-ops": "operator"},
        "viewer",
    )
    assert role == "operator"

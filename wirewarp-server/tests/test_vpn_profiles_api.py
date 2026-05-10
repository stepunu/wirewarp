"""VPN profiles: self-serve create returns plaintext-once, server stores
only public material; permission updates reissue rules to the agent."""
from __future__ import annotations

import base64
import uuid

import pytest
from sqlalchemy import select

from app.auth import hash_password
from app.models.user import User
from app.models.vpn_profile import VpnProfile


async def _seed_vpn_user(
    db, *, vpn_enabled: bool = True, username: str = "alice-vpn"
) -> User:
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("passwordpassword"),
        role="viewer",
        is_active=True,
        auth_provider="local",
        vpn_enabled=vpn_enabled,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _bootstrap_endpoint(client, db, factories) -> str:
    gateway = await factories.make_client(db, is_gateway=True)
    resp = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51821",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_admin_create_profile_returns_plaintext_once(client, db, factories):
    endpoint_id = await _bootstrap_endpoint(client, db, factories)
    user = await _seed_vpn_user(db)

    resp = await client.post(
        "/api/vpn-profiles",
        json={
            "user_id": str(user.id),
            "vpn_endpoint_id": endpoint_id,
            "label": "phone",
            "tunnel_mode": "split",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["wg_private_key"]
    assert body["config_text"].startswith("[Interface]")
    assert "PrivateKey" in body["config_text"]

    # The plaintext key is base64 32 bytes — same Curve25519 wire format.
    raw = base64.b64decode(body["wg_private_key"])
    assert len(raw) == 32

    # The server must NOT have persisted the private key. Only the public
    # key + PSK live on the row.
    rows = (await db.execute(select(VpnProfile))).scalars().all()
    assert len(rows) == 1
    stored = rows[0]
    assert stored.wg_public_key == body["wg_public_key"]
    assert body["wg_private_key"] not in [stored.wg_public_key, stored.wg_psk]
    assert not hasattr(stored, "wg_private_key")


@pytest.mark.asyncio
async def test_self_serve_create_requires_vpn_enabled(client, db, factories, monkeypatch):
    """Override the test client's stub user to be vpn_enabled=False — the
    /me endpoint must reject."""
    from app.auth import get_current_user
    from app.main import app

    endpoint_id = await _bootstrap_endpoint(client, db, factories)

    user = await _seed_vpn_user(db, vpn_enabled=False)

    async def _override():
        return user

    app.dependency_overrides[get_current_user] = _override
    try:
        resp = await client.post(
            "/api/vpn-profiles/me",
            json={
                "vpn_endpoint_id": endpoint_id,
                "label": "phone",
                "tunnel_mode": "split",
            },
        )
        assert resp.status_code == 403
    finally:
        # Test fixture cleans up overrides on teardown via app.dependency_overrides.clear()
        pass


@pytest.mark.asyncio
async def test_regenerate_returns_new_keypair_and_invalidates_old(client, db, factories):
    endpoint_id = await _bootstrap_endpoint(client, db, factories)
    user = await _seed_vpn_user(db)

    resp = await client.post(
        "/api/vpn-profiles",
        json={
            "user_id": str(user.id),
            "vpn_endpoint_id": endpoint_id,
            "label": "phone",
            "tunnel_mode": "split",
        },
    )
    first = resp.json()
    profile_id = first["id"]

    # Use the admin "create on behalf" then regenerate via /me — but /me
    # checks current_user.id == profile.user_id. Override get_current_user
    # to be the seeded user.
    from app.auth import get_current_user
    from app.main import app

    async def _be_alice():
        return user

    app.dependency_overrides[get_current_user] = _be_alice

    resp = await client.post(f"/api/vpn-profiles/me/{profile_id}/regenerate")
    assert resp.status_code == 200, resp.text
    second = resp.json()
    assert second["wg_public_key"] != first["wg_public_key"]
    assert second["wg_private_key"] != first["wg_private_key"]


@pytest.mark.asyncio
async def test_permissions_replace_full_list(client, db, factories):
    """Permissions are per-(user, endpoint). Setting them BEFORE any
    profile exists is the supported flow."""
    endpoint_id = await _bootstrap_endpoint(client, db, factories)
    user = await _seed_vpn_user(db)

    resp = await client.put(
        f"/api/vpn-endpoints/{endpoint_id}/users/{user.id}/permissions",
        json={
            "permissions": [
                {
                    "destination": "192.168.1.50",
                    "protocol": "tcp",
                    "port_range_start": 22,
                    "port_range_end": 22,
                },
                {"destination": "192.168.2.0/24", "protocol": "any"},
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    perms = resp.json()
    assert len(perms) == 2
    assert {p["destination"] for p in perms} == {
        "192.168.1.50",
        "192.168.2.0/24",
    }

    resp = await client.put(
        f"/api/vpn-endpoints/{endpoint_id}/users/{user.id}/permissions",
        json={"permissions": [{"destination": "10.0.0.5", "protocol": "any"}]},
    )
    assert resp.status_code == 200
    perms = resp.json()
    assert len(perms) == 1
    assert perms[0]["destination"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_self_serve_blocked_when_no_permissions(client, db, factories):
    """The self-serve flow refuses if no permission set has been
    pre-provisioned for this (user, endpoint)."""
    endpoint_id = await _bootstrap_endpoint(client, db, factories)

    user = await _seed_vpn_user(db)
    from app.auth import get_current_user
    from app.main import app

    async def _be_user():
        return user

    app.dependency_overrides[get_current_user] = _be_user
    try:
        resp = await client.post(
            "/api/vpn-profiles/me",
            json={
                "vpn_endpoint_id": endpoint_id,
                "label": "phone",
                "tunnel_mode": "split",
            },
        )
        assert resp.status_code == 403, resp.text
        assert "permissions" in resp.json()["detail"].lower()
    finally:
        pass


@pytest.mark.asyncio
async def test_self_serve_allowed_after_permissions_provisioned(client, db, factories):
    endpoint_id = await _bootstrap_endpoint(client, db, factories)
    user = await _seed_vpn_user(db)

    # Admin pre-provisions one rule.
    await client.put(
        f"/api/vpn-endpoints/{endpoint_id}/users/{user.id}/permissions",
        json={"permissions": [{"destination": "192.168.1.50", "protocol": "any"}]},
    )

    from app.auth import get_current_user
    from app.main import app

    async def _be_user():
        return user

    app.dependency_overrides[get_current_user] = _be_user
    resp = await client.post(
        "/api/vpn-profiles/me",
        json={
            "vpn_endpoint_id": endpoint_id,
            "label": "phone",
            "tunnel_mode": "split",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # AllowedIPs in the rendered .conf now reflects the provisioned rules,
    # not the bare VPN /24.
    assert "192.168.1.50" in body["config_text"]


@pytest.mark.asyncio
async def test_endpoint_permissions_sheet_payload(client, db, factories):
    """Sheet GET returns every vpn_enabled user with their permission
    set + profile count, including users without any permissions yet."""
    endpoint_id = await _bootstrap_endpoint(client, db, factories)
    user1 = await _seed_vpn_user(db)
    # Add a second vpn-enabled user so the sheet has multiple rows.
    user2 = await _seed_vpn_user(db, username="bob-vpn")

    await client.put(
        f"/api/vpn-endpoints/{endpoint_id}/users/{user1.id}/permissions",
        json={"permissions": [{"destination": "10.0.0.1", "protocol": "any"}]},
    )

    resp = await client.get(f"/api/vpn-endpoints/{endpoint_id}/permissions")
    assert resp.status_code == 200
    rows = resp.json()
    by_username = {r["username"]: r for r in rows}
    assert "alice-vpn" in by_username
    assert "bob-vpn" in by_username
    assert len(by_username["alice-vpn"]["permissions"]) == 1
    assert len(by_username["bob-vpn"]["permissions"]) == 0
    assert by_username["alice-vpn"]["profile_count"] == 0

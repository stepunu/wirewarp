"""Login / logout / register / providers + audit attribution."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.auth import hash_password
from app.models.command_log import CommandLog
from app.models.system_settings import SystemSettings
from app.models.user import User


async def _seed_local_admin(db):
    db.add(
        User(
            username="admin1",
            email="admin1@example",
            password_hash=hash_password("correctpassword"),
            role="admin",
            is_active=True,
            auth_provider="local",
        )
    )
    await db.commit()


@pytest.mark.asyncio
async def test_login_success_records_audit_and_last_login(client, db):
    await _seed_local_admin(db)

    resp = await client.post(
        "/api/auth/login", json={"username": "admin1", "password": "correctpassword"}
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]

    user = await db.scalar(select(User).where(User.username == "admin1"))
    assert user.last_login_at is not None

    events = (
        await db.execute(
            select(CommandLog).where(CommandLog.event_type == "auth.login.success")
        )
    ).scalars().all()
    assert any(e.actor_user_id == user.id for e in events)


@pytest.mark.asyncio
async def test_login_failure_audited(client, db):
    await _seed_local_admin(db)
    resp = await client.post(
        "/api/auth/login", json={"username": "admin1", "password": "wrong"}
    )
    assert resp.status_code == 401

    events = (
        await db.execute(
            select(CommandLog).where(CommandLog.event_type == "auth.login.failure")
        )
    ).scalars().all()
    assert events
    assert events[-1].success is False


@pytest.mark.asyncio
async def test_login_blocked_when_disabled(client, db):
    db.add(
        User(
            username="dis",
            email="dis@example",
            password_hash=hash_password("correctpassword"),
            role="viewer",
            is_active=False,
            auth_provider="local",
        )
    )
    await db.commit()

    resp = await client.post(
        "/api/auth/login", json={"username": "dis", "password": "correctpassword"}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_rejects_external_user_via_local_endpoint(client, db):
    """A user with auth_provider != local has no local password; hitting
    the local /login endpoint must not succeed even if a stale hash
    happens to exist on the row."""
    db.add(
        User(
            username="oidc-user",
            email="o@example",
            password_hash=None,
            role="viewer",
            is_active=True,
            auth_provider="oidc",
            external_id="abc",
        )
    )
    await db.commit()
    resp = await client.post(
        "/api/auth/login", json={"username": "oidc-user", "password": "anything"}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_register_requires_admin_token(client):
    """Register endpoint is now admin-gated. Through the test stub the
    user is admin so the call succeeds — the no-auth case is covered by
    the RBAC tests."""
    resp = await client.post(
        "/api/auth/register",
        json={
            "username": "new1",
            "email": "n@x",
            "password": "passwordpassword",
            "role": "viewer",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["username"] == "new1"


@pytest.mark.asyncio
async def test_logout_audited(client, db):
    resp = await client.post("/api/auth/logout")
    assert resp.status_code == 204
    events = (
        await db.execute(
            select(CommandLog).where(CommandLog.event_type == "auth.logout")
        )
    ).scalars().all()
    assert events


@pytest.mark.asyncio
async def test_providers_endpoint_default(client):
    resp = await client.get("/api/auth/providers")
    assert resp.status_code == 200
    assert resp.json()["active_provider"] == "local"


@pytest.mark.asyncio
async def test_providers_endpoint_oidc(client, db):
    settings = SystemSettings(id=1, auth_provider="oidc")
    db.add(settings)
    await db.commit()
    resp = await client.get("/api/auth/providers")
    assert resp.status_code == 200
    assert resp.json()["active_provider"] == "oidc"


@pytest.mark.asyncio
async def test_audit_join_surfaces_actor_username(client, db):
    """Login event should appear in /api/audit with actor_username
    populated by the LEFT JOIN on users."""
    await _seed_local_admin(db)
    await client.post("/api/auth/login", json={"username": "admin1", "password": "correctpassword"})

    resp = await client.get("/api/audit", params={"event_type": "auth.login.success"})
    assert resp.status_code == 200
    rows = resp.json()
    assert rows
    assert rows[0]["event_type"] == "auth.login.success"
    assert rows[0]["actor_username"] == "admin1"

"""Admin /api/users CRUD."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.user import User


@pytest.mark.asyncio
async def test_list_users_returns_seeded_admin_only(client):
    """Conftest seeds the admin stub user; /api/users should reflect it."""
    resp = await client.get("/api/users")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["role"] == "admin"


@pytest.mark.asyncio
async def test_create_local_user_returns_safe_fields(client):
    resp = await client.post(
        "/api/users",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "longenoughpassword",
            "role": "operator",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["username"] == "alice"
    assert body["role"] == "operator"
    assert body["is_active"] is True
    assert body["auth_provider"] == "local"
    assert "password_hash" not in body
    assert "password" not in body


@pytest.mark.asyncio
async def test_create_user_dup_username_rejected(client):
    a = {"username": "bob", "email": "b@x", "password": "passwordpassword", "role": "viewer"}
    assert (await client.post("/api/users", json=a)).status_code == 201
    dup = {"username": "bob", "email": "other@x", "password": "passwordpassword", "role": "viewer"}
    assert (await client.post("/api/users", json=dup)).status_code == 400


@pytest.mark.asyncio
async def test_patch_role_and_is_active(client, db):
    resp = await client.post(
        "/api/users",
        json={"username": "carol", "email": "c@x", "password": "passwordpassword", "role": "viewer"},
    )
    user_id = resp.json()["id"]

    resp = await client.patch(f"/api/users/{user_id}", json={"role": "operator"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "operator"

    resp = await client.patch(f"/api/users/{user_id}", json={"is_active": False})
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_delete_user(client):
    resp = await client.post(
        "/api/users",
        json={"username": "dan", "email": "d@x", "password": "passwordpassword", "role": "viewer"},
    )
    user_id = resp.json()["id"]

    resp = await client.delete(f"/api/users/{user_id}")
    assert resp.status_code == 204

    resp = await client.get("/api/users")
    usernames = [u["username"] for u in resp.json()]
    assert "dan" not in usernames


@pytest.mark.asyncio
async def test_invalid_role_rejected_at_schema_layer(client):
    resp = await client.post(
        "/api/users",
        json={
            "username": "eve",
            "email": "e@x",
            "password": "passwordpassword",
            "role": "superadmin",
        },
    )
    assert resp.status_code == 422

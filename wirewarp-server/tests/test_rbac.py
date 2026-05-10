"""Role-based access control across the routers.

We don't exercise every mutation — just enough to confirm `require_role`
gates fire correctly for viewer/operator/admin shaped requests.
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_admin_can_create_token(client):
    resp = await client.post("/api/agents/tokens", json={"agent_type": "server"})
    assert resp.status_code == 201
    body = resp.json()
    # Plaintext token returned exactly once on issuance.
    assert body["token"]
    assert body["agent_type"] == "server"


@pytest.mark.asyncio
async def test_operator_cannot_create_token(operator_client):
    resp = await operator_client.post(
        "/api/agents/tokens", json={"agent_type": "server"}
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_create_token(viewer_client):
    resp = await viewer_client.post(
        "/api/agents/tokens", json={"agent_type": "server"}
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_patch_settings(viewer_client):
    resp = await viewer_client.patch(
        "/api/settings", json={"instance_name": "Hijacked"}
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_operator_cannot_patch_settings(operator_client):
    resp = await operator_client.patch(
        "/api/settings", json={"instance_name": "Stillblocked"}
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_can_get_settings(viewer_client):
    resp = await viewer_client.get("/api/settings")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_viewer_can_list_audit(viewer_client):
    resp = await viewer_client.get("/api/audit")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_viewer_cannot_list_users(viewer_client):
    resp = await viewer_client.get("/api/users")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_list_users(client):
    resp = await client.get("/api/users")
    assert resp.status_code == 200

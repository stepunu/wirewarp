"""Admin /api/vpn-endpoints CRUD."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.vpn_endpoint import VpnEndpoint


@pytest.mark.asyncio
async def test_create_endpoint_allocates_network(client, db, factories):
    gateway = await factories.make_client(db, is_gateway=True)

    resp = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51821",
            "listen_port": 51821,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["vpn_network"].endswith("/24")
    assert body["wg_interface"] == "wg-vpn0"
    assert body["enabled"] is True


@pytest.mark.asyncio
async def test_create_endpoint_rejected_for_non_gateway(client, db, factories):
    plain_client = await factories.make_client(db, is_gateway=False)
    resp = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(plain_client.id),
            "public_endpoint": "vpn.example:51821",
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_endpoint_unique_per_gateway(client, db, factories):
    gateway = await factories.make_client(db, is_gateway=True)
    resp = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51821",
        },
    )
    assert resp.status_code == 201
    resp = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51822",
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_patch_endpoint_toggle_enabled(client, db, factories):
    gateway = await factories.make_client(db, is_gateway=True)
    resp = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51821",
        },
    )
    ep_id = resp.json()["id"]

    resp = await client.patch(f"/api/vpn-endpoints/{ep_id}", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_delete_endpoint_cascades(client, db, factories):
    gateway = await factories.make_client(db, is_gateway=True)
    resp = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51821",
        },
    )
    ep_id = resp.json()["id"]

    resp = await client.delete(f"/api/vpn-endpoints/{ep_id}")
    assert resp.status_code == 204

    rows = (await db.execute(select(VpnEndpoint))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_list_endpoints_visible_to_viewer(viewer_client, db, factories):
    """Read-only endpoints work for viewer; admin-only mutations are
    covered in test_rbac."""
    resp = await viewer_client.get("/api/vpn-endpoints")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_create_endpoint_forbidden_for_operator(operator_client, db, factories):
    gateway = await factories.make_client(db, is_gateway=True)
    resp = await operator_client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51821",
        },
    )
    assert resp.status_code == 403

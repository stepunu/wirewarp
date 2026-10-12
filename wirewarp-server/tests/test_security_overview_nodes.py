from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from app.auth import get_current_user
from app.main import app
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.edge_node import EdgeNode
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.models.traefik_snapshot import TraefikSnapshot


@pytest.mark.asyncio
async def test_overview_counts_gateway_lan_and_vps_routes_by_owner(client, session_maker, factories):
    async with session_maker() as db:
        server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled", edge_install_phase="healthy")
        gateway = await factories.make_client(db)
        ordinary = await factories.make_client(db, is_gateway=False)
        db.add(EdgeNode(agent_id=gateway.agent_id, edge_mode="security_edge", edge_state="enabled", edge_install_phase="healthy", lan_bind_ip=gateway.lan_ip))
        db.add(EdgeNode(agent_id=ordinary.agent_id, edge_mode="security_edge", edge_state="enabled"))
        db.add_all([
            HTTPRoute(agent_id=gateway.agent_id, domain="lan.example.test", destination_ip="192.168.1.12", destination_port=80, visibility="lan_only"),
            HTTPRoute(agent_id=gateway.agent_id, domain="disabled.example.test", destination_ip="192.168.1.13", destination_port=80, visibility="lan_only", active=False),
            HTTPRoute(agent_id=server.agent_id, domain="vps.example.test", destination_ip="192.168.1.14", destination_port=80, visibility="public_only"),
            CrowdSecSnapshot(agent_id=gateway.agent_id, installed=True, running=True, phase="healthy", total_decisions=7),
            TraefikSnapshot(agent_id=gateway.agent_id, installed=True, running=True, phase="healthy", routes_count=99),
        ])
        await db.commit()
    response = await client.get("/api/security/overview")
    assert response.status_code == 200, response.text
    data = response.json()
    rows = {row["agent_id"]: row for row in data["servers"]}
    assert set(rows) == {str(server.agent_id), str(gateway.agent_id)}
    lan = rows[str(gateway.agent_id)]
    assert lan["server_id"] is None
    assert lan["role"] == "gateway"
    assert lan["placement"] == "gateway_edge"
    assert lan["runtime_mode"] == "security_edge"
    assert lan["routes_count"] == 2
    assert lan["active_routes_count"] == 1
    assert lan["relay_routes_count"] == 0
    assert lan["crowdsec_installed"] and lan["crowdsec_running"]
    assert lan["traefik_phase"] == "healthy"
    assert lan["traefik_updated_at"] is not None
    assert rows[str(server.agent_id)]["server_id"] == str(server.id)
    assert rows[str(server.agent_id)]["routes_count"] == 1
    assert data["http_routes_count"] == 3
    assert data["active_http_routes_count"] == 2
    assert data["kpis"]["blocked"] == 7


@pytest.mark.asyncio
async def test_disabled_and_unconfigured_gateway_never_report_enabled_or_healthy(client, session_maker, factories):
    async with session_maker() as db:
        gateway = await factories.make_client(db)
        ownerless = await factories.make_client(db)
        db.add(EdgeNode(agent_id=gateway.agent_id, edge_mode="security_edge", edge_state="disabled", edge_install_phase="disabled"))
        db.add(TraefikSnapshot(agent_id=gateway.agent_id, installed=True, running=False, phase="degraded", last_error="Listener conflict"))
        await db.commit()
        original_count = await db.scalar(select(func.count()).select_from(EdgeNode))
    response = await client.get("/api/security/overview")
    assert response.status_code == 200, response.text
    rows = {row["agent_id"]: row for row in response.json()["servers"]}
    disabled = rows[str(gateway.agent_id)]
    assert disabled["edge_state"] == "disabled"
    assert disabled["runtime_mode"] == "disabled"
    assert disabled["traefik_running"] is False
    assert disabled["traefik_installed"] is True
    assert disabled["traefik_phase"] == "degraded"
    assert disabled["traefik_error"] == "Listener conflict"
    unknown = rows[str(ownerless.agent_id)]
    assert unknown["runtime_mode"] == "disabled"
    assert unknown["edge_state"] == "disabled"
    assert unknown["crowdsec_installed"] is None
    assert unknown["traefik_installed"] is None
    assert unknown["traefik_phase"] is None
    async with session_maker() as db:
        assert await db.scalar(select(func.count()).select_from(EdgeNode)) == original_count


@pytest.mark.asyncio
async def test_relay_only_vps_reports_relay_snapshot_without_owning_gateway_route(client, session_maker, factories):
    async with session_maker() as db:
        server = await factories.make_server(db)
        gateway = await factories.make_client(db)
        attachment = await factories.make_attachment(db, client=gateway, server=server)
        owner = await db.get(EdgeNode, server.agent_id)
        owner.relay_enabled = True
        db.add(EdgeNode(agent_id=gateway.agent_id, edge_mode="security_edge", edge_state="enabled"))
        route = HTTPRoute(id=uuid.uuid4(), agent_id=gateway.agent_id, domain="public.example.test", destination_ip="192.168.1.12", destination_port=80, visibility="both")
        db.add(route)
        await db.flush()
        db.add(HTTPPublicIngress(route_id=route.id, attachment_id=attachment.id, public_port=443))
        db.add(TraefikSnapshot(agent_id=server.agent_id, installed=True, running=True, phase="healthy"))
        await db.commit()
    response = await client.get("/api/security/overview")
    assert response.status_code == 200, response.text
    data = response.json()
    rows = {row["agent_id"]: row for row in data["servers"]}
    relay = rows[str(server.agent_id)]
    assert relay["server_id"] == str(server.id)
    assert relay["runtime_mode"] == "relay_only"
    assert relay["placement"] == "vps_relay"
    assert relay["edge_state"] == "disabled"
    assert relay["crowdsec_installed"] is None
    assert relay["traefik_installed"] and relay["traefik_running"]
    assert relay["routes_count"] == 0
    assert relay["relay_routes_count"] == 1
    assert rows[str(gateway.agent_id)]["routes_count"] == 1
    assert data["http_routes_count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "operator", "viewer"])
async def test_overview_read_roles(client, role):
    client._wirewarp_user.role = role
    response = await client.get("/api/security/overview")
    assert response.status_code == 200
    assert response.json()["servers"] == []
    assert response.json()["http_routes_count"] == 0


@pytest.mark.asyncio
async def test_overview_rejects_user_and_unauthenticated_requests(client):
    client._wirewarp_user.role = "user"
    assert (await client.get("/api/security/overview")).status_code == 403
    override = app.dependency_overrides.pop(get_current_user)
    try:
        assert (await client.get("/api/security/overview")).status_code == 401
    finally:
        app.dependency_overrides[get_current_user] = override

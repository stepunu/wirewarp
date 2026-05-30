from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.edge_route_config import EdgeRouteConfig
from app.models.port_forward import PortForward
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.traefik_snapshot import TraefikSnapshot


def _agent(agent_type: str, name: str) -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name=name,
        type=agent_type,
        hostname=f"{name}.example",
        status="connected",
        last_seen=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_nodes_list_derives_server_gateway_client_roles(client, session_maker) -> None:
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    client_agent = _agent("client", "road-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent, client_agent])
        await s.commit()
        s.add(TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24"))
        s.add(TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True, vm_network="192.168.1.0/24"))
        s.add(TunnelClient(id=uuid.uuid4(), agent_id=client_agent.id, is_gateway=False))
        await s.commit()

    resp = await client.get("/api/nodes")

    assert resp.status_code == 200
    by_name = {row["name"]: row for row in resp.json()}
    assert by_name["edge-1"]["role"] == "server"
    assert by_name["gw-1"]["role"] == "gateway"
    assert by_name["road-1"]["role"] == "client"


@pytest.mark.asyncio
async def test_node_edge_rolls_up_component_phases(client, session_maker) -> None:
    agent = _agent("server", "edge-1")
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
        s.add(TunnelServer(id=uuid.uuid4(), agent_id=agent.id, tunnel_network="10.21.0.0/24"))
        s.add(
            CrowdSecSnapshot(
                agent_id=agent.id,
                installed=True,
                running=True,
                phase="healthy",
                appsec_enabled=True,
                bouncer_registered=True,
            )
        )
        s.add(
            TraefikSnapshot(
                agent_id=agent.id,
                installed=True,
                running=False,
                phase="degraded",
                last_error="unit failed",
            )
        )
        await s.commit()

    resp = await client.get(f"/api/nodes/{agent.id}/edge")

    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_id"] == str(agent.id)
    assert body["phase"] == "degraded"
    assert body["crowdsec"]["phase"] == "healthy"
    assert body["crowdsec"]["appsec_enabled"] is True
    assert body["traefik"]["phase"] == "degraded"
    assert body["traefik"]["last_error"] == "unit failed"


@pytest.mark.asyncio
async def test_edge_reconcile_dispatches_unified_desired_state(client, session_maker, fake_manager) -> None:
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        client_row = TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True)
        s.add_all([server, client_row])
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        s.add(att)
        await s.commit()
        pf = PortForward(
            id=uuid.uuid4(),
            attachment_id=att.id,
            protocol="tcp",
            public_port=443,
            destination_ip="192.168.1.10",
            destination_port=8080,
            service_kind="http",
            domain="app.example.com",
            active=True,
        )
        s.add(pf)
        await s.flush()
        s.add(EdgeRouteConfig(id=uuid.uuid4(), port_forward_id=pf.id, waf_mode="block"))
        await s.commit()

    fake_manager.online.add(str(server_agent.id))
    resp = await client.post(f"/api/nodes/{server_agent.id}/edge/reconcile")

    assert resp.status_code == 202
    assert fake_manager.sent
    msg = fake_manager.sent[-1]["message"]
    assert msg["type"] == "edge_desired_state"
    assert set(msg["params"]) == {"whitelist", "traefik_static_config", "traefik_dynamic_config"}
    middleware = msg["params"]["traefik_dynamic_config"]["http"]["middlewares"]["crowdsec-bouncer"]
    assert middleware["plugin"]["bouncer"]["crowdsecAppsecEnabled"] is True


@pytest.mark.asyncio
async def test_security_sites_filter_by_agent_id_and_default_observe(client, session_maker, fake_manager) -> None:
    server_agent = _agent("server", "edge-1")
    other_agent = _agent("server", "edge-2")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, other_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        other = TunnelServer(id=uuid.uuid4(), agent_id=other_agent.id, tunnel_network="10.22.0.0/24")
        client_row = TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True)
        s.add_all([server, other, client_row])
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        other_att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=other.id,
            tunnel_ip="10.22.0.2",
            wg_interface="wg1",
            fwmark=0x102,
            route_table_id=101,
        )
        s.add_all([att, other_att])
        await s.commit()
        s.add(
            PortForward(
                id=uuid.uuid4(),
                attachment_id=other_att.id,
                protocol="tcp",
                public_port=443,
                destination_ip="192.168.1.20",
                destination_port=8080,
                service_kind="http",
                domain="other.example.com",
                active=True,
            )
        )
        await s.commit()

    fake_manager.online.add(str(server_agent.id))
    resp = await client.post(
        "/api/security/sites",
        json={
            "attachment_id": str(att.id),
            "domain": "app.example.com",
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
        },
    )
    assert resp.status_code == 201
    assert resp.json()["edge_config"]["waf_mode"] == "observe"

    filtered = await client.get(f"/api/security/sites?agent_id={server_agent.id}")
    assert filtered.status_code == 200
    assert [row["domain"] for row in filtered.json()] == ["app.example.com"]


@pytest.mark.asyncio
async def test_antibot_requires_configured_captcha_keys(client, session_maker) -> None:
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        client_row = TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True)
        s.add_all([server, client_row])
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        s.add(att)
        await s.commit()

    resp = await client.post(
        "/api/security/sites",
        json={
            "attachment_id": str(att.id),
            "domain": "app.example.com",
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
            "antibot": True,
        },
    )

    assert resp.status_code == 400
    assert "CAPTCHA" in resp.json()["detail"]

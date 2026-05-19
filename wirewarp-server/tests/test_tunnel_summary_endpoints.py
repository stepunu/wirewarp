"""End-to-end tests for the per-server / per-client summary endpoints.

The aggregation logic lives in the router (sums + counts via SQLAlchemy
func), so the cheapest verification is a REST round-trip through the
`client` fixture with hand-built fixtures.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.agent import Agent
from app.models.heal_event import AgentHealEvent
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.port_forward import PortForward
from app.models.wg_peer_snapshot import WgPeerSnapshot


def _agent(agent_type: str) -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name=f"{agent_type}-summary-test",
        type=agent_type,
        last_seen=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_tunnel_server_summary_counts_heal_events_in_last_24h(
    client, session_maker
) -> None:
    agent = _agent("server")
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
        server = TunnelServer(
            id=uuid.uuid4(),
            agent_id=agent.id,
            wg_port=51820,
            wg_interface="wg0",
            public_iface="eth0",
            tunnel_network="10.21.0.0/24",
        )
        s.add(server)
        await s.commit()

        now = datetime.now(timezone.utc)
        s.add(
            AgentHealEvent(
                agent_id=agent.id,
                mode="server",
                interface="wg0",
                healed=["mss-clamp"],
                occurred_at=now - timedelta(minutes=10),
            )
        )
        s.add(
            AgentHealEvent(
                agent_id=agent.id,
                mode="server",
                interface="wg0",
                healed=["mss-clamp"],
                occurred_at=now - timedelta(hours=48),  # outside the window
            )
        )
        await s.commit()
        server_id = server.id

    resp = await client.get(f"/api/tunnel-servers/{server_id}/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["recent_heal_count"] == 1
    assert body["peer_count"] == 0
    assert body["forward_count"] == 0


@pytest.mark.asyncio
async def test_tunnel_server_summary_counts_forwards(client, session_maker) -> None:
    server_agent = _agent("server")
    client_agent = _agent("client")
    async with session_maker() as s:
        s.add_all([server_agent, client_agent])
        await s.commit()
        server = TunnelServer(
            id=uuid.uuid4(),
            agent_id=server_agent.id,
            wg_port=51820,
            wg_interface="wg0",
            public_iface="eth0",
            tunnel_network="10.21.0.0/24",
        )
        s.add(server)
        await s.commit()
        tc = TunnelClient(id=uuid.uuid4(), agent_id=client_agent.id, is_gateway=False)
        s.add(tc)
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=tc.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=257,
            route_table_id=100,
        )
        s.add(att)
        await s.commit()
        s.add_all(
            [
                PortForward(
                    attachment_id=att.id,
                    protocol="tcp",
                    public_port=8080,
                    destination_ip="10.21.0.2",
                    destination_port=8080,
                ),
                PortForward(
                    attachment_id=att.id,
                    protocol="tcp",
                    public_port=8443,
                    destination_ip="10.21.0.2",
                    destination_port=8443,
                ),
            ]
        )
        await s.commit()
        server_id = server.id

    resp = await client.get(f"/api/tunnel-servers/{server_id}/summary")
    assert resp.status_code == 200
    assert resp.json()["forward_count"] == 2


@pytest.mark.asyncio
async def test_tunnel_client_summary_returns_attachment_health(client, session_maker) -> None:
    server_agent = _agent("server")
    client_agent = _agent("client")
    async with session_maker() as s:
        s.add_all([server_agent, client_agent])
        await s.commit()
        server = TunnelServer(
            id=uuid.uuid4(),
            agent_id=server_agent.id,
            wg_port=51820,
            wg_interface="wg0",
            public_iface="eth0",
            tunnel_network="10.21.0.0/24",
        )
        s.add(server)
        await s.commit()
        tc = TunnelClient(
            id=uuid.uuid4(),
            agent_id=client_agent.id,
            is_gateway=True,
            lan_ip="192.168.40.10",
        )
        s.add(tc)
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=tc.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=257,
            route_table_id=100,
        )
        s.add(att)
        await s.commit()

        # One mesh peer with a recent handshake on the attachment's iface.
        s.add(
            WgPeerSnapshot(
                agent_id=client_agent.id,
                interface="wg0",
                kind="mesh",
                public_key="server-pk",
                rx_bytes=1024,
                tx_bytes=512,
                last_handshake_unix=int(datetime.now(timezone.utc).timestamp()) - 30,
            )
        )
        await s.commit()
        client_id = tc.id

    resp = await client.get(f"/api/tunnel-clients/{client_id}/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_rx_bytes"] == 1024
    assert body["total_tx_bytes"] == 512
    assert len(body["attachment_health"]) == 1
    h = body["attachment_health"][0]
    assert h["wg_interface"] == "wg0"
    assert h["peer_count"] == 1
    assert h["last_handshake_unix"] is not None

"""Tests for the auto-whitelist builder + install endpoint dispatch.

Covers:
  * Every scope set the operator picked (mesh agents, tunnel-server IPs,
    tunnel mesh subnets, VPN subnets, gateway LAN subnets, discovered
    LAN clients).
  * Target agent's own IPs are excluded (no point self-whitelisting).
  * Hash is stable under row-order changes.
  * /tunnel-servers/{id}/crowdsec/install dispatches the right command
    via the FakeManager.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.models.agent import Agent
from app.models.gateway_lan_client import GatewayLanClient
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.vpn_endpoint import VpnEndpoint
from app.services.crowdsec_ops import build_whitelist, whitelist_hash


def _agent(agent_type: str, public_ip: str | None) -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name=f"{agent_type}-cs-test",
        type=agent_type,
        public_ip=public_ip,
        last_seen=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_whitelist_includes_other_agent_ips_but_excludes_self(db) -> None:
    self_agent = _agent("server", "1.1.1.1")
    other_server = _agent("server", "2.2.2.2")
    other_client = _agent("client", "3.3.3.3")
    db.add_all([self_agent, other_server, other_client])
    await db.commit()

    payload = await build_whitelist(self_agent.id, db)
    assert "1.1.1.1" not in payload["ips"]
    assert "2.2.2.2" in payload["ips"]
    assert "3.3.3.3" in payload["ips"]


@pytest.mark.asyncio
async def test_whitelist_includes_tunnel_server_ips(db) -> None:
    self_agent = _agent("server", "1.1.1.1")
    other_agent = _agent("server", "2.2.2.2")
    db.add_all([self_agent, other_agent])
    await db.commit()
    other_server = TunnelServer(
        id=uuid.uuid4(),
        agent_id=other_agent.id,
        wg_port=51820,
        wg_interface="wg0",
        public_iface="eth0",
        tunnel_network="10.21.0.0/24",
    )
    db.add(other_server)
    await db.commit()
    db.add_all([
        TunnelServerIP(id=uuid.uuid4(), tunnel_server_id=other_server.id, address="2.2.2.2", is_primary=True),
        TunnelServerIP(id=uuid.uuid4(), tunnel_server_id=other_server.id, address="4.4.4.4", is_primary=False),
    ])
    await db.commit()

    payload = await build_whitelist(self_agent.id, db)
    assert "2.2.2.2" in payload["ips"]
    assert "4.4.4.4" in payload["ips"]
    # Mesh subnet rolls up to CIDRs.
    assert "10.21.0.0/24" in payload["cidrs"]


@pytest.mark.asyncio
async def test_whitelist_includes_gateway_lan_subnets_and_discovered_hosts(db) -> None:
    self_agent = _agent("server", "1.1.1.1")
    gw_agent = _agent("client", "5.5.5.5")
    db.add_all([self_agent, gw_agent])
    await db.commit()
    tc = TunnelClient(
        id=uuid.uuid4(),
        agent_id=gw_agent.id,
        is_gateway=True,
        vm_network="192.168.40.0/24",
        lan_ip="192.168.40.10",
    )
    db.add(tc)
    await db.commit()
    db.add_all(
        [
            GatewayLanClient(tunnel_client_id=tc.id, lan_ip="192.168.40.50"),
            GatewayLanClient(tunnel_client_id=tc.id, lan_ip="192.168.40.111"),
        ]
    )
    await db.commit()

    payload = await build_whitelist(self_agent.id, db)
    assert "192.168.40.0/24" in payload["cidrs"]
    assert "192.168.40.50" in payload["ips"]
    assert "192.168.40.111" in payload["ips"]


@pytest.mark.asyncio
async def test_whitelist_includes_vpn_endpoint_networks(db) -> None:
    self_agent = _agent("server", "1.1.1.1")
    gw_agent = _agent("client", "5.5.5.5")
    db.add_all([self_agent, gw_agent])
    await db.commit()
    tc = TunnelClient(id=uuid.uuid4(), agent_id=gw_agent.id, is_gateway=True)
    db.add(tc)
    await db.commit()
    db.add(
        VpnEndpoint(
            id=uuid.uuid4(),
            tunnel_client_id=tc.id,
            wg_interface="wg-vpn0",
            listen_port=51821,
            vpn_network="10.99.0.0/24",
            public_endpoint="vpn.example.com:51821",
            enabled=True,
        )
    )
    await db.commit()

    payload = await build_whitelist(self_agent.id, db)
    assert "10.99.0.0/24" in payload["cidrs"]


def test_whitelist_hash_is_stable() -> None:
    a = {"ips": ["1.1.1.1", "2.2.2.2"], "cidrs": ["10.0.0.0/24"]}
    b = {"cidrs": ["10.0.0.0/24"], "ips": ["1.1.1.1", "2.2.2.2"]}
    assert whitelist_hash(a) == whitelist_hash(b)


def test_whitelist_hash_changes_with_content() -> None:
    base = {"ips": ["1.1.1.1"], "cidrs": []}
    modded = {"ips": ["1.1.1.1", "2.2.2.2"], "cidrs": []}
    assert whitelist_hash(base) != whitelist_hash(modded)


@pytest.mark.asyncio
async def test_install_endpoint_dispatches_crowdsec_install(
    client, session_maker, fake_manager
) -> None:
    # Fake-manager: report the agent as online so send_command queues
    # rather than 409s.
    server_agent = _agent("server", "1.1.1.1")
    other_agent = _agent("client", "2.2.2.2")
    async with session_maker() as s:
        s.add_all([server_agent, other_agent])
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
        server_id = server.id
    fake_manager.online.add(str(server_agent.id))

    resp = await client.post(f"/api/tunnel-servers/{server_id}/crowdsec/install")
    assert resp.status_code == 202
    body = resp.json()
    assert body["sent"] is True
    assert body["command_id"]

    # Manager saw exactly one command with the right type + payload.
    assert len(fake_manager.sent) == 1
    msg = fake_manager.sent[0]["message"]
    assert msg["type"] == "crowdsec_install"
    assert "ips" in msg["params"]
    assert "cidrs" in msg["params"]
    # The other agent's public IP is in the whitelist; the server agent's own is not.
    assert "2.2.2.2" in msg["params"]["ips"]
    assert "1.1.1.1" not in msg["params"]["ips"]


@pytest.mark.asyncio
async def test_install_endpoint_409_when_agent_offline(
    client, session_maker, fake_manager
) -> None:
    server_agent = _agent("server", "1.1.1.1")
    async with session_maker() as s:
        s.add(server_agent)
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
        server_id = server.id
    # Note: fake_manager.online not populated → agent is offline.

    resp = await client.post(f"/api/tunnel-servers/{server_id}/crowdsec/install")
    assert resp.status_code == 409

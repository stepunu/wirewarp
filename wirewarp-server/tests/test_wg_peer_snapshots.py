"""Tests for the unified wg_peer_snapshots table.

Covers the heartbeat upsert path, the kind-derivation rule, and the
three router endpoints (tunnel-server, tunnel-client, vpn-endpoint).
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_server import TunnelServer
from app.models.vpn_endpoint import VpnEndpoint
from app.models.wg_peer_snapshot import WgPeerSnapshot
from app.websocket.handlers import handle_heartbeat


def _agent(agent_type: str = "server") -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name=f"{agent_type}-peer-test",
        type=agent_type,
        last_seen=datetime.now(timezone.utc),
    )


def _peer_entry(iface: str, pubkey: str, *, rx: int = 0, tx: int = 0, handshake: int | None = None) -> dict:
    return {
        "interface": iface,
        "public_key": pubkey,
        "endpoint": "1.2.3.4:51820",
        "allowed_ips": "10.0.0.2/32",
        "rx_bytes": rx,
        "tx_bytes": tx,
        "last_handshake_unix": handshake,
        "persistent_keepalive": 25,
    }


@pytest.mark.asyncio
async def test_heartbeat_upserts_wg_peer_snapshots(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_heartbeat(
        str(agent.id),
        {
            "all_peers": [
                _peer_entry("wg0", "pubkey-a", rx=100, tx=50, handshake=int(time.time())),
                _peer_entry("wg-vpn0", "pubkey-b", rx=200, tx=80),
            ]
        },
        db,
    )

    rows = (
        await db.execute(
            select(WgPeerSnapshot).where(WgPeerSnapshot.agent_id == agent.id)
        )
    ).scalars().all()
    by_pk = {r.public_key: r for r in rows}
    assert set(by_pk) == {"pubkey-a", "pubkey-b"}
    assert by_pk["pubkey-a"].kind == "mesh"
    assert by_pk["pubkey-a"].rx_bytes == 100
    assert by_pk["pubkey-b"].kind == "vpn"
    assert by_pk["pubkey-b"].tx_bytes == 80


@pytest.mark.asyncio
async def test_heartbeat_upsert_updates_existing_row(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    # First heartbeat — inserts.
    await handle_heartbeat(
        str(agent.id),
        {"all_peers": [_peer_entry("wg0", "pk1", rx=10, tx=5)]},
        db,
    )

    # Second — same key, larger counters.
    await handle_heartbeat(
        str(agent.id),
        {"all_peers": [_peer_entry("wg0", "pk1", rx=999, tx=777)]},
        db,
    )

    rows = (
        await db.execute(
            select(WgPeerSnapshot).where(WgPeerSnapshot.agent_id == agent.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].rx_bytes == 999
    assert rows[0].tx_bytes == 777


@pytest.mark.asyncio
async def test_heartbeat_ignores_malformed_peer_entries(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_heartbeat(
        str(agent.id),
        {
            "all_peers": [
                {},  # missing iface + pubkey
                {"interface": "wg0"},  # missing pubkey
                {"public_key": "x"},  # missing iface
                _peer_entry("wg0", "good-pk", rx=1),
            ]
        },
        db,
    )

    rows = (
        await db.execute(
            select(WgPeerSnapshot).where(WgPeerSnapshot.agent_id == agent.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].public_key == "good-pk"


@pytest.mark.asyncio
async def test_tunnel_server_wg_peers_endpoint(client, session_maker) -> None:
    """GET /api/tunnel-servers/{id}/wg-peers returns mesh-kind snapshots only."""
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
        s.add_all(
            [
                WgPeerSnapshot(
                    agent_id=agent.id,
                    interface="wg0",
                    kind="mesh",
                    public_key="pk-mesh",
                    rx_bytes=10,
                    tx_bytes=5,
                ),
                WgPeerSnapshot(
                    agent_id=agent.id,
                    interface="wg-vpn0",
                    kind="vpn",
                    public_key="pk-vpn",
                    rx_bytes=20,
                    tx_bytes=8,
                ),
            ]
        )
        await s.commit()
        server_id = server.id

    resp = await client.get(f"/api/tunnel-servers/{server_id}/wg-peers")
    assert resp.status_code == 200
    body = resp.json()
    assert [r["public_key"] for r in body] == ["pk-mesh"]
    # Computed field present.
    assert "handshake_age_seconds" in body[0]


@pytest.mark.asyncio
async def test_tunnel_server_summary_aggregates(client, session_maker) -> None:
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
        s.add_all(
            [
                WgPeerSnapshot(
                    agent_id=agent.id,
                    interface="wg0",
                    kind="mesh",
                    public_key="pk-a",
                    rx_bytes=100,
                    tx_bytes=50,
                ),
                WgPeerSnapshot(
                    agent_id=agent.id,
                    interface="wg0",
                    kind="mesh",
                    public_key="pk-b",
                    rx_bytes=200,
                    tx_bytes=70,
                ),
            ]
        )
        await s.commit()
        server_id = server.id

    resp = await client.get(f"/api/tunnel-servers/{server_id}/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["peer_count"] == 2
    assert body["total_rx_bytes"] == 300
    assert body["total_tx_bytes"] == 120
    assert body["recent_heal_count"] == 0
    assert body["forward_count"] == 0


@pytest.mark.asyncio
async def test_vpn_endpoint_wg_peers_scoped_to_interface(client, session_maker) -> None:
    agent = _agent("client")
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
        tc = TunnelClient(id=uuid.uuid4(), agent_id=agent.id, is_gateway=True)
        s.add(tc)
        await s.commit()
        endpoint = VpnEndpoint(
            id=uuid.uuid4(),
            tunnel_client_id=tc.id,
            wg_interface="wg-vpn0",
            listen_port=51821,
            vpn_network="10.99.0.0/24",
            public_endpoint="vpn.example.com:51821",
            enabled=True,
        )
        s.add(endpoint)
        await s.commit()
        s.add_all(
            [
                WgPeerSnapshot(
                    agent_id=agent.id,
                    interface="wg-vpn0",
                    kind="vpn",
                    public_key="pk-laptop",
                    rx_bytes=500,
                    tx_bytes=100,
                ),
                WgPeerSnapshot(
                    agent_id=agent.id,
                    interface="wg0",
                    kind="mesh",
                    public_key="pk-server",
                    rx_bytes=42,
                    tx_bytes=42,
                ),
            ]
        )
        await s.commit()
        endpoint_id = endpoint.id

    resp = await client.get(f"/api/vpn-endpoints/{endpoint_id}/wg-peers")
    assert resp.status_code == 200
    body = resp.json()
    assert [r["public_key"] for r in body] == ["pk-laptop"]

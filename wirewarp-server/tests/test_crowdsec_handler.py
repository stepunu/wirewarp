"""Tests for `handle_crowdsec_status` upserts and the /crowdsec route."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.tunnel_server import TunnelServer
from app.websocket.handlers import handle_crowdsec_status


def _agent() -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name="crowdsec-test",
        type="server",
        last_seen=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_crowdsec_status_insert(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_crowdsec_status(
        str(agent.id),
        {
            "type": "crowdsec_status",
            "running": True,
            "version": "1.6.4",
            "total_decisions": 42,
            "top_scenarios": [{"name": "ssh-bf", "count": 12}],
            "top_ips": [{"ip": "1.2.3.4", "count": 9}],
        },
        db,
    )

    snap = (
        await db.execute(
            select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent.id)
        )
    ).scalar_one()
    assert snap.running is True
    assert snap.version == "1.6.4"
    assert snap.total_decisions == 42
    assert snap.top_scenarios == [{"name": "ssh-bf", "count": 12}]


@pytest.mark.asyncio
async def test_crowdsec_status_upsert_updates_counts(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_crowdsec_status(
        str(agent.id),
        {"running": True, "version": "1.6.4", "total_decisions": 5},
        db,
    )
    await handle_crowdsec_status(
        str(agent.id),
        {"running": True, "version": "1.6.4", "total_decisions": 50},
        db,
    )

    rows = (
        await db.execute(
            select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].total_decisions == 50


@pytest.mark.asyncio
async def test_crowdsec_status_not_running_persists_sentinel(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_crowdsec_status(
        str(agent.id),
        {"running": False},
        db,
    )

    snap = (
        await db.execute(
            select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent.id)
        )
    ).scalar_one()
    assert snap.running is False
    assert snap.total_decisions == 0


@pytest.mark.asyncio
async def test_crowdsec_status_ignores_frame_without_running_field(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_crowdsec_status(str(agent.id), {"version": "x"}, db)

    rows = (
        await db.execute(
            select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent.id)
        )
    ).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_crowdsec_endpoint_returns_sentinel_when_missing(client, session_maker) -> None:
    agent = _agent()
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
        server_id = server.id

    resp = await client.get(f"/api/tunnel-servers/{server_id}/crowdsec")
    assert resp.status_code == 200
    body = resp.json()
    assert body["running"] is False
    assert body["total_decisions"] == 0


@pytest.mark.asyncio
async def test_crowdsec_endpoint_returns_stored_snapshot(client, session_maker) -> None:
    agent = _agent()
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
        s.add(
            CrowdSecSnapshot(
                agent_id=agent.id,
                running=True,
                version="1.6.4",
                total_decisions=7,
                top_scenarios=[{"name": "ssh-bf", "count": 3}],
                top_ips=[{"ip": "5.6.7.8", "count": 2}],
            )
        )
        await s.commit()
        server_id = server.id

    resp = await client.get(f"/api/tunnel-servers/{server_id}/crowdsec")
    assert resp.status_code == 200
    body = resp.json()
    assert body["running"] is True
    assert body["version"] == "1.6.4"
    assert body["top_scenarios"] == [{"name": "ssh-bf", "count": 3}]

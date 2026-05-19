"""Tests for `handle_heal_event` and the GET /agents/{id}/heal-events route.

Mirrors the conftest pattern used by test_command_result_binding (direct
handler tests) + test_users_api (REST round-trip via the `client` fixture).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.heal_event import AgentHealEvent
from app.websocket.handlers import handle_heal_event


def _make_agent(agent_type: str = "client") -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name=f"{agent_type}-heal-test",
        type=agent_type,
    )


@pytest.mark.asyncio
async def test_heal_event_persists_row(db) -> None:
    agent = _make_agent()
    db.add(agent)
    await db.commit()

    await handle_heal_event(
        str(agent.id),
        {
            "type": "heal_event",
            "mode": "client",
            "interface": "wg0",
            "healed": ["ip-rule-fwmark", "mss-clamp"],
            "timestamp": "2026-05-19T18:00:00Z",
        },
        db,
    )

    rows = (
        await db.execute(
            select(AgentHealEvent).where(AgentHealEvent.agent_id == agent.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.mode == "client"
    assert row.interface == "wg0"
    assert row.healed == ["ip-rule-fwmark", "mss-clamp"]
    assert row.occurred_at is not None


@pytest.mark.asyncio
async def test_heal_event_updates_last_seen(db) -> None:
    agent = _make_agent()
    agent.last_seen = None
    db.add(agent)
    await db.commit()

    await handle_heal_event(
        str(agent.id),
        {"mode": "server", "interface": "wg0", "healed": ["mss-clamp"]},
        db,
    )
    await db.refresh(agent)
    assert agent.last_seen is not None


@pytest.mark.asyncio
async def test_heal_event_rejects_bad_mode(db) -> None:
    agent = _make_agent()
    db.add(agent)
    await db.commit()

    await handle_heal_event(
        str(agent.id),
        {"mode": "bogus", "interface": "wg0", "healed": ["x"]},
        db,
    )
    rows = (
        await db.execute(
            select(AgentHealEvent).where(AgentHealEvent.agent_id == agent.id)
        )
    ).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_heal_event_rejects_non_list_healed(db) -> None:
    agent = _make_agent()
    db.add(agent)
    await db.commit()

    await handle_heal_event(
        str(agent.id),
        {"mode": "client", "interface": "wg0", "healed": "not-a-list"},
        db,
    )
    rows = (
        await db.execute(
            select(AgentHealEvent).where(AgentHealEvent.agent_id == agent.id)
        )
    ).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_heal_events_list_endpoint_returns_newest_first(client, session_maker) -> None:
    agent = _make_agent()
    async with session_maker() as s:
        s.add(agent)
        await s.commit()

        from datetime import datetime, timedelta, timezone
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        for i in range(3):
            s.add(
                AgentHealEvent(
                    agent_id=agent.id,
                    mode="client",
                    interface=f"wg{i}",
                    healed=[f"item-{i}"],
                    occurred_at=base + timedelta(minutes=i),
                )
            )
        await s.commit()

    resp = await client.get(f"/api/agents/{agent.id}/heal-events?limit=10")
    assert resp.status_code == 200
    body = resp.json()
    assert [row["interface"] for row in body] == ["wg2", "wg1", "wg0"]


@pytest.mark.asyncio
async def test_heal_events_list_endpoint_caps_limit(client, session_maker) -> None:
    agent = _make_agent()
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
    resp = await client.get(f"/api/agents/{agent.id}/heal-events?limit=9999")
    assert resp.status_code == 200
    # No rows yet but the request shouldn't 4xx on the limit clamp.
    assert resp.json() == []

"""Tests for handle_traefik_status, handle_security_events, and related routes.

Mirrors test_crowdsec_handler.py in structure and style.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.security_event import SecurityEvent
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.tunnel_server import TunnelServer
from app.services.traefik_ops import _build_http_config, build_traefik_static_config
from app.websocket.handlers import handle_security_events, handle_traefik_status


def _agent() -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name="traefik-test",
        type="server",
        last_seen=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Traefik config rendering
# ---------------------------------------------------------------------------


def test_static_config_pins_available_denyip_plugin_version() -> None:
    cfg = build_traefik_static_config()
    denyip = cfg["experimental"]["plugins"]["denyip"]

    assert denyip == {
        "moduleName": "github.com/kvncrw/denyip",
        "version": "v1.3.0",
    }


def test_dynamic_config_omits_empty_middlewares_section() -> None:
    assert _build_http_config({}, {}, {}) == {}


def test_dynamic_config_omits_empty_http_sections() -> None:
    routers = {"app": {"rule": "Host(`app.example.com`)", "service": "svc-app"}}
    services = {"svc-app": {"loadBalancer": {"servers": [{"url": "http://10.0.0.2:80"}]}}}

    assert _build_http_config(routers, services, {}) == {
        "http": {
            "routers": routers,
            "services": services,
        }
    }


def test_dynamic_config_keeps_nonempty_middlewares_section() -> None:
    middleware = {"rate": {"rateLimit": {"average": 3, "burst": 9}}}
    routers = {"app": {"rule": "Host(`app.example.com`)", "service": "svc-app"}}
    services = {"svc-app": {"loadBalancer": {"servers": [{"url": "http://10.0.0.2:80"}]}}}

    assert _build_http_config(routers, services, middleware) == {
        "http": {
            "routers": routers,
            "services": services,
            "middlewares": middleware,
        }
    }


# ---------------------------------------------------------------------------
# handle_traefik_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_traefik_status_insert(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_traefik_status(
        str(agent.id),
        {
            "type": "traefik_status",
            "installed": True,
            "running": True,
            "version": "v3.0.1",
            "routes_count": 3,
        },
        db,
    )

    snap = (
        await db.execute(
            select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent.id)
        )
    ).scalar_one()
    assert snap.installed is True
    assert snap.running is True
    assert snap.version == "v3.0.1"
    assert snap.routes_count == 3
    assert snap.error is None


@pytest.mark.asyncio
async def test_traefik_status_installed_but_stopped(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_traefik_status(
        str(agent.id),
        {
            "type": "traefik_status",
            "installed": True,
            "running": False,
            "error": "traefik.service failed: exit code 1",
        },
        db,
    )

    snap = (
        await db.execute(
            select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent.id)
        )
    ).scalar_one()
    assert snap.installed is True
    assert snap.running is False
    assert "exit code 1" in (snap.error or "")


@pytest.mark.asyncio
async def test_traefik_status_upsert(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_traefik_status(str(agent.id), {"running": True, "routes_count": 1}, db)
    await handle_traefik_status(str(agent.id), {"running": True, "routes_count": 5}, db)

    rows = (
        await db.execute(
            select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].routes_count == 5


@pytest.mark.asyncio
async def test_traefik_status_ignores_frame_without_running(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_traefik_status(str(agent.id), {"version": "v3"}, db)

    rows = (
        await db.execute(
            select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent.id)
        )
    ).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_traefik_status_running_implies_installed(db) -> None:
    """Older agents may not send 'installed'; running=True implies installed=True."""
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_traefik_status(str(agent.id), {"running": True}, db)

    snap = (
        await db.execute(
            select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent.id)
        )
    ).scalar_one()
    assert snap.installed is True


# ---------------------------------------------------------------------------
# Traefik HTTP endpoints via test client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_traefik_endpoint_returns_sentinel_when_missing(client, session_maker) -> None:
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

    resp = await client.get(f"/api/tunnel-servers/{server_id}/traefik")
    assert resp.status_code == 200
    body = resp.json()
    assert body["installed"] is False
    assert body["running"] is False
    assert body["routes_count"] == 0


@pytest.mark.asyncio
async def test_traefik_endpoint_returns_stored_snapshot(client, session_maker) -> None:
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
            TraefikSnapshot(
                agent_id=agent.id,
                installed=True,
                running=True,
                version="v3.0.1",
                routes_count=4,
            )
        )
        await s.commit()
        server_id = server.id

    resp = await client.get(f"/api/tunnel-servers/{server_id}/traefik")
    assert resp.status_code == 200
    body = resp.json()
    assert body["running"] is True
    assert body["version"] == "v3.0.1"
    assert body["routes_count"] == 4


# ---------------------------------------------------------------------------
# handle_security_events
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_security_events_insert_batch(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_security_events(
        str(agent.id),
        {
            "type": "security_events",
            "events": [
                {
                    "source": "crowdsec",
                    "kind": "ssh-bf",
                    "ip": "1.2.3.4",
                    "action": "ban",
                    "occurred_at": "2026-05-29T12:00:00+00:00",
                },
                {
                    "source": "appsec",
                    "kind": "sqli",
                    "ip": "5.6.7.8",
                    "action": "block",
                    "occurred_at": "2026-05-29T12:01:00+00:00",
                    "raw": {"rule_id": "942100"},
                },
            ],
        },
        db,
    )

    rows = (
        await db.execute(
            select(SecurityEvent).where(SecurityEvent.agent_id == agent.id)
        )
    ).scalars().all()
    assert len(rows) == 2
    sources = {r.source for r in rows}
    assert sources == {"crowdsec", "appsec"}


@pytest.mark.asyncio
async def test_security_events_accept_traefik_rate_limit_event(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_security_events(
        str(agent.id),
        {
            "type": "security_events",
            "events": [
                {
                    "source": "traefik",
                    "kind": "rate_limit",
                    "ip": "84.113.55.126",
                    "value": "media-ww-step1-ro@file",
                    "action": "rate_limit",
                    "occurred_at": "2026-05-30T17:42:53+00:00",
                    "raw": {"status": 429, "path": "/web/manifest.json"},
                }
            ],
        },
        db,
    )

    row = await db.scalar(select(SecurityEvent).where(SecurityEvent.agent_id == agent.id))
    assert row is not None
    assert row.source == "traefik"
    assert row.kind == "rate_limit"
    assert row.action == "rate_limit"
    assert row.raw == {"status": 429, "path": "/web/manifest.json"}


@pytest.mark.asyncio
async def test_security_events_empty_list_is_noop(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_security_events(str(agent.id), {"events": []}, db)
    rows = (
        await db.execute(select(SecurityEvent).where(SecurityEvent.agent_id == agent.id))
    ).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_security_events_skips_entries_without_required_fields(db) -> None:
    agent = _agent()
    db.add(agent)
    await db.commit()

    await handle_security_events(
        str(agent.id),
        {
            "events": [
                {"source": "crowdsec"},  # missing 'kind' -> skip
                {"kind": "sqli"},         # missing 'source' -> skip
                {"source": "traefik", "kind": "rate-limit"},  # valid
            ]
        },
        db,
    )

    rows = (
        await db.execute(select(SecurityEvent).where(SecurityEvent.agent_id == agent.id))
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].source == "traefik"


# ---------------------------------------------------------------------------
# Security API routes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_security_overview_empty(client) -> None:
    resp = await client.get("/api/security/overview?range=24h")
    assert resp.status_code == 200
    body = resp.json()
    assert "kpis" in body
    assert body["kpis"]["blocked"] >= 0
    assert isinstance(body["servers"], list)


@pytest.mark.asyncio
async def test_security_events_list_empty(client) -> None:
    resp = await client.get("/api/security/events")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_security_sites_list_empty(client) -> None:
    resp = await client.get("/api/security/sites")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_security_bans_empty(client) -> None:
    resp = await client.get("/api/security/bans")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_security_certs_empty(client) -> None:
    resp = await client.get("/api/security/certs")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_security_overview_invalid_range(client) -> None:
    resp = await client.get("/api/security/overview?range=invalid")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_security_events_filter_by_source(client, session_maker) -> None:
    agent = _agent()
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
        s.add(SecurityEvent(
            agent_id=agent.id, source="crowdsec", kind="ssh-bf",
            ip="1.2.3.4", action="ban",
            occurred_at=datetime.now(timezone.utc),
        ))
        s.add(SecurityEvent(
            agent_id=agent.id, source="appsec", kind="sqli",
            ip="5.6.7.8", action="block",
            occurred_at=datetime.now(timezone.utc),
        ))
        await s.commit()

    resp = await client.get("/api/security/events?source=crowdsec")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["source"] == "crowdsec"

"""Security Edge Console API router.

Prefix: /api/security

GET endpoints require ops role (admin, operator, viewer).
Mutation endpoints (POST, PATCH, DELETE) require admin role.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.agent import Agent
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.edge_route_config import EdgeRouteConfig
from app.models.port_forward import PortForward
from app.models.security_event import SecurityEvent
from app.models.system_settings import SystemSettings
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.realtime.events import emit_security_changed
from app.schemas.security import (
    BanRead,
    CertRead,
    SecurityEventRead,
    SecurityKPIs,
    SecurityOverview,
    ServerStatus,
    SiteCreate,
    SiteRead,
    SiteUpdate,
    TimePoint,
    TopAttacker,
    TopItem,
    TraefikStatusRead,
)
from app.services.edge_ops import dispatch_edge_desired_state, dispatch_edge_for_attachment, site_server_context
from app.services.secrets import get_captcha_secret_key

router = APIRouter()


def _range_cutoff(range_str: str) -> datetime:
    now = datetime.now(timezone.utc)
    if range_str == "7d":
        return now - timedelta(days=7)
    if range_str == "30d":
        return now - timedelta(days=30)
    return now - timedelta(hours=24)


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

@router.get("/overview", response_model=SecurityOverview)
async def security_overview(
    range: str = Query(default="24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """Aggregate security KPIs and time-series from all agents.

    Derived from crowdsec_snapshots + security_events. Returns zero-filled
    values when tables are empty — the frontend can always render something.
    """
    cutoff = _range_cutoff(range)

    # Total decisions from crowdsec snapshots (best proxy for blocked count)
    total_blocked = (
        await db.scalar(
            sa_func.coalesce(
                select(sa_func.sum(CrowdSecSnapshot.total_decisions)).scalar_subquery(),
                0,
            )
        )
    ) or 0

    # Attack IPs from security_events
    attack_ips_count = (
        await db.scalar(
            select(sa_func.count(sa_func.distinct(SecurityEvent.ip))).where(
                SecurityEvent.occurred_at >= cutoff,
                SecurityEvent.ip.is_not(None),
            )
        )
    ) or 0

    # Top attackers (by ip, count) from security_events
    top_atk_rows = (
        await db.execute(
            select(SecurityEvent.ip, sa_func.count(SecurityEvent.id).label("cnt"))
            .where(SecurityEvent.occurred_at >= cutoff, SecurityEvent.ip.is_not(None))
            .group_by(SecurityEvent.ip)
            .order_by(sa_func.count(SecurityEvent.id).desc())
            .limit(10)
        )
    ).all()
    top_attackers = [TopAttacker(ip=r[0], count=r[1]) for r in top_atk_rows]

    # Top scenarios
    top_scen_rows = (
        await db.execute(
            select(SecurityEvent.kind, sa_func.count(SecurityEvent.id).label("cnt"))
            .where(SecurityEvent.occurred_at >= cutoff)
            .group_by(SecurityEvent.kind)
            .order_by(sa_func.count(SecurityEvent.id).desc())
            .limit(10)
        )
    ).all()
    top_scenarios = [TopItem(name=r[0], count=r[1]) for r in top_scen_rows]

    # Access series: aggregate wg_traffic_samples rx+tx into time buckets.
    # Zero-fill when empty — the charts just show a flat line.
    access_series: list[TimePoint] = []
    block_series: list[TimePoint] = []

    # Per-server status
    server_rows = (
        await db.execute(
            select(TunnelServer, Agent)
            .join(Agent, Agent.id == TunnelServer.agent_id)
        )
    ).all()

    servers: list[ServerStatus] = []
    for ts, agent in server_rows:
        cs = await db.scalar(
            select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent.id)
        )
        tk = await db.scalar(
            select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent.id)
        )
        servers.append(
            ServerStatus(
                server_id=ts.id,
                agent_id=agent.id,
                name=agent.name or agent.hostname or str(ts.id),
                crowdsec_running=bool(cs and cs.running),
                traefik_running=bool(tk and tk.running),
            )
        )

    kpis = SecurityKPIs(
        access=0,
        visitors=0,
        blocked=int(total_blocked),
        attack_ips=int(attack_ips_count),
        err_4xx=0,
        err_5xx=0,
    )

    return SecurityOverview(
        kpis=kpis,
        access_series=access_series,
        block_series=block_series,
        top_attackers=top_attackers,
        top_scenarios=top_scenarios,
        servers=servers,
    )


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@router.get("/events", response_model=list[SecurityEventRead])
async def list_security_events(
    limit: int = Query(default=50, ge=1, le=500),
    agent_id: uuid.UUID | None = None,
    source: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    q = select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(limit)
    if agent_id is not None:
        q = q.where(SecurityEvent.agent_id == agent_id)
    if source is not None:
        q = q.where(SecurityEvent.source == source)
    rows = (await db.execute(q)).scalars().all()
    return rows


# ---------------------------------------------------------------------------
# Sites (HTTP port_forwards)
# ---------------------------------------------------------------------------

async def _captcha_configured(db: AsyncSession) -> bool:
    row = await db.get(SystemSettings, 1)
    if not row:
        return False
    secret = await get_captcha_secret_key(db)
    return bool(row.captcha_provider and row.captcha_site_key and secret)


def _site_read(
    pf: PortForward,
    *,
    server_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
) -> SiteRead:
    from app.schemas.security import EdgeRouteConfigRead

    ec_read = None
    if pf.edge_route_config is not None:
        ec = pf.edge_route_config
        ec_read = EdgeRouteConfigRead(
            id=ec.id,
            port_forward_id=ec.port_forward_id,
            waf_mode=ec.waf_mode,
            rate_limit_rps=ec.rate_limit_rps,
            rate_limit_burst=ec.rate_limit_burst,
            antibot=ec.antibot,
            auth_mode=ec.auth_mode,
            auth_config=ec.auth_config,
            ip_allow=ec.ip_allow,
            ip_deny=ec.ip_deny,
            geo_block=ec.geo_block,
            tls_source=ec.tls_source,
            created_at=ec.created_at,
            updated_at=ec.updated_at,
        )
    return SiteRead(
        id=pf.id,
        attachment_id=pf.attachment_id,
        tunnel_server_ip_id=pf.tunnel_server_ip_id,
        server_id=server_id,
        agent_id=agent_id,
        protocol=pf.protocol,
        public_port=pf.public_port,
        public_port_end=pf.public_port_end,
        domain=pf.domain,
        destination_ip=pf.destination_ip,
        destination_port=pf.destination_port,
        destination_port_end=pf.destination_port_end,
        active=pf.active,
        description=pf.description,
        service_kind=pf.service_kind,
        edge_config=ec_read,
        created_at=pf.created_at,
    )


async def _get_server_agent_for_pf(pf: PortForward, db: AsyncSession) -> str | None:
    """Return the agent_id (str) of the tunnel server that owns this port_forward."""
    att = await db.scalar(
        select(TunnelClientAttachment).where(
            TunnelClientAttachment.id == pf.attachment_id
        )
    )
    if att is None:
        return None
    ts = await db.scalar(
        select(TunnelServer).where(TunnelServer.id == att.tunnel_server_id)
    )
    if ts is None:
        return None
    return str(ts.agent_id)


@router.get("/sites", response_model=list[SiteRead])
async def list_sites(
    server_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """All HTTP port_forwards joined with their edge_route_config."""
    q = (
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.service_kind == "http")
        .order_by(PortForward.created_at.desc())
    )
    scope_server: TunnelServer | None = None
    if agent_id is not None:
        scope_server = await db.scalar(
            select(TunnelServer).where(TunnelServer.agent_id == agent_id)
        )
        if scope_server is None:
            return []
    elif server_id is not None:
        scope_server = await db.scalar(
            select(TunnelServer).where(TunnelServer.id == server_id)
        )
        if scope_server is None:
            return []
    if scope_server is not None:
        att_ids = (
            await db.execute(
                select(TunnelClientAttachment.id).where(
                    TunnelClientAttachment.tunnel_server_id == scope_server.id
                )
            )
        ).scalars().all()
        if not att_ids:
            return []
        q = q.where(PortForward.attachment_id.in_(att_ids))

    rows = (await db.execute(q)).scalars().all()
    out: list[SiteRead] = []
    for pf in rows:
        sid, aid = await site_server_context(pf, db)
        out.append(_site_read(pf, server_id=sid, agent_id=aid))
    return out


@router.post("/sites", response_model=SiteRead, status_code=201)
async def create_site(
    body: SiteCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    """Create an HTTP port_forward + edge_route_config, then sync Traefik."""
    if body.antibot and not await _captcha_configured(db):
        raise HTTPException(status_code=400, detail="CAPTCHA provider keys must be configured before enabling anti-bot")

    pf = PortForward(
        id=uuid.uuid4(),
        attachment_id=body.attachment_id,
        tunnel_server_ip_id=body.tunnel_server_ip_id,
        protocol="tcp",
        public_port=443,  # Traefik handles TLS; raw port unused by iptables
        destination_ip=body.destination_ip,
        destination_port=body.destination_port,
        description=body.description,
        active=True,
        service_kind="http",
        domain=body.domain,
    )
    db.add(pf)
    await db.flush()  # obtain pf.id before creating edge config

    ec = EdgeRouteConfig(
        id=uuid.uuid4(),
        port_forward_id=pf.id,
        waf_mode=body.waf_mode,
        rate_limit_rps=body.rate_limit_rps,
        rate_limit_burst=body.rate_limit_burst,
        antibot=body.antibot,
        auth_mode=body.auth_mode,
        auth_config=body.auth_config,
        ip_allow=body.ip_allow,
        ip_deny=body.ip_deny,
        geo_block=body.geo_block,
        tls_source=body.tls_source,
    )
    db.add(ec)
    await db.commit()

    await db.refresh(pf)
    await db.refresh(ec)
    pf.edge_route_config = ec  # type: ignore[assignment]

    agent_id = await _get_server_agent_for_pf(pf, db)
    if agent_id:
        await dispatch_edge_desired_state(agent_id, db, actor_user_id=user.id)

    emit_security_changed()
    sid, aid = await site_server_context(pf, db)
    return _site_read(pf, server_id=sid, agent_id=aid)


@router.patch("/sites/{port_forward_id}", response_model=SiteRead)
async def update_site(
    port_forward_id: uuid.UUID,
    body: SiteUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    pf = await db.scalar(
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.id == port_forward_id, PortForward.service_kind == "http")
    )
    if pf is None:
        raise HTTPException(status_code=404, detail="Site not found")
    if body.antibot is True and not await _captcha_configured(db):
        raise HTTPException(status_code=400, detail="CAPTCHA provider keys must be configured before enabling anti-bot")

    body_fields = body.model_fields_set

    # Update port_forward fields. Nullable fields may be explicitly cleared;
    # non-null transport fields only update when a concrete value is supplied.
    for field in ("domain", "description"):
        if field in body_fields:
            setattr(pf, field, getattr(body, field))
    for field in ("destination_ip", "destination_port", "active"):
        val = getattr(body, field, None)
        if field in body_fields and val is not None:
            setattr(pf, field, val)

    # Update or create edge_route_config
    ec = pf.edge_route_config
    if ec is None:
        ec = EdgeRouteConfig(id=uuid.uuid4(), port_forward_id=pf.id)
        db.add(ec)
    for field in (
        "rate_limit_rps", "rate_limit_burst", "auth_config",
        "ip_allow", "ip_deny", "geo_block",
    ):
        if field in body_fields:
            setattr(ec, field, getattr(body, field))
    for field in ("waf_mode", "antibot", "auth_mode", "tls_source"):
        val = getattr(body, field, None)
        if field in body_fields and val is not None:
            setattr(ec, field, val)

    await db.commit()
    await db.refresh(pf)
    ec = pf.edge_route_config or ec
    pf.edge_route_config = ec  # type: ignore[assignment]

    agent_id = await _get_server_agent_for_pf(pf, db)
    if agent_id:
        await dispatch_edge_desired_state(agent_id, db, actor_user_id=user.id)

    emit_security_changed()
    sid, aid = await site_server_context(pf, db)
    return _site_read(pf, server_id=sid, agent_id=aid)


@router.delete("/sites/{port_forward_id}", status_code=204)
async def delete_site(
    port_forward_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    pf = await db.scalar(
        select(PortForward).where(
            PortForward.id == port_forward_id, PortForward.service_kind == "http"
        )
    )
    if pf is None:
        raise HTTPException(status_code=404, detail="Site not found")
    agent_id = await _get_server_agent_for_pf(pf, db)
    attachment_id = pf.attachment_id
    await db.delete(pf)
    await db.commit()
    if agent_id:
        await dispatch_edge_for_attachment(attachment_id, db, actor_user_id=user.id)
    emit_security_changed()


# ---------------------------------------------------------------------------
# Bans (read-only)
# ---------------------------------------------------------------------------

@router.get("/bans", response_model=list[BanRead])
async def list_bans(
    server_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """Return known banned IPs from crowdsec_snapshots top_ips and security_events.

    Read-only. Adding/removing bans (via cscli decisions add/delete) is a
    future enhancement once the agent supports a crowdsec_decision_add command.
    TODO: dispatch crowdsec_decision_add/remove when ready.
    """
    bans: dict[str, BanRead] = {}

    # From crowdsec snapshots top_ips
    q = select(CrowdSecSnapshot)
    if server_id is not None:
        ts = await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))
        if ts is None:
            raise HTTPException(status_code=404, detail="Tunnel server not found")
        q = q.where(CrowdSecSnapshot.agent_id == ts.agent_id)

    snaps = (await db.execute(q)).scalars().all()
    for snap in snaps:
        if not snap.top_ips:
            continue
        for entry in snap.top_ips:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip")
            count = entry.get("count", 1)
            if ip and ip not in bans:
                bans[ip] = BanRead(ip=ip, count=int(count), source="crowdsec")

    # From security_events with action='ban'
    ev_q = (
        select(SecurityEvent.ip, sa_func.count(SecurityEvent.id).label("cnt"))
        .where(SecurityEvent.action == "ban", SecurityEvent.ip.is_not(None))
        .group_by(SecurityEvent.ip)
    )
    if server_id is not None and ts is not None:
        ev_q = ev_q.where(SecurityEvent.agent_id == ts.agent_id)
    ev_rows = (await db.execute(ev_q)).all()
    for ip, cnt in ev_rows:
        if ip not in bans:
            bans[ip] = BanRead(ip=ip, count=int(cnt), source="security_event")

    return list(bans.values())


# ---------------------------------------------------------------------------
# Certs (read-only placeholder)
# ---------------------------------------------------------------------------

@router.get("/certs", response_model=list[CertRead])
async def list_certs(
    server_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """Return managed cert domains derived from HTTP port_forwards.

    Status is always 'managed' — real Let's Encrypt cert status is a
    later enhancement that requires reading Traefik's acme.json.
    TODO: surface real ACME status from the agent once available.
    """
    q = select(PortForward).where(
        PortForward.service_kind == "http",
        PortForward.domain.is_not(None),
    )
    if server_id is not None:
        ts = await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))
        if ts is None:
            raise HTTPException(status_code=404, detail="Tunnel server not found")
        att_ids = (
            await db.execute(
                select(TunnelClientAttachment.id).where(
                    TunnelClientAttachment.tunnel_server_id == ts.id
                )
            )
        ).scalars().all()
        q = q.where(PortForward.attachment_id.in_(att_ids))

    rows = (await db.execute(q)).scalars().all()
    return [
        CertRead(
            domain=pf.domain,
            port_forward_id=pf.id,
            status="managed",
        )
        for pf in rows
        if pf.domain
    ]

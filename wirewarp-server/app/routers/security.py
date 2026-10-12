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
from app.models.http_route import HTTPRoute
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.edge_node import EdgeNode
from app.models.security_event import SecurityEvent
from app.models.system_settings import SystemSettings
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.realtime.events import emit_edge_changed, emit_security_changed
from app.schemas.security import (
    BanRead,
    CertRead,
    EffectiveRateLimit,
    EffectiveRateLimitValue,
    SecurityEventRead,
    SecurityEventGroupRead,
    SecurityKPIs,
    SecurityOverview,
    ServerStatus,
    ServerEdgePolicyRead,
    ServerEdgePolicyUpdate,
    SiteEffectivePolicy,
    SiteCreate,
    SiteRead,
    SiteUpdate,
    TimePoint,
    TopAttacker,
    TopItem,
    TraefikStatusRead,
    TraefikImportPreview,
    TraefikImportRequest,
    TraefikImportResult,
)
from app.services.edge_port_conflicts import (
    find_active_raw_edge_forward_on_server,
    server_id_for_attachment,
)
from app.services.edge_ops import (
    dispatch_edge_desired_state,
    edge_feature_disabled_detail,
    edge_unavailable_reason,
    site_server_context,
)
from app.services.edge_ownership import get_edge_owner
from app.services.edge_render import validate_edge_configuration
from app.schemas.edge import EdgeRouteUpsert
from pydantic import ValidationError
from app.services.secrets import get_captcha_secret_key
from app.services.traefik_importer import preview_traefik_import

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

    from app.models.tunnel_client import TunnelClient
    from app.services.edge_relay_ops import load_relay_routes
    from app.services.edge_ops import edge_runtime_mode

    # Capabilities belong to the agent. Gateways do not need a VPS attachment.
    server_rows = (
        await db.execute(
            select(Agent, TunnelServer, TunnelClient, EdgeNode, CrowdSecSnapshot, TraefikSnapshot)
            .outerjoin(TunnelServer, TunnelServer.agent_id == Agent.id)
            .outerjoin(TunnelClient, TunnelClient.agent_id == Agent.id)
            .outerjoin(EdgeNode, EdgeNode.agent_id == Agent.id)
            .outerjoin(CrowdSecSnapshot, CrowdSecSnapshot.agent_id == Agent.id)
            .outerjoin(TraefikSnapshot, TraefikSnapshot.agent_id == Agent.id)
            .where((Agent.type == "server") | TunnelClient.is_gateway.is_(True))
            .order_by(Agent.name, Agent.id)
        )
    ).all()
    route_counts = dict((await db.execute(
        select(HTTPRoute.agent_id, sa_func.count(HTTPRoute.id)).group_by(HTTPRoute.agent_id)
    )).all())
    active_route_counts = dict((await db.execute(
        select(HTTPRoute.agent_id, sa_func.count(HTTPRoute.id)).where(HTTPRoute.active.is_(True)).group_by(HTTPRoute.agent_id)
    )).all())

    servers: list[ServerStatus] = []
    for agent, ts, _gateway, owner, cs, tk in server_rows:
        role = "server" if agent.type == "server" else "gateway"
        runtime_mode = edge_runtime_mode(owner) if owner else "disabled"
        relay_only = runtime_mode == "relay_only"
        relay_routes = await load_relay_routes(db, agent.id) if ts else []
        servers.append(
            ServerStatus(
                server_id=ts.id if ts else None,
                agent_id=agent.id,
                name=agent.name or agent.hostname or str(agent.id),
                role=role,
                placement="gateway_edge" if role == "gateway" else "vps_relay" if relay_only else "vps_edge",
                runtime_mode=runtime_mode,
                edge_mode=owner.edge_mode if owner else "tcp_udp_only",
                edge_state=owner.edge_state if owner else "disabled",
                edge_install_phase=owner.edge_install_phase if owner else "disabled",
                routes_count=route_counts.get(agent.id, 0),
                active_routes_count=active_route_counts.get(agent.id, 0),
                relay_routes_count=len(relay_routes),
                crowdsec_running=bool(cs and cs.running),
                traefik_running=bool(tk and tk.running),
                crowdsec_installed=cs.installed if cs else None,
                traefik_installed=tk.installed if tk else None,
                crowdsec_phase=cs.phase if cs else None,
                traefik_phase=tk.phase if tk else None,
                crowdsec_error=(cs.last_error or cs.error) if cs else None,
                traefik_error=(tk.last_error or tk.error) if tk else None,
                crowdsec_updated_at=cs.updated_at if cs else None,
                traefik_updated_at=tk.updated_at if tk else None,
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
        http_routes_count=sum(node.routes_count for node in servers),
        active_http_routes_count=sum(node.active_routes_count for node in servers),
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


@router.get("/events/groups", response_model=list[SecurityEventGroupRead])
async def list_security_event_groups(
    limit: int = Query(default=50, ge=1, le=500),
    agent_id: uuid.UUID | None = None,
    source: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    q = select(
        SecurityEvent.agent_id,
        SecurityEvent.source,
        SecurityEvent.kind,
        SecurityEvent.ip,
        SecurityEvent.value,
        SecurityEvent.action,
        sa_func.count(SecurityEvent.id).label("cnt"),
        sa_func.min(SecurityEvent.occurred_at).label("first_seen_at"),
        sa_func.max(SecurityEvent.occurred_at).label("last_seen_at"),
    )
    if agent_id is not None:
        q = q.where(SecurityEvent.agent_id == agent_id)
    if source is not None:
        q = q.where(SecurityEvent.source == source)
    q = (
        q.group_by(
            SecurityEvent.agent_id,
            SecurityEvent.source,
            SecurityEvent.kind,
            SecurityEvent.ip,
            SecurityEvent.value,
            SecurityEvent.action,
        )
        .order_by(sa_func.max(SecurityEvent.occurred_at).desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).all()
    return [
        SecurityEventGroupRead(
            agent_id=row[0],
            source=row[1],
            kind=row[2],
            ip=row[3],
            value=row[4],
            action=row[5],
            count=int(row[6]),
            first_seen_at=row[7],
            last_seen_at=row[8],
        )
        for row in rows
    ]


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
    pf: HTTPRoute,
    *,
    server_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
    server: EdgeNode | None = None,
) -> SiteRead:
    from app.schemas.security import EdgeRouteConfigRead

    ec_read = None
    if pf.edge_route_config is not None:
        ec = pf.edge_route_config
        ec_read = EdgeRouteConfigRead(
            id=ec.id,
            route_id=ec.route_id,
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
            upstream_scheme=ec.upstream_scheme,
            upstream_insecure_skip_verify=ec.upstream_insecure_skip_verify,
            imported_router_name=ec.imported_router_name,
            imported_service_name=ec.imported_service_name,
            imported_middlewares=ec.imported_middlewares,
            import_warnings=ec.import_warnings,
            created_at=ec.created_at,
            updated_at=ec.updated_at,
        )
    return SiteRead(
        id=pf.id,
        attachment_id=pf.public_ingress.attachment_id if pf.public_ingress else None,
        tunnel_server_ip_id=pf.public_ingress.tunnel_server_ip_id if pf.public_ingress else None,
        server_id=server_id,
        agent_id=agent_id,
        protocol="tcp",
        public_port=pf.public_ingress.public_port if pf.public_ingress else None,
        visibility=pf.visibility,
        domain=pf.domain,
        destination_ip=pf.destination_ip,
        destination_port=pf.destination_port,
        active=pf.active,
        description=pf.description,
        service_kind=pf.service_kind,
        edge_config=ec_read,
        effective_policy=_effective_site_policy(pf, server),
        created_at=pf.created_at,
    )


def _safe_route_name(pf: HTTPRoute) -> str:
    return (pf.domain or str(pf.id)).replace(".", "-").replace(":", "-")


def _effective_site_policy(
    pf: HTTPRoute,
    server: EdgeNode | None,
) -> SiteEffectivePolicy:
    ec = pf.edge_route_config
    safe_name = _safe_route_name(pf)
    middleware_chain: list[str] = []
    global_limit = None
    site_limit = None
    if server and server.edge_rate_limit_rps:
        burst = server.edge_rate_limit_burst or server.edge_rate_limit_rps * 5
        global_limit = EffectiveRateLimitValue(rps=server.edge_rate_limit_rps, burst=burst)
        middleware_chain.append("server-ratelimit")
    if ec and ec.rate_limit_rps:
        burst = ec.rate_limit_burst or ec.rate_limit_rps * 5
        site_limit = EffectiveRateLimitValue(rps=ec.rate_limit_rps, burst=burst)
        middleware_chain.append(f"ratelimit-{safe_name}")
    if ec and ec.ip_allow:
        middleware_chain.append(f"ipallow-{safe_name}")
    if ec and ec.ip_deny:
        middleware_chain.append(f"ipdeny-{safe_name}")
    if ec and ec.geo_block:
        middleware_chain.append(f"geoblock-{safe_name}")
    if ec and (ec.waf_mode != "off" or ec.antibot):
        middleware_chain.append("crowdsec-bouncer")
    if ec and ec.auth_mode == "basic" and ec.auth_config:
        middleware_chain.append(f"basicauth-{safe_name}")
    if ec and ec.auth_mode == "forward" and ec.auth_config:
        middleware_chain.append(f"forwardauth-{safe_name}")
    return SiteEffectivePolicy(
        rate_limit=EffectiveRateLimit(global_=global_limit, site=site_limit),
        middleware_chain=middleware_chain,
        warnings=[str(v) for v in (ec.import_warnings or [])] if ec else [],
    )


def _server_edge_policy_read(server: TunnelServer, owner: EdgeNode) -> ServerEdgePolicyRead:
    return ServerEdgePolicyRead(
        server_id=server.id,
        agent_id=server.agent_id,
        rate_limit_rps=owner.edge_rate_limit_rps,
        rate_limit_burst=owner.edge_rate_limit_burst,
    )


async def _ensure_security_edge_enabled_for_attachment(
    attachment_id: uuid.UUID,
    db: AsyncSession,
) -> TunnelServer:
    server_id = await server_id_for_attachment(db, attachment_id)
    if server_id is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    server = await db.get(TunnelServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    owner = await get_edge_owner(db, server.agent_id)
    if edge_unavailable_reason(owner):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(owner))
    return server


async def _ensure_security_edge_enabled_for_site(pf: HTTPRoute, db: AsyncSession) -> EdgeNode:
    owner = await get_edge_owner(db, pf.agent_id)
    if edge_unavailable_reason(owner):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(owner))
    return owner


def _validate_rate_limit(rps: int | None, burst: int | None) -> None:
    if rps is not None and rps < 1:
        raise HTTPException(status_code=400, detail="Rate limit RPS must be at least 1")
    if burst is not None and burst < 1:
        raise HTTPException(status_code=400, detail="Rate limit burst must be at least 1")


@router.get("/servers/{server_id}/edge-policy", response_model=ServerEdgePolicyRead)
async def get_server_edge_policy(
    server_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    server = await db.get(TunnelServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    return _server_edge_policy_read(server, await get_edge_owner(db, server.agent_id))


@router.patch("/servers/{server_id}/edge-policy", response_model=ServerEdgePolicyRead)
async def update_server_edge_policy(
    server_id: uuid.UUID,
    body: ServerEdgePolicyUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    server = await db.get(TunnelServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    owner = await get_edge_owner(db, server.agent_id)
    if edge_unavailable_reason(owner):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(owner))
    fields = body.model_fields_set
    rps = body.rate_limit_rps if "rate_limit_rps" in fields else owner.edge_rate_limit_rps
    burst = body.rate_limit_burst if "rate_limit_burst" in fields else owner.edge_rate_limit_burst
    _validate_rate_limit(rps, burst)
    if "rate_limit_rps" in fields:
        owner.edge_rate_limit_rps = body.rate_limit_rps
    if "rate_limit_burst" in fields:
        owner.edge_rate_limit_burst = body.rate_limit_burst
    await validate_edge_configuration(server.agent_id, db)
    await db.commit()
    await db.refresh(owner)
    await dispatch_edge_desired_state(server.agent_id, db, actor_user_id=user.id)
    emit_edge_changed()
    emit_security_changed()
    return _server_edge_policy_read(server, await get_edge_owner(db, server.agent_id))


@router.post("/traefik/import/preview", response_model=TraefikImportPreview)
async def preview_traefik_routes(
    body: TraefikImportRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    try:
        return await preview_traefik_import(body, db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/traefik/import", response_model=TraefikImportResult, status_code=201)
async def import_traefik_routes(
    body: TraefikImportRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    if body.activate:
        await _ensure_site_does_not_shadow_raw_edge_forward(
            db=db,
            attachment_id=body.attachment_id,
            active=True,
        )
    try:
        preview = await preview_traefik_import(body, db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    server = await db.get(TunnelServer, body.server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    owner = await get_edge_owner(db, server.agent_id)
    if edge_unavailable_reason(owner):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(owner))

    created = 0
    updated = 0
    skipped = 0
    for route in preview.routes:
        if not route.importable:
            skipped += 1
            continue
        pf = await db.get(HTTPRoute, route.existing_site_id) if route.existing_site_id else None
        if pf is None:
            pf = HTTPRoute(
                id=uuid.uuid4(),
                agent_id=server.agent_id,
                visibility="public_only",
                destination_ip=route.destination_ip or "",
                destination_port=route.destination_port or 80,
                description=f"Imported from Traefik router {route.router_name}",
                active=body.activate,
                domain=route.domain,
            )
            db.add(pf)
            await db.flush()
            created += 1
        else:
            if pf.agent_id != server.agent_id:
                raise HTTPException(status_code=400, detail="Imported route belongs to another node")
            pf.destination_ip = route.destination_ip or pf.destination_ip
            pf.destination_port = route.destination_port or pf.destination_port
            pf.active = body.activate
            pf.domain = route.domain
            if not pf.description:
                pf.description = f"Imported from Traefik router {route.router_name}"
            updated += 1

        ingress = await db.get(HTTPPublicIngress, pf.id)
        if ingress is None:
            ingress = HTTPPublicIngress(route_id=pf.id, attachment_id=body.attachment_id, active=body.activate)
            db.add(ingress)
        else:
            ingress.attachment_id = body.attachment_id
            ingress.active = body.activate
        ec = await db.scalar(
            select(EdgeRouteConfig).where(EdgeRouteConfig.route_id == pf.id)
        )
        if ec is None:
            ec = EdgeRouteConfig(id=uuid.uuid4(), port_forward_id=pf.id)
            db.add(ec)
        policy = route.mapped_policy
        ec.waf_mode = "observe"
        ec.rate_limit_rps = _int_or_none(policy.get("rate_limit_rps"))
        ec.rate_limit_burst = _int_or_none(policy.get("rate_limit_burst"))
        ec.antibot = False
        ec.auth_mode = str(policy.get("auth_mode") or "none")
        ec.auth_config = policy.get("auth_config")
        ec.ip_allow = policy.get("ip_allow") or None
        ec.ip_deny = policy.get("ip_deny") or None
        ec.geo_block = policy.get("geo_block") or None
        ec.tls_source = route.tls_source
        ec.upstream_scheme = route.upstream_scheme
        ec.upstream_insecure_skip_verify = route.upstream_insecure_skip_verify
        ec.imported_router_name = route.router_name
        ec.imported_service_name = route.service_name
        ec.imported_middlewares = route.middlewares
        ec.import_warnings = route.warnings or None
        _sync_legacy_policy(ec, {"waf_mode", "rate_limit_rps", "rate_limit_burst", "antibot", "auth_mode", "auth_config", "ip_allow", "ip_deny", "geo_block", "tls_source"})

    await validate_edge_configuration(server.agent_id, db)
    await db.commit()
    await dispatch_edge_desired_state(server.agent_id, db, actor_user_id=user.id)
    emit_edge_changed()
    emit_security_changed()
    return TraefikImportResult(
        summary=preview.summary,
        routes=preview.routes,
        created=created,
        updated=updated,
        skipped=skipped,
    )


def _int_or_none(value) -> int | None:  # noqa: ANN001
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def _ensure_site_does_not_shadow_raw_edge_forward(
    *,
    db: AsyncSession,
    attachment_id: uuid.UUID,
    active: bool,
    exclude_port_forward_id: uuid.UUID | None = None,
) -> None:
    if not active:
        return
    server_id = await server_id_for_attachment(db, attachment_id)
    if server_id is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    conflict = await find_active_raw_edge_forward_on_server(
        db,
        server_id,
        exclude_port_forward_id=exclude_port_forward_id,
    )
    if conflict is None:
        return
    raise HTTPException(
        status_code=409,
        detail=(
            f"Raw TCP port forward {conflict.public_port} is active on this server. "
            "Disable raw forwards on 80/443 before enabling Security Edge sites."
        ),
    )


@router.get("/sites", response_model=list[SiteRead])
async def list_sites(
    server_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    q = select(HTTPRoute).options(selectinload(HTTPRoute.edge_route_config), selectinload(HTTPRoute.public_ingress)).order_by(HTTPRoute.created_at.desc())
    if server_id is not None:
        server = await db.get(TunnelServer, server_id)
        if server is None:
            return []
        q = q.where(HTTPRoute.agent_id == server.agent_id)
    if agent_id is not None:
        q = q.where(HTTPRoute.agent_id == agent_id)
    rows = (await db.execute(q)).scalars().all()
    out = []
    for route in rows:
        sid, aid = await site_server_context(route, db)
        owner = await get_edge_owner(db, route.agent_id)
        out.append(_site_read(route, server_id=sid, agent_id=aid, server=owner))
    return out


def _sync_legacy_policy(ec: EdgeRouteConfig, fields: set[str]) -> None:
    policy = dict(ec.policy_json or {})
    for field in ("waf_mode", "antibot", "auth_mode", "auth_config", "ip_allow", "ip_deny", "geo_block", "tls_source"):
        if field in fields:
            policy[field] = getattr(ec, field)
    if fields.intersection({"rate_limit_rps", "rate_limit_burst"}):
        rate = dict(policy.get("rate_limit") or {})
        if "rate_limit_rps" in fields:
            rate["requests"] = ec.rate_limit_rps
        if "rate_limit_burst" in fields:
            rate["burst"] = ec.rate_limit_burst
        policy["rate_limit"] = rate
    ec.policy_json = policy


def _legacy_upsert(body: SiteCreate | SiteUpdate) -> EdgeRouteUpsert:
    payload = body.model_dump(exclude_unset=True)
    allowed = {"attachment_id", "tunnel_server_ip_id", "domain", "destination_ip", "destination_port", "description", "upstream_scheme", "upstream_insecure_skip_verify"}
    values = {key: value for key, value in payload.items() if key in allowed}
    if "active" in payload:
        values["enabled"] = payload["active"]
    try:
        return EdgeRouteUpsert.model_validate(values)
    except ValidationError:
        raise HTTPException(status_code=422, detail="Invalid HTTP route configuration") from None


@router.post("/sites", response_model=SiteRead, status_code=201)
async def create_site(
    body: SiteCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    server = await _ensure_security_edge_enabled_for_attachment(body.attachment_id, db)
    if body.antibot and not await _captcha_configured(db):
        raise HTTPException(status_code=400, detail="CAPTCHA provider keys must be configured before enabling anti-bot")
    _validate_rate_limit(body.rate_limit_rps, body.rate_limit_burst)
    await _ensure_site_does_not_shadow_raw_edge_forward(db=db, attachment_id=body.attachment_id, active=True)
    if await db.scalar(select(HTTPRoute.id).where(HTTPRoute.agent_id == server.agent_id, HTTPRoute.domain == body.domain)):
        raise HTTPException(status_code=409, detail="An HTTP route with this domain already exists on this node")
    from app.routers.nodes import _upsert_node_route

    route = await _upsert_node_route(server.agent_id, body.domain, _legacy_upsert(body), db, user, commit=False)
    ec = route.edge_route_config
    config_fields = {"waf_mode", "rate_limit_rps", "rate_limit_burst", "antibot", "auth_mode", "auth_config", "ip_allow", "ip_deny", "geo_block", "tls_source", "upstream_scheme", "upstream_insecure_skip_verify"}
    for field in config_fields:
        setattr(ec, field, getattr(body, field))
    _sync_legacy_policy(ec, config_fields)
    await validate_edge_configuration(route.agent_id, db)
    await db.commit()
    await db.refresh(route)
    await db.refresh(route, ["public_ingress"])
    route.edge_route_config = ec
    await dispatch_edge_desired_state(route.agent_id, db, actor_user_id=user.id)
    emit_edge_changed()
    emit_security_changed()
    owner = await get_edge_owner(db, server.agent_id)
    return _site_read(route, server_id=server.id, agent_id=server.agent_id, server=owner)


@router.patch("/sites/{port_forward_id}", response_model=SiteRead)
async def update_site(
    port_forward_id: uuid.UUID,
    body: SiteUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    route = await db.scalar(select(HTTPRoute).options(selectinload(HTTPRoute.edge_route_config), selectinload(HTTPRoute.public_ingress)).where(HTTPRoute.id == port_forward_id))
    if route is None:
        raise HTTPException(status_code=404, detail="Site not found")
    owner = await _ensure_security_edge_enabled_for_site(route, db)
    if body.antibot is True and not await _captcha_configured(db):
        raise HTTPException(status_code=400, detail="CAPTCHA provider keys must be configured before enabling anti-bot")
    fields = body.model_fields_set
    ec = route.edge_route_config
    _validate_rate_limit(body.rate_limit_rps if "rate_limit_rps" in fields else ec.rate_limit_rps if ec else None, body.rate_limit_burst if "rate_limit_burst" in fields else ec.rate_limit_burst if ec else None)
    active = body.active if body.active is not None else route.active
    if route.public_ingress:
        await _ensure_site_does_not_shadow_raw_edge_forward(db=db, attachment_id=route.public_ingress.attachment_id, active=active, exclude_port_forward_id=route.id)
    if "domain" in fields:
        from app.schemas.system_settings import valid_dns_name
        if body.domain is None or not valid_dns_name(body.domain) or "_" in body.domain:
            raise HTTPException(status_code=422, detail="HTTP route domain must be a valid DNS name")
        duplicate = await db.scalar(select(HTTPRoute.id).where(HTTPRoute.agent_id == route.agent_id, HTTPRoute.domain == body.domain, HTTPRoute.id != route.id))
        if duplicate:
            raise HTTPException(status_code=409, detail="An HTTP route with this domain already exists on this node")
    from app.routers.nodes import _upsert_node_route

    route = await _upsert_node_route(route.agent_id, route.domain, _legacy_upsert(body), db, user, commit=False, route_id=route.id)
    if "domain" in fields:
        route.domain = body.domain
    if "description" in fields:
        route.description = body.description
    ec = route.edge_route_config
    nullable = {"rate_limit_rps", "rate_limit_burst", "auth_config", "ip_allow", "ip_deny", "geo_block"}
    config_fields = nullable | {"waf_mode", "antibot", "auth_mode", "tls_source", "upstream_scheme", "upstream_insecure_skip_verify"}
    for field in fields.intersection(config_fields):
        value = getattr(body, field)
        if field in nullable or value is not None:
            setattr(ec, field, value)
    _sync_legacy_policy(ec, fields.intersection(config_fields))
    await validate_edge_configuration(route.agent_id, db)
    await db.commit()
    await db.refresh(route)
    await db.refresh(route, ["public_ingress"])
    route.edge_route_config = ec
    await dispatch_edge_desired_state(route.agent_id, db, actor_user_id=user.id)
    emit_edge_changed()
    emit_security_changed()
    sid, aid = await site_server_context(route, db)
    return _site_read(route, server_id=sid, agent_id=aid, server=owner)


@router.delete("/sites/{port_forward_id}", status_code=204)
async def delete_site(
    port_forward_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    route = await db.get(HTTPRoute, port_forward_id)
    if route is None:
        raise HTTPException(status_code=404, detail="Site not found")
    await _ensure_security_edge_enabled_for_site(route, db)
    from app.services.edge_migration import ensure_route_not_referenced
    await ensure_route_not_referenced(db, route.id)
    agent_id = route.agent_id
    await db.delete(route)
    await db.commit()
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=user.id)
    emit_edge_changed()
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
    q = select(HTTPRoute).where(
        HTTPRoute.domain.is_not(None),
    )
    if server_id is not None:
        ts = await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))
        if ts is None:
            raise HTTPException(status_code=404, detail="Tunnel server not found")
        q = q.where(HTTPRoute.agent_id == ts.agent_id)

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

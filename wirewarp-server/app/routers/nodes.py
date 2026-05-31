from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.agent import Agent
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.edge_cache_snapshot import EdgeCacheSnapshot
from app.models.edge_component_state import EdgeComponentState
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_profile import EdgeProfile
from app.models.port_forward import PortForward
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.realtime.events import emit_edge_changed, emit_security_changed
from app.schemas.crowdsec import CrowdSecSnapshotRead
from app.schemas.edge import (
    EdgeNodePolicyRead,
    EdgeNodePolicyUpdate,
    EdgeRouteRead,
    EdgeRouteUpsert,
)
from app.schemas.nodes import (
    EdgeComponentRead,
    NodeEdgeActionResult,
    NodeEdgeCapabilitiesRead,
    NodeEdgeCapabilitiesUpdate,
    NodeEdgeRead,
    NodeRead,
)
from app.schemas.security import (
    EdgeRouteConfigRead,
    EffectiveRateLimit,
    EffectiveRateLimitValue,
    ServerEdgePolicyRead,
    SiteEffectivePolicy,
    SiteRead,
    TraefikStatusRead,
)
from app.services.edge_ops import (
    EDGE_COMPONENTS,
    DEFAULT_SECURITY_EDGE_COMPONENTS,
    dispatch_edge_desired_state,
    edge_feature_disabled_detail,
    edge_phase,
    edge_unavailable_reason,
    set_component_desired,
)
from app.services.agent_commands import send_command
from app.services.edge_port_conflicts import server_id_for_attachment
from app.services.edge_resources import (
    apply_policy_to_edge_config,
    get_or_create_node_policy,
    get_profile_by_id_or_slug,
    node_policy_read,
    route_edge_config,
    route_read,
)

router = APIRouter()


def _node_role(agent: Agent, client: TunnelClient | None) -> str:
    if agent.type == "server":
        return "server"
    if client and client.is_gateway:
        return "gateway"
    return "client"


async def _node_read(agent: Agent, db: AsyncSession) -> NodeRead:
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent.id))
    client = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == agent.id))
    cs = await db.scalar(select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent.id))
    tk = await db.scalar(select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent.id))
    edge_components = (
        await _component_state_map(server, db, crowdsec=cs, traefik=tk)
        if server is not None
        else {}
    )
    return NodeRead(
        agent_id=agent.id,
        name=agent.name,
        role=_node_role(agent, client),
        status=agent.status,
        hostname=agent.hostname,
        public_ip=agent.public_ip,
        version=agent.version,
        last_seen=agent.last_seen,
        tunnel_server_id=server.id if server else None,
        tunnel_client_id=client.id if client else None,
        is_gateway=bool(client and client.is_gateway),
        edge_phase=_node_edge_phase(server, cs, tk) if server else None,
        edge_mode=server.edge_mode if server else None,
        edge_state=server.edge_state if server else None,
        edge_install_phase=server.edge_install_phase if server else None,
        edge_components=edge_components,
    )


def _node_edge_phase(
    server: TunnelServer,
    cs: CrowdSecSnapshot | None,
    tk: TraefikSnapshot | None,
) -> str:
    if edge_unavailable_reason(server):
        return "disabled"
    return edge_phase(cs, tk)


def _site_read(
    pf: PortForward,
    *,
    server_id: uuid.UUID | None,
    agent_id: uuid.UUID | None,
) -> SiteRead:
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
        effective_policy=_effective_site_policy(pf, server_id),
        created_at=pf.created_at,
    )


def _server_policy(server: TunnelServer) -> ServerEdgePolicyRead:
    return ServerEdgePolicyRead(
        server_id=server.id,
        agent_id=server.agent_id,
        rate_limit_rps=server.edge_rate_limit_rps,
        rate_limit_burst=server.edge_rate_limit_burst,
    )


async def _component_state_map(
    server: TunnelServer,
    db: AsyncSession,
    *,
    crowdsec: CrowdSecSnapshot | None = None,
    traefik: TraefikSnapshot | None = None,
) -> dict[str, EdgeComponentRead]:
    if crowdsec is None:
        crowdsec = await db.scalar(select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == server.agent_id))
    if traefik is None:
        traefik = await db.scalar(select(TraefikSnapshot).where(TraefikSnapshot.agent_id == server.agent_id))
    cache = await db.scalar(
        select(EdgeCacheSnapshot).where(
            EdgeCacheSnapshot.agent_id == server.agent_id,
            EdgeCacheSnapshot.backend == "nginx_proxy_cache",
        )
    )
    rows = (
        await db.execute(
            select(EdgeComponentState).where(EdgeComponentState.agent_id == server.agent_id)
        )
    ).scalars().all()
    desired_by_component = {row.component: row for row in rows}

    out: dict[str, EdgeComponentRead] = {}
    for component in EDGE_COMPONENTS:
        row = desired_by_component.get(component)
        desired = row.desired if row else _default_component_desired(server, component)
        installed = row.installed if row else False
        running = row.running if row else False
        phase = row.phase if row else ("pending" if desired == "enabled" else "disabled")
        version = row.version if row else None
        last_error = row.last_error if row else None
        updated_at = row.updated_at if row else None

        if component == "traefik" and traefik is not None:
            installed = traefik.installed
            running = traefik.running
            phase = traefik.phase or phase
            version = traefik.version
            last_error = traefik.last_error or traefik.error
            updated_at = traefik.updated_at
        elif component == "crowdsec" and crowdsec is not None:
            installed = crowdsec.installed
            running = crowdsec.running
            phase = crowdsec.phase or phase
            version = crowdsec.version
            last_error = crowdsec.last_error or crowdsec.error
            updated_at = crowdsec.updated_at
        elif component == "appsec" and crowdsec is not None:
            installed = crowdsec.installed and crowdsec.appsec_enabled
            running = crowdsec.running and crowdsec.appsec_enabled and crowdsec.bouncer_registered
            if crowdsec.appsec_enabled and crowdsec.bouncer_registered:
                phase = "healthy"
            elif crowdsec.appsec_enabled:
                phase = "degraded"
            elif desired == "enabled":
                phase = "pending"
            else:
                phase = "disabled"
            last_error = crowdsec.last_error or crowdsec.error
            updated_at = crowdsec.updated_at
        elif component == "nginx_cache" and cache is not None:
            installed = cache.installed
            running = cache.running
            phase = cache.phase or phase
            version = cache.version
            last_error = cache.last_error
            updated_at = cache.updated_at

        if edge_unavailable_reason(server) and component not in desired_by_component:
            desired = "disabled"
            if not installed:
                phase = "disabled"

        out[component] = EdgeComponentRead(
            component=component,
            desired=desired,
            installed=installed,
            running=running,
            phase=phase,
            version=version,
            last_error=last_error,
            updated_at=updated_at,
        )
    return out


def _default_component_desired(server: TunnelServer, component: str) -> str:
    if server.edge_mode == "security_edge" and server.edge_state == "enabled":
        return DEFAULT_SECURITY_EDGE_COMPONENTS.get(component, "disabled")
    return "disabled"


async def _capabilities_read(
    server: TunnelServer,
    db: AsyncSession,
    *,
    crowdsec: CrowdSecSnapshot | None = None,
    traefik: TraefikSnapshot | None = None,
) -> NodeEdgeCapabilitiesRead:
    reason = edge_unavailable_reason(server)
    return NodeEdgeCapabilitiesRead(
        agent_id=server.agent_id,
        mode=server.edge_mode,
        state=server.edge_state,
        install_phase=server.edge_install_phase,
        last_error=server.edge_last_error,
        unavailable_reason=reason,
        components=await _component_state_map(server, db, crowdsec=crowdsec, traefik=traefik),
    )


async def _server_for_agent(agent_id: uuid.UUID, db: AsyncSession) -> TunnelServer:
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    if server is None:
        raise HTTPException(status_code=404, detail="Security edge is only available on server nodes")
    return server


async def _ensure_attachment_on_server(
    attachment_id: uuid.UUID,
    server: TunnelServer,
    db: AsyncSession,
) -> None:
    attached_server_id = await server_id_for_attachment(db, attachment_id)
    if attached_server_id is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    if attached_server_id != server.id:
        raise HTTPException(
            status_code=400,
            detail={"code": "attachment_server_mismatch", "field": "attachment_id"},
        )


async def _upsert_node_route(
    agent_id: uuid.UUID,
    domain: str | None,
    body: EdgeRouteUpsert,
    db: AsyncSession,
    actor: User,
) -> PortForward:
    server = await _server_for_agent(agent_id, db)
    if edge_unavailable_reason(server):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(server))

    att_ids = (
        await db.execute(
            select(TunnelClientAttachment.id).where(
                TunnelClientAttachment.tunnel_server_id == server.id
            )
        )
    ).scalars().all()
    route = None
    if domain is not None and att_ids:
        route = await db.scalar(
            select(PortForward)
            .options(selectinload(PortForward.edge_route_config))
            .where(
                PortForward.attachment_id.in_(att_ids),
                PortForward.service_kind == "http",
                PortForward.domain == domain,
            )
        )

    if route is None:
        if body.attachment_id is None:
            raise HTTPException(status_code=400, detail={"code": "required", "field": "attachment_id"})
        if body.destination_ip is None:
            raise HTTPException(status_code=400, detail={"code": "required", "field": "destination_ip"})
        if body.destination_port is None:
            raise HTTPException(status_code=400, detail={"code": "required", "field": "destination_port"})
        await _ensure_attachment_on_server(body.attachment_id, server, db)
        route = PortForward(
            id=uuid.uuid4(),
            attachment_id=body.attachment_id,
            protocol="tcp",
            public_port=443,
            destination_ip=body.destination_ip,
            destination_port=body.destination_port,
            description=body.description,
            active=True if body.enabled is None else body.enabled,
            service_kind="http",
            domain=domain,
        )
        db.add(route)
        await db.flush()
    else:
        if body.attachment_id is not None:
            await _ensure_attachment_on_server(body.attachment_id, server, db)
            route.attachment_id = body.attachment_id
        if body.enabled is not None:
            route.active = body.enabled
        if body.destination_ip is not None:
            route.destination_ip = body.destination_ip
        if body.destination_port is not None:
            route.destination_port = body.destination_port
        if body.description is not None:
            route.description = body.description

    ec = await route_edge_config(db, route)
    if body.profile_id is not None:
        if await db.get(EdgeProfile, body.profile_id) is None:
            raise HTTPException(status_code=404, detail="Edge profile not found")
        ec.profile_id = body.profile_id
    if body.profile is not None:
        profile = await get_profile_by_id_or_slug(db, body.profile)
        if profile is None:
            raise HTTPException(status_code=404, detail="Edge profile not found")
        ec.profile_id = profile.id
    if body.priority is not None:
        ec.priority = body.priority
    if body.upstream_scheme is not None:
        ec.upstream_scheme = body.upstream_scheme
    if body.upstream_insecure_skip_verify is not None:
        ec.upstream_insecure_skip_verify = body.upstream_insecure_skip_verify
    if body.policy is not None:
        apply_policy_to_edge_config(ec, body.policy)

    await db.commit()
    await db.refresh(route)
    route.edge_route_config = ec  # type: ignore[assignment]
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    emit_security_changed()
    return route


async def _apply_capabilities(
    server: TunnelServer,
    body: NodeEdgeCapabilitiesUpdate,
    db: AsyncSession,
    actor: User,
) -> None:
    now = datetime.now(timezone.utc)
    fields = body.model_fields_set
    if "mode" in fields and body.mode is not None:
        if body.mode not in {"tcp_udp_only", "security_edge"}:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_edge_mode", "field": "mode", "detail": "Mode must be tcp_udp_only or security_edge."},
            )
        server.edge_mode = body.mode
        if body.mode == "tcp_udp_only":
            server.edge_state = "disabled"
            server.edge_install_phase = "disabled"
    if "state" in fields and body.state is not None:
        if body.state not in {"enabled", "disabled"}:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_edge_state", "field": "state", "detail": "State must be enabled or disabled."},
            )
        if body.state == "enabled":
            server.edge_mode = "security_edge"
            if server.edge_state != "enabled":
                server.edge_enabled_at = now
                server.edge_enabled_by = actor.id
            server.edge_state = "enabled"
            if server.edge_install_phase == "disabled":
                server.edge_install_phase = "pending"
        else:
            if server.edge_state != "disabled":
                server.edge_disabled_at = now
                server.edge_disabled_by = actor.id
            server.edge_state = "disabled"
            server.edge_install_phase = "disabled"
    if body.components:
        await set_component_desired(server.agent_id, db, body.components)


def _effective_site_policy(
    pf: PortForward,
    server_id: uuid.UUID | None,
) -> SiteEffectivePolicy:
    ec = pf.edge_route_config
    safe_name = (pf.domain or str(pf.id)).replace(".", "-").replace(":", "-")
    middleware_chain: list[str] = []
    global_limit = None
    # `_site_read` is only called from `_server_sites`, so server_id is set
    # there. The actual rate-limit values are injected after the server rows
    # are loaded below to avoid another query per row.
    if getattr(pf, "_wirewarp_server_rate_limit_rps", None):
        rps = getattr(pf, "_wirewarp_server_rate_limit_rps")
        burst = getattr(pf, "_wirewarp_server_rate_limit_burst") or rps * 5
        global_limit = EffectiveRateLimitValue(rps=rps, burst=burst)
        middleware_chain.append("server-ratelimit")
    site_limit = None
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


async def _server_sites(server: TunnelServer, db: AsyncSession) -> list[SiteRead]:
    att_ids = (
        await db.execute(
            select(TunnelClientAttachment.id).where(
                TunnelClientAttachment.tunnel_server_id == server.id
            )
        )
    ).scalars().all()
    if not att_ids:
        return []
    rows = (
        await db.execute(
            select(PortForward)
            .options(selectinload(PortForward.edge_route_config))
            .where(
                PortForward.attachment_id.in_(att_ids),
                PortForward.service_kind == "http",
            )
            .order_by(PortForward.created_at.desc())
        )
    ).scalars().all()
    out: list[SiteRead] = []
    for pf in rows:
        pf._wirewarp_server_rate_limit_rps = server.edge_rate_limit_rps  # type: ignore[attr-defined]
        pf._wirewarp_server_rate_limit_burst = server.edge_rate_limit_burst  # type: ignore[attr-defined]
        out.append(_site_read(pf, server_id=server.id, agent_id=server.agent_id))
    return out


@router.get("", response_model=list[NodeRead])
async def list_nodes(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    rows = (await db.execute(select(Agent).order_by(Agent.created_at.desc()))).scalars().all()
    return [await _node_read(agent, db) for agent in rows]


@router.get("/{agent_id}", response_model=NodeRead)
async def get_node(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return await _node_read(agent, db)


@router.get("/{agent_id}/edge", response_model=NodeEdgeRead)
async def get_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    server = await _server_for_agent(agent_id, db)
    cs = await db.scalar(select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent_id))
    tk = await db.scalar(select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent_id))
    return NodeEdgeRead(
        agent_id=agent_id,
        mode=server.edge_mode,
        state=server.edge_state,
        phase=_node_edge_phase(server, cs, tk),
        install_phase=server.edge_install_phase,
        last_error=server.edge_last_error,
        unavailable_reason=edge_unavailable_reason(server),
        components=await _component_state_map(server, db, crowdsec=cs, traefik=tk),
        policy=_server_policy(server),
        crowdsec=(
            CrowdSecSnapshotRead.model_validate(cs)
            if cs
            else CrowdSecSnapshotRead(installed=False, running=False, phase="pending")
        ),
        traefik=(
            TraefikStatusRead.model_validate(tk)
            if tk
            else TraefikStatusRead(installed=False, running=False, phase="pending")
        ),
        sites=await _server_sites(server, db),
    )


@router.get("/{agent_id}/edge/capabilities", response_model=NodeEdgeCapabilitiesRead)
async def get_node_edge_capabilities(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    server = await _server_for_agent(agent_id, db)
    return await _capabilities_read(server, db)


@router.put("/{agent_id}/edge/capabilities", response_model=NodeEdgeCapabilitiesRead)
async def put_node_edge_capabilities(
    agent_id: uuid.UUID,
    body: NodeEdgeCapabilitiesUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    await _apply_capabilities(server, body, db, actor)
    await db.commit()
    await db.refresh(server)
    emit_edge_changed()
    return await _capabilities_read(server, db)


@router.get("/{agent_id}/edge/policy", response_model=EdgeNodePolicyRead)
async def get_node_edge_policy(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    server = await _server_for_agent(agent_id, db)
    policy = await get_or_create_node_policy(db, server.agent_id)
    await db.commit()
    return await node_policy_read(db, policy)


@router.patch("/{agent_id}/edge/policy", response_model=EdgeNodePolicyRead)
async def patch_node_edge_policy(
    agent_id: uuid.UUID,
    body: EdgeNodePolicyUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    if edge_unavailable_reason(server):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(server))
    policy = await get_or_create_node_policy(db, server.agent_id)
    fields = body.model_fields_set
    if "default_profile_id" in fields:
        if body.default_profile_id is not None and await db.get(EdgeProfile, body.default_profile_id) is None:
            raise HTTPException(status_code=404, detail="Edge profile not found")
        policy.default_profile_id = body.default_profile_id
    for field in (
        "client_ip_strategy",
        "trusted_proxy_cidrs",
        "cloudflare_mode",
        "access_log_retention_hours",
        "security_event_retention_days",
    ):
        if field in fields:
            setattr(policy, field, getattr(body, field))
    if "policy" in fields and body.policy is not None:
        policy.policy_json = body.policy
    await db.commit()
    await db.refresh(policy)
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return await node_policy_read(db, policy)


@router.get("/{agent_id}/edge/effective", response_model=EdgeNodePolicyRead)
async def get_node_edge_effective(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    server = await _server_for_agent(agent_id, db)
    policy = await get_or_create_node_policy(db, server.agent_id)
    await db.commit()
    return await node_policy_read(db, policy)


@router.get("/{agent_id}/edge/routes", response_model=list[EdgeRouteRead])
async def list_node_edge_routes(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    server = await _server_for_agent(agent_id, db)
    att_ids = (
        await db.execute(
            select(TunnelClientAttachment.id).where(
                TunnelClientAttachment.tunnel_server_id == server.id
            )
        )
    ).scalars().all()
    if not att_ids:
        return []
    rows = (
        await db.execute(
            select(PortForward)
            .options(selectinload(PortForward.edge_route_config))
            .where(
                PortForward.attachment_id.in_(att_ids),
                PortForward.service_kind == "http",
            )
            .order_by(PortForward.domain)
        )
    ).scalars().all()
    return [await route_read(db, row, row.edge_route_config) for row in rows]


@router.post("/{agent_id}/edge/routes", response_model=EdgeRouteRead, status_code=201)
async def create_node_edge_route(
    agent_id: uuid.UUID,
    body: EdgeRouteUpsert,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    if not body.attachment_id:
        raise HTTPException(status_code=400, detail={"code": "required", "field": "attachment_id"})
    route = await _upsert_node_route(agent_id, None, body, db, actor)
    return await route_read(db, route, route.edge_route_config)


@router.put("/{agent_id}/edge/routes/by-domain/{domain}", response_model=EdgeRouteRead)
async def upsert_node_edge_route_by_domain(
    agent_id: uuid.UUID,
    domain: str,
    body: EdgeRouteUpsert,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    route = await _upsert_node_route(agent_id, domain, body, db, actor)
    return await route_read(db, route, route.edge_route_config)


@router.post("/{agent_id}/edge/install", response_model=NodeEdgeActionResult, status_code=202)
async def install_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    await _apply_capabilities(
        server,
        NodeEdgeCapabilitiesUpdate(
            mode="security_edge",
            state="enabled",
            components=DEFAULT_SECURITY_EDGE_COMPONENTS,
        ),
        db,
        actor,
    )
    server.edge_install_phase = "pending"
    await db.commit()
    await db.refresh(server)
    sent, command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return NodeEdgeActionResult(sent=sent, command_id=command_id if sent else None, edge=await _capabilities_read(server, db))


@router.post("/{agent_id}/edge/enable", response_model=NodeEdgeActionResult, status_code=202)
async def enable_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    components = {}
    current = await _component_state_map(server, db)
    if not any(component.desired == "enabled" for component in current.values()):
        components = DEFAULT_SECURITY_EDGE_COMPONENTS
    await _apply_capabilities(
        server,
        NodeEdgeCapabilitiesUpdate(mode="security_edge", state="enabled", components=components or None),
        db,
        actor,
    )
    await db.commit()
    await db.refresh(server)
    sent, command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return NodeEdgeActionResult(sent=sent, command_id=command_id if sent else None, edge=await _capabilities_read(server, db))


@router.post("/{agent_id}/edge/disable", response_model=NodeEdgeActionResult, status_code=202)
async def disable_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    await _apply_capabilities(
        server,
        NodeEdgeCapabilitiesUpdate(mode="security_edge", state="disabled"),
        db,
        actor,
    )
    await db.commit()
    await db.refresh(server)
    sent, command_id = await send_command(
        agent_id=str(agent_id),
        command_type="edge_disable",
        params={
            "preserve_state": True,
            "services": ["traefik", "crowdsec", "nginx"],
        },
        db=db,
        actor_user_id=actor.id,
    )
    emit_edge_changed()
    return NodeEdgeActionResult(sent=sent, command_id=command_id if sent else None, edge=await _capabilities_read(server, db))


@router.post("/{agent_id}/edge/reconcile", status_code=202)
async def reconcile_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    agent = await db.get(Agent, agent_id)
    if agent is None or agent.type != "server":
        raise HTTPException(status_code=404, detail="Server node not found")
    server = await _server_for_agent(agent_id, db)
    if edge_unavailable_reason(server):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(server))
    sent, command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    if not sent:
        raise HTTPException(status_code=503, detail="Agent is not currently connected")
    return {"command_id": command_id, "sent": True}

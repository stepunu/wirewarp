from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.agent import Agent
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.port_forward import PortForward
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.realtime.events import emit_edge_changed
from app.schemas.crowdsec import CrowdSecSnapshotRead
from app.schemas.nodes import NodeEdgeRead, NodeRead
from app.schemas.security import (
    EdgeRouteConfigRead,
    EffectiveRateLimit,
    EffectiveRateLimitValue,
    ServerEdgePolicyRead,
    SiteEffectivePolicy,
    SiteRead,
    TraefikStatusRead,
)
from app.services.edge_ops import dispatch_edge_desired_state, edge_phase

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
        edge_phase=edge_phase(cs, tk) if server else None,
    )


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
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    if server is None:
        raise HTTPException(status_code=404, detail="Security edge is only available on server nodes")
    cs = await db.scalar(select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent_id))
    tk = await db.scalar(select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent_id))
    return NodeEdgeRead(
        agent_id=agent_id,
        phase=edge_phase(cs, tk),
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


@router.post("/{agent_id}/edge/reconcile", status_code=202)
async def reconcile_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    agent = await db.get(Agent, agent_id)
    if agent is None or agent.type != "server":
        raise HTTPException(status_code=404, detail="Server node not found")
    sent, command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    if not sent:
        raise HTTPException(status_code=503, detail="Agent is not currently connected")
    return {"command_id": command_id, "sent": True}

from __future__ import annotations

import ipaddress
import uuid

from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timezone
from sqlalchemy import select, func
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
from app.models.edge_node import EdgeNode
from app.models.http_route import HTTPRoute
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.user import User
from app.realtime.events import emit_agent_changed, emit_edge_changed, emit_security_changed
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
    NodeRename,
)
from app.schemas.security import (
    EdgeRouteConfigRead,
    EffectiveRateLimit,
    EffectiveRateLimitValue,
    ServerEdgePolicyRead,
    ServerEdgePolicyUpdate,
    SiteEffectivePolicy,
    SiteRead,
    TraefikStatusRead,
)
from app.schemas.system_settings import valid_dns_name
from app.services.edge_ops import (
    EDGE_COMPONENTS,
    DEFAULT_SECURITY_EDGE_COMPONENTS,
    dispatch_edge_desired_state,
    replay_edge_lifecycle,
    ensure_edge_enabled,
    edge_feature_disabled_detail,
    edge_phase,
    component_phase,
    edge_unavailable_reason,
    set_component_desired,
)
from app.services.agent_commands import send_command
from app.services.edge_ownership import get_edge_owner, is_gateway_edge, load_http_routes
from app.services.edge_relay_ops import public_ingress_available
from app.services.edge_ops import edge_runtime_mode
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
    owner = await get_edge_owner(db, agent.id) if server or (client and client.is_gateway) else None
    edge_components = (
        await _component_state_map(owner, db, crowdsec=cs, traefik=tk)
        if owner is not None
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
        edge_phase=_node_edge_phase(owner, cs, tk) if owner else None,
        edge_mode=owner.edge_mode if owner else None,
        edge_state=owner.edge_state if owner else None,
        edge_install_phase=owner.edge_install_phase if owner else None,
        edge_components=edge_components,
        lan_bind_ip=owner.lan_bind_ip if owner else None,
        public_bind_ip=owner.public_bind_ip if owner else None,
        relay_enabled=owner.relay_enabled if owner else False,
        runtime_mode=edge_runtime_mode(owner) if owner else "disabled",
    )


def _node_edge_phase(
    server: EdgeNode,
    cs: CrowdSecSnapshot | None,
    tk: TraefikSnapshot | None,
) -> str:
    if edge_unavailable_reason(server):
        if server.relay_enabled:
            return tk.phase if tk and tk.phase else component_phase(bool(tk and tk.installed), bool(tk and tk.running), tk.error if tk else None)
        return "disabled"
    return edge_phase(cs, tk)


def _site_read(
    pf: HTTPRoute,
    *,
    server_id: uuid.UUID | None,
    agent_id: uuid.UUID | None,
    owner: EdgeNode,
) -> SiteRead:
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
        effective_policy=_effective_site_policy(pf, owner),
        created_at=pf.created_at,
    )


def _server_policy(server: EdgeNode, server_id: uuid.UUID | None) -> ServerEdgePolicyRead:
    return ServerEdgePolicyRead(
        server_id=server_id,
        agent_id=server.agent_id,
        rate_limit_rps=server.edge_rate_limit_rps,
        rate_limit_burst=server.edge_rate_limit_burst,
    )


async def _component_state_map(
    server: EdgeNode,
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
        if server.relay_enabled and edge_unavailable_reason(server):
            desired = "enabled" if component == "traefik" else "disabled"
            if component == "traefik" and not running and phase == "disabled":
                phase = "pending"

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


def _default_component_desired(server: EdgeNode, component: str) -> str:
    if server.edge_mode == "security_edge" and server.edge_state == "enabled":
        return DEFAULT_SECURITY_EDGE_COMPONENTS.get(component, "disabled")
    return "disabled"


async def _capabilities_read(
    server: EdgeNode,
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
        lan_bind_ip=server.lan_bind_ip,
        public_bind_ip=server.public_bind_ip,
        public_ingress_available=await public_ingress_available(db, server.agent_id),
        relay_enabled=server.relay_enabled,
        runtime_mode=edge_runtime_mode(server),
        components=await _component_state_map(server, db, crowdsec=crowdsec, traefik=traefik),
    )


async def _server_for_agent(agent_id: uuid.UUID, db: AsyncSession) -> EdgeNode:
    return await get_edge_owner(db, agent_id)


async def _ensure_attachment_on_server(
    attachment_id: uuid.UUID,
    server: EdgeNode,
    db: AsyncSession,
) -> TunnelClientAttachment:
    attachment = await db.get(TunnelClientAttachment, attachment_id)
    if attachment is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    owner_server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == server.agent_id))
    owner_client = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == server.agent_id))
    matches = attachment.tunnel_server_id == owner_server.id if owner_server else bool(owner_client and attachment.tunnel_client_id == owner_client.id)
    if not matches:
        raise HTTPException(
            status_code=400,
            detail={"code": "attachment_server_mismatch", "field": "attachment_id"},
        )
    return attachment


async def _upsert_node_route(
    agent_id: uuid.UUID,
    domain: str | None,
    body: EdgeRouteUpsert,
    db: AsyncSession,
    actor: User | None,
    *,
    commit: bool = True,
    route_id: uuid.UUID | None = None,
    validate_config: bool = True,
    new_route_id: uuid.UUID | None = None,
) -> HTTPRoute:
    server = await _server_for_agent(agent_id, db)
    if edge_unavailable_reason(server):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(server))

    gateway = await is_gateway_edge(db, agent_id)
    if body.policy is not None:
        from app.services.edge_render import validate_render_policy
        try:
            validate_render_policy(body.policy)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    requested_domain = domain if domain is not None else body.domain
    if requested_domain is not None:
        requested_domain = requested_domain.lower().rstrip(".")
    if requested_domain is not None and not valid_dns_name(requested_domain):
        raise HTTPException(status_code=422, detail={"code": "invalid_domain", "field": "domain"})
    if body.public_port is not None and body.public_port != 443:
        raise HTTPException(status_code=422, detail="Managed HTTP routes use HTTPS port 443")
    route = None
    if requested_domain is not None or route_id is not None:
        route = await db.scalar(
            select(HTTPRoute)
            .options(selectinload(HTTPRoute.edge_route_config), selectinload(HTTPRoute.public_ingress))
            .where(
                HTTPRoute.agent_id == agent_id,
                HTTPRoute.id == route_id if route_id is not None else func.lower(HTTPRoute.domain) == requested_domain,
            )
        )
    if route_id is not None and route is None:
        raise HTTPException(status_code=404, detail="Route not found on this node")
    if route is not None and domain is None and route_id is None:
        raise HTTPException(status_code=409, detail="A route with this domain already exists on this node")
    visibility = body.visibility or (route.visibility if route else "lan_only" if gateway else "public_only")
    if not gateway and visibility != "public_only":
        raise HTTPException(status_code=409, detail={"code": "vps_lan_listener_unavailable", "detail": "VPS routes support public visibility only."})
    if gateway and visibility == "lan_only" and (body.attachment_id is not None or body.tunnel_server_ip_id is not None or body.public_port is not None):
        raise HTTPException(status_code=400, detail={"code": "lan_route_has_public_ingress", "detail": "LAN-only routes do not use an attachment or public port."})

    ingress = route.public_ingress if route else None
    attachment_id = body.attachment_id or (ingress.attachment_id if ingress else None)
    attachment = None
    if not gateway:
        if attachment_id is None:
            raise HTTPException(status_code=400, detail={"code": "required", "field": "attachment_id"})
        attachment = await _ensure_attachment_on_server(attachment_id, server, db)
        from app.services.edge_relay_ops import load_relay_routes
        if any(relay.domain.lower().rstrip(".") == requested_domain and relay.id != route_id for relay, _ in await load_relay_routes(db, agent_id)):
            raise HTTPException(status_code=409, detail="This hostname is already published through a gateway relay")
    elif visibility != "lan_only":
        if not await public_ingress_available(db, agent_id):
            raise HTTPException(status_code=409, detail={"code": "gateway_public_ingress_unavailable", "detail": "Complete a relay attachment before publishing this gateway route."})
        from app.services.edge_relay_ops import validate_gateway_publication
        attachment = await validate_gateway_publication(db, agent_id, attachment_id, requested_domain or route.domain, route.id if route else None)
    if body.tunnel_server_ip_id is not None:
        public_ip = await db.get(TunnelServerIP, body.tunnel_server_ip_id)
        if public_ip is None:
            raise HTTPException(status_code=404, detail="Public IP not found")
        if attachment is None or public_ip.tunnel_server_id != attachment.tunnel_server_id:
            raise HTTPException(status_code=400, detail={"code": "public_ip_server_mismatch", "field": "tunnel_server_ip_id"})
    if body.destination_ip is not None:
        try:
            target = ipaddress.ip_address(body.destination_ip)
        except ValueError:
            raise HTTPException(status_code=422, detail="Destination must be an IP address") from None
        if target.is_unspecified or target.is_multicast:
            raise HTTPException(status_code=422, detail="Destination requires a unicast IP address")

    if route is None:
        if not requested_domain or len(requested_domain) > 253 or any(ch.isspace() for ch in requested_domain):
            raise HTTPException(status_code=400, detail={"code": "required_or_invalid", "field": "domain"})
        if body.destination_ip is None:
            raise HTTPException(status_code=400, detail={"code": "required", "field": "destination_ip"})
        if body.destination_port is None:
            raise HTTPException(status_code=400, detail={"code": "required", "field": "destination_port"})
        route = HTTPRoute(
            id=new_route_id or uuid.uuid4(),
            agent_id=agent_id,
            destination_ip=body.destination_ip,
            destination_port=body.destination_port,
            description=body.description,
            active=True if body.enabled is None else body.enabled,
            domain=requested_domain,
            visibility=visibility,
        )
        db.add(route)
        await db.flush()
        route.public_ingress = None
        if visibility != "lan_only":
            ingress = HTTPPublicIngress(route_id=route.id, attachment_id=attachment_id, tunnel_server_ip_id=body.tunnel_server_ip_id, public_port=body.public_port or 443, active=route.active)
            db.add(ingress)
            route.public_ingress = ingress
    else:
        route.visibility = visibility
        if body.enabled is not None:
            route.active = body.enabled
        if body.destination_ip is not None:
            route.destination_ip = body.destination_ip
        if body.destination_port is not None:
            route.destination_port = body.destination_port
        if body.description is not None:
            route.description = body.description
        if ingress and visibility == "lan_only":
            await db.delete(ingress)
            route.public_ingress = None
        elif ingress:
            ingress.attachment_id = attachment_id
            if "tunnel_server_ip_id" in body.model_fields_set:
                ingress.tunnel_server_ip_id = body.tunnel_server_ip_id
            if body.public_port is not None:
                ingress.public_port = body.public_port
            ingress.active = route.active
        elif visibility != "lan_only":
            ingress = HTTPPublicIngress(route_id=route.id, attachment_id=attachment_id, tunnel_server_ip_id=body.tunnel_server_ip_id, public_port=443, active=route.active)
            db.add(ingress)
            route.public_ingress = ingress

    if gateway and attachment is not None:
        server.public_bind_ip = attachment.tunnel_ip

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

    route.edge_route_config = ec  # type: ignore[assignment]
    from app.services.edge_render import validate_edge_configuration
    await db.flush()
    if validate_config:
        await validate_edge_configuration(agent_id, db)
    if commit:
        await db.commit()
        await db.refresh(route)
        route.edge_route_config = ec
        await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id if actor else None)
        emit_edge_changed()
        emit_security_changed()
    else:
        await db.flush()
    return route


async def _apply_capabilities(
    server: EdgeNode,
    body: NodeEdgeCapabilitiesUpdate,
    db: AsyncSession,
    actor: User,
) -> None:
    now = datetime.now(timezone.utc)
    fields = body.model_fields_set
    for field in ("lan_bind_ip", "public_bind_ip"):
        if field in fields:
            value = getattr(body, field)
            if value is not None:
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    raise HTTPException(status_code=422, detail={"code": "invalid_listener_ip", "field": field}) from None
                if address.is_unspecified or address.is_multicast or address.is_loopback:
                    raise HTTPException(status_code=422, detail={"code": "explicit_listener_ip_required", "field": field})
                value = str(address)
            setattr(server, field, value)
    if server.lan_bind_ip and server.lan_bind_ip == server.public_bind_ip:
        raise HTTPException(status_code=422, detail="LAN and public relay listener IPs must differ")
    gateway = await is_gateway_edge(db, server.agent_id)
    will_enable = body.state == "enabled" or (server.edge_state == "enabled" and body.state != "disabled" and body.mode != "tcp_udp_only")
    if gateway and will_enable and not server.lan_bind_ip:
        client = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == server.agent_id))
        if "lan_bind_ip" not in fields and client and client.lan_ip:
            try:
                address = ipaddress.ip_address(client.lan_ip)
            except ValueError:
                address = None
            if address and not (address.is_unspecified or address.is_multicast or address.is_loopback):
                server.lan_bind_ip = str(address)
        if not server.lan_bind_ip:
            raise HTTPException(status_code=409, detail="Configure a LAN listener IP before enabling gateway Security Edge")
    if gateway and server.lan_bind_ip:
        client = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == server.agent_id))
        if server.lan_bind_ip != client.lan_ip:
            raise HTTPException(status_code=422, detail="The LAN listener must use the gateway's configured LAN IP")
    if gateway:
        for value in (server.lan_bind_ip, server.public_bind_ip):
            if value and ipaddress.ip_address(value).version != 4:
                raise HTTPException(status_code=422, detail="Gateway Edge listeners currently require IPv4 addresses")
        if will_enable:
            from app.services.edge_relay_ops import validate_gateway_publication
            for route in await load_http_routes(db, server.agent_id, active_only=True):
                if route.visibility != "lan_only" and route.public_ingress:
                    await validate_gateway_publication(db, server.agent_id, route.public_ingress.attachment_id, route.domain, route.id)
    if server.lan_bind_ip and server.lan_bind_ip == server.public_bind_ip:
        raise HTTPException(status_code=422, detail="LAN and public relay listener IPs must differ")
    if "mode" in fields and body.mode is not None:
        if body.mode not in {"tcp_udp_only", "security_edge"}:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_edge_mode", "field": "mode", "detail": "Mode must be tcp_udp_only or security_edge."},
            )
        server.edge_mode = body.mode
        if body.mode == "tcp_udp_only":
            if server.edge_state != "disabled":
                server.edge_disabled_at = now
                server.edge_disabled_by = actor.id
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
    pf: HTTPRoute,
    owner: EdgeNode,
) -> SiteEffectivePolicy:
    ec = pf.edge_route_config
    safe_name = (pf.domain or str(pf.id)).replace(".", "-").replace(":", "-")
    middleware_chain: list[str] = []
    global_limit = None
    if owner.edge_rate_limit_rps:
        rps = owner.edge_rate_limit_rps
        burst = owner.edge_rate_limit_burst or rps * 5
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


async def _server_sites(server: EdgeNode, db: AsyncSession) -> list[SiteRead]:
    rows = await load_http_routes(db, server.agent_id)
    tunnel_server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == server.agent_id))
    out: list[SiteRead] = []
    for pf in rows:
        out.append(_site_read(pf, server_id=tunnel_server.id if tunnel_server else None, agent_id=server.agent_id, owner=server))
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


@router.patch("/{agent_id}", response_model=NodeRead)
async def rename_node(
    agent_id: uuid.UUID,
    body: NodeRename,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Node not found")
    agent.name = body.name
    await db.commit()
    emit_agent_changed()
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
    tunnel_server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    return NodeEdgeRead(
        agent_id=agent_id,
        mode=server.edge_mode,
        state=server.edge_state,
        phase=_node_edge_phase(server, cs, tk),
        install_phase=server.edge_install_phase,
        last_error=server.edge_last_error,
        unavailable_reason=edge_unavailable_reason(server),
        components=await _component_state_map(server, db, crowdsec=cs, traefik=tk),
        lan_bind_ip=server.lan_bind_ip,
        public_bind_ip=server.public_bind_ip,
        public_ingress_available=await public_ingress_available(db, agent_id),
        relay_enabled=server.relay_enabled,
        runtime_mode=edge_runtime_mode(server),
        policy=_server_policy(server, tunnel_server.id if tunnel_server else None),
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


@router.patch("/{agent_id}/edge/global-policy", response_model=ServerEdgePolicyRead)
async def update_node_global_policy(
    agent_id: uuid.UUID,
    body: ServerEdgePolicyUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    owner = await get_edge_owner(db, agent_id)
    ensure_edge_enabled(owner)
    for field, value in body.model_dump(exclude_unset=True).items():
        if value is not None and value < 1:
            raise HTTPException(status_code=400, detail="Rate limits must be at least 1")
        setattr(owner, "edge_" + field, value)
    await db.commit()
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    emit_security_changed()
    tunnel_server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    return _server_policy(owner, tunnel_server.id if tunnel_server else None)


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
    await replay_edge_lifecycle(agent_id, db, actor_user_id=actor.id)
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
    from app.services.edge_render import validate_edge_configuration
    await validate_edge_configuration(agent_id, db)
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
    rows = await load_http_routes(db, server.agent_id)
    return [await route_read(db, row, row.edge_route_config) for row in rows]


@router.post("/{agent_id}/edge/routes", response_model=EdgeRouteRead, status_code=201)
async def create_node_edge_route(
    agent_id: uuid.UUID,
    body: EdgeRouteUpsert,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
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


@router.patch("/{agent_id}/edge/routes/{route_id}", response_model=EdgeRouteRead)
async def patch_node_edge_route(
    agent_id: uuid.UUID,
    route_id: uuid.UUID,
    body: EdgeRouteUpsert,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    await _server_for_agent(agent_id, db)
    route = await db.get(HTTPRoute, route_id)
    if route is None or route.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Route not found on this node")
    if body.domain is not None and body.domain != route.domain:
        raise HTTPException(status_code=400, detail="Use the existing route domain when updating a route")
    updated = await _upsert_node_route(agent_id, route.domain, body, db, actor, route_id=route.id)
    return await route_read(db, updated, updated.edge_route_config)


@router.delete("/{agent_id}/edge/routes/{route_id}", status_code=204)
async def delete_node_edge_route(
    agent_id: uuid.UUID,
    route_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    owner = await _server_for_agent(agent_id, db)
    if edge_unavailable_reason(owner):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(owner))
    route = await db.get(HTTPRoute, route_id)
    if route is None or route.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Route not found on this node")
    from app.services.edge_migration import ensure_route_not_referenced
    await ensure_route_not_referenced(db, route.id)
    await db.delete(route)
    await db.commit()
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    emit_security_changed()


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
    sent, command_id = await replay_edge_lifecycle(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return NodeEdgeActionResult(sent=sent, command_id=command_id if sent else None, edge=await _capabilities_read(server, db))


@router.post("/{agent_id}/edge/reconcile", status_code=202)
async def reconcile_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    if edge_unavailable_reason(server):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(server))
    sent, command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    if not sent:
        raise HTTPException(status_code=503, detail="Agent is not currently connected")
    return {"command_id": command_id, "sent": True}

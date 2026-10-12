from __future__ import annotations

import uuid
from dataclasses import replace

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.edge_component_state import EdgeComponentState
from app.models.edge_route_config import EdgeRouteConfig
from app.models.http_route import HTTPRoute
from app.models.edge_node import EdgeNode
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.system_settings import SystemSettings
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.services.crowdsec_ops import build_whitelist
from app.services.edge_cache_ops import build_nginx_cache_config
from app.services.traefik_ops import (
    build_traefik_dynamic_config,
    build_traefik_static_config,
    load_letsencrypt_config,
)
from app.services.secrets import get_letsencrypt_cloudflare_api_token, get_letsencrypt_rfc2136_tsig_secret
from app.services.edge_ownership import get_edge_owner, edge_entrypoints, is_gateway_edge
from app.services.edge_relay_ops import gateway_ingress, load_relay_routes, relay_dynamic_config


SECRET_KEYS = {"captchaSecretKey", "cloudflare_dns_api_token", "rfc2136_tsig_secret"}
EDGE_COMPONENTS = ("traefik", "crowdsec", "appsec", "access_log", "nginx_cache")
DEFAULT_SECURITY_EDGE_COMPONENTS = {
    "traefik": "enabled",
    "crowdsec": "enabled",
    "appsec": "enabled",
    "access_log": "enabled",
    "nginx_cache": "disabled",
}


def edge_runtime_mode(node: EdgeNode) -> str:
    if not edge_unavailable_reason(node):
        return "security_edge"
    return "relay_only" if node.relay_enabled else "disabled"


def edge_unavailable_reason(server: TunnelServer) -> str | None:
    if server.edge_mode != "security_edge":
        return "security_edge_not_enabled"
    if server.edge_state != "enabled":
        return "security_edge_disabled"
    return None


def edge_feature_disabled_detail(server: TunnelServer) -> dict:
    reason = edge_unavailable_reason(server) or "edge_feature_disabled"
    return {
        "code": "edge_feature_disabled",
        "reason": reason,
        "mode": server.edge_mode,
        "state": server.edge_state,
        "detail": "Security Edge must be enabled for this node before using this endpoint.",
    }


def ensure_edge_enabled(server: TunnelServer) -> None:
    if edge_unavailable_reason(server):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(server))


def default_component_desired(server: TunnelServer, component: str) -> str:
    if server.edge_mode == "security_edge" and server.edge_state == "enabled":
        return DEFAULT_SECURITY_EDGE_COMPONENTS.get(component, "disabled")
    return "disabled"


def component_phase(installed: bool, running: bool, last_error: str | None = None) -> str:
    if running:
        return "healthy"
    if installed or last_error:
        return "degraded"
    return "pending"


def edge_phase(cs: CrowdSecSnapshot | None, tk: TraefikSnapshot | None) -> str:
    phases = {
        getattr(cs, "phase", None) or component_phase(False, False),
        getattr(tk, "phase", None) or component_phase(False, False),
    }
    if "degraded" in phases:
        return "degraded"
    if phases == {"healthy"}:
        return "healthy"
    return "pending"


async def load_component_states(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> dict[str, EdgeComponentState]:
    rows = (
        await db.execute(
            select(EdgeComponentState).where(EdgeComponentState.agent_id == agent_id)
        )
    ).scalars().all()
    return {row.component: row for row in rows}


async def set_component_desired(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
    components: dict[str, str],
) -> dict[str, EdgeComponentState]:
    existing = await load_component_states(agent_id, db)
    out: dict[str, EdgeComponentState] = {}
    agent_uuid = uuid.UUID(str(agent_id))
    for component, desired in components.items():
        if component not in EDGE_COMPONENTS:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_edge_component", "field": component, "detail": "Unknown edge component."},
            )
        if desired not in {"enabled", "disabled"}:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_edge_component_state", "field": component, "detail": "Component state must be enabled or disabled."},
            )
        row = existing.get(component)
        if row is None:
            row = EdgeComponentState(
                id=uuid.uuid4(),
                agent_id=agent_uuid,
                component=component,
            )
            db.add(row)
        row.desired = desired
        if desired == "disabled":
            row.phase = "pending" if row.running else "disabled"
        elif row.phase == "disabled":
            row.phase = "pending"
        out[component] = row
    return out


async def build_edge_desired_state(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> dict:
    server = await get_edge_owner(db, agent_id)
    relay_only = bool(server.relay_enabled and edge_unavailable_reason(server))
    if not relay_only:
        ensure_edge_enabled(server)
    if relay_only:
        static_config = build_traefik_static_config()
        static_config.pop("certificatesResolvers", None)
        static_config.pop("experimental", None)
        static_config["entryPoints"] = await edge_entrypoints(db, agent_id)
        return {
            "runtime_mode": "relay_only", "public_ingress": [], "whitelist": {"ips": [], "cidrs": []},
            "traefik_static_config": static_config,
            "traefik_dynamic_config": await relay_dynamic_config(db, agent_id),
            "nginx_cache_config": {}, "traefik_acme": {},
        }
    letsencrypt = await load_letsencrypt_config(db)
    gateway = await is_gateway_edge(db, agent_id)
    if gateway and letsencrypt.complete and letsencrypt.challenge != "dns-01":
        from app.services.edge_ownership import load_http_routes
        routes = await load_http_routes(db, agent_id, active_only=True)
        if any(route.edge_route_config is None or route.edge_route_config.tls_source == "letsencrypt" for route in routes):
            raise HTTPException(status_code=409, detail="Gateway Let's Encrypt routes require DNS-01. HTTP-01 and TLS-ALPN-01 relay support is not available yet.")
        letsencrypt = replace(letsencrypt, enabled=False)
    traefik_acme: dict[str, str] = {}
    if letsencrypt.complete and letsencrypt.challenge == "dns-01":
        if letsencrypt.dns_provider == "cloudflare":
            traefik_acme["cloudflare_dns_api_token"] = await get_letsencrypt_cloudflare_api_token(db)
        elif letsencrypt.dns_provider == "rfc2136":
            row = await db.get(SystemSettings, 1)
            traefik_acme = {
                "rfc2136_nameserver": row.letsencrypt_rfc2136_nameserver,
                "rfc2136_tsig_key": row.letsencrypt_rfc2136_tsig_key,
                "rfc2136_tsig_algorithm": row.letsencrypt_rfc2136_tsig_algorithm,
                "rfc2136_tsig_secret": await get_letsencrypt_rfc2136_tsig_secret(db),
            }

    static_config = build_traefik_static_config(letsencrypt=letsencrypt)
    static_config["entryPoints"] = await edge_entrypoints(db, agent_id)
    dynamic_config = await build_traefik_dynamic_config(agent_id, db)
    dynamic_config.update(await relay_dynamic_config(db, agent_id))
    return {
        "runtime_mode": "security_edge",
        "public_ingress": await gateway_ingress(db, agent_id),
        "whitelist": await build_whitelist(agent_id, db),
        "traefik_static_config": static_config,
        "traefik_dynamic_config": dynamic_config,
        "nginx_cache_config": await build_nginx_cache_config(agent_id, db),
        "traefik_acme": traefik_acme,
    }


def redact_edge_desired_state(payload: dict) -> dict:
    def scrub(value):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized = key.lower().replace("_", "")
                if key in SECRET_KEYS or normalized in {"authconfig", "users", "usersfile", "authorization", "proxyauthorization", "password", "secret", "token", "apikey", "keyfile"}:
                    result[key] = "[redacted]" if item else item
                elif normalized in {"customrequestheaders", "customresponseheaders"} and isinstance(item, dict):
                    # Operators can put credentials in headers with arbitrary names.
                    result[key] = {header: "[redacted]" if content else content for header, content in item.items()}
                else:
                    result[key] = scrub(item)
            return result
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return value

    return scrub(payload)


async def dispatch_edge_desired_state(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str]:
    from app.services.agent_commands import send_command

    server = await db.get(EdgeNode, uuid.UUID(str(agent_id)))
    if server is None or (edge_unavailable_reason(server) and not server.relay_enabled):
        return False, "edge_feature_disabled"
    await get_edge_owner(db, agent_id)
    payload = await build_edge_desired_state(agent_id, db)
    cache = payload.get("nginx_cache_config") or {}
    cache_enabled = bool(cache.get("enabled")) and cache.get("mode") not in {None, "", "off", "headers_only"}
    await set_component_desired(agent_id, db, {"nginx_cache": "enabled" if cache_enabled else "disabled"})
    from app.services.edge_runtime import rendered_edge_config
    _, version = await rendered_edge_config(uuid.UUID(str(agent_id)), db, created_by=actor_user_id, desired=payload)
    payload["desired_hash"] = version.desired_hash
    payload["config_version_id"] = str(version.id)
    result = await send_command(
        agent_id=str(agent_id),
        command_type="edge_desired_state",
        params=payload,
        db=db,
        actor_user_id=actor_user_id,
        log_params=redact_edge_desired_state(payload),
    )
    if await is_gateway_edge(db, agent_id):
        await refresh_public_relays(db, actor_user_id)
    return result


async def refresh_public_relays(db: AsyncSession, actor_user_id: uuid.UUID | None = None) -> None:
    """Reconcile every previously managed relay, including the last removed route."""
    from datetime import datetime, timezone
    servers = list((await db.scalars(select(TunnelServer))).all())
    for server in servers:
        node = await db.get(EdgeNode, server.agent_id)
        active = bool(await load_relay_routes(db, server.agent_id))
        if not active and (node is None or not node.relay_enabled):
            continue
        if node is None:
            node = await get_edge_owner(db, server.agent_id)
        was_relay = node.relay_enabled
        node.relay_enabled = active
        if was_relay and not active and edge_unavailable_reason(node):
            node.edge_disabled_at = datetime.now(timezone.utc)
        await db.commit()
        await replay_edge_lifecycle(server.agent_id, db, actor_user_id)


async def dispatch_all_server_edges(
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> None:
    rows = (
        await db.execute(
            select(Agent.id)
            .join(EdgeNode, EdgeNode.agent_id == Agent.id)
            .where(((EdgeNode.edge_mode == "security_edge") & (EdgeNode.edge_state == "enabled")) | EdgeNode.relay_enabled.is_(True))
        )
    ).scalars().all()
    for agent_id in rows:
        await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor_user_id)


async def replay_edge_lifecycle(agent_id: uuid.UUID | str, db: AsyncSession, actor_user_id: uuid.UUID | None = None) -> tuple[bool, str]:
    node = await db.get(EdgeNode, uuid.UUID(str(agent_id)))
    if node is not None and not node.relay_enabled and edge_unavailable_reason(node) and node.edge_disabled_at is not None:
        from app.services.agent_commands import send_command
        result = await send_command(
            agent_id=str(agent_id), command_type="edge_disable",
            params={"preserve_state": True}, db=db, actor_user_id=actor_user_id,
        )
        if await is_gateway_edge(db, agent_id):
            await refresh_public_relays(db, actor_user_id)
        return result
    result = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor_user_id)
    if node is not None and edge_unavailable_reason(node) and await is_gateway_edge(db, agent_id):
        await refresh_public_relays(db, actor_user_id)
    return result


async def dispatch_edge_for_attachment(
    attachment_id: uuid.UUID,
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str] | None:
    row = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == attachment_id)
    )
    if row is None:
        return None
    server = await db.scalar(
        select(TunnelServer).where(TunnelServer.id == row.tunnel_server_id)
    )
    if server is None:
        return None
    return await dispatch_edge_desired_state(
        server.agent_id,
        db,
        actor_user_id=actor_user_id,
    )


async def site_server_context(
    pf: HTTPRoute,
    db: AsyncSession,
) -> tuple[uuid.UUID | None, uuid.UUID | None]:
    server = await db.scalar(
        select(TunnelServer).where(TunnelServer.agent_id == pf.agent_id)
    )
    return server.id if server else None, pf.agent_id


async def uses_antibot(db: AsyncSession, *, exclude_port_forward_id: uuid.UUID | None = None) -> bool:
    q = select(EdgeRouteConfig).where(EdgeRouteConfig.antibot.is_(True))
    if exclude_port_forward_id is not None:
        q = q.where(EdgeRouteConfig.port_forward_id != exclude_port_forward_id)
    return (await db.scalar(q.limit(1))) is not None

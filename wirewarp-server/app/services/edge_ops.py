from __future__ import annotations

import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.edge_component_state import EdgeComponentState
from app.models.edge_route_config import EdgeRouteConfig
from app.models.port_forward import PortForward
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.services.crowdsec_ops import build_whitelist
from app.services.edge_cache_ops import build_nginx_cache_config
from app.services.traefik_ops import (
    build_traefik_dynamic_config,
    build_traefik_static_config,
    load_letsencrypt_config,
)
from app.services.secrets import get_letsencrypt_cloudflare_api_token


SECRET_KEYS = {"captchaSecretKey", "cloudflare_dns_api_token"}
EDGE_COMPONENTS = ("traefik", "crowdsec", "appsec", "access_log", "nginx_cache")
DEFAULT_SECURITY_EDGE_COMPONENTS = {
    "traefik": "enabled",
    "crowdsec": "enabled",
    "appsec": "enabled",
    "access_log": "enabled",
    "nginx_cache": "disabled",
}


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
            row.phase = "disabled"
            row.running = False
        elif row.phase == "disabled":
            row.phase = "pending"
        out[component] = row
    return out


async def build_edge_desired_state(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> dict:
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    if server is not None:
        ensure_edge_enabled(server)
    letsencrypt = await load_letsencrypt_config(db)
    le_token = await get_letsencrypt_cloudflare_api_token(db)
    traefik_acme: dict[str, str] = {}
    if letsencrypt.complete and letsencrypt.challenge == "dns-01" and le_token:
        traefik_acme["cloudflare_dns_api_token"] = le_token

    return {
        "whitelist": await build_whitelist(agent_id, db),
        "traefik_static_config": build_traefik_static_config(letsencrypt=letsencrypt),
        "traefik_dynamic_config": await build_traefik_dynamic_config(agent_id, db),
        "nginx_cache_config": await build_nginx_cache_config(agent_id, db),
        "traefik_acme": traefik_acme,
    }


def redact_edge_desired_state(payload: dict) -> dict:
    def scrub(value):
        if isinstance(value, dict):
            return {
                k: ("[redacted]" if k in SECRET_KEYS and v else scrub(v))
                for k, v in value.items()
            }
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

    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    if server is None or edge_unavailable_reason(server):
        return False, "edge_feature_disabled"
    payload = await build_edge_desired_state(agent_id, db)
    return await send_command(
        agent_id=str(agent_id),
        command_type="edge_desired_state",
        params=payload,
        db=db,
        actor_user_id=actor_user_id,
        log_params=redact_edge_desired_state(payload),
    )


async def dispatch_all_server_edges(
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> None:
    rows = (
        await db.execute(
            select(Agent.id)
            .join(TunnelServer, TunnelServer.agent_id == Agent.id)
            .where(
                TunnelServer.edge_mode == "security_edge",
                TunnelServer.edge_state == "enabled",
            )
        )
    ).scalars().all()
    for agent_id in rows:
        await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor_user_id)


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
    pf: PortForward,
    db: AsyncSession,
) -> tuple[uuid.UUID | None, uuid.UUID | None]:
    att = await db.scalar(
        select(TunnelClientAttachment).where(
            TunnelClientAttachment.id == pf.attachment_id
        )
    )
    if att is None:
        return None, None
    server = await db.scalar(
        select(TunnelServer).where(TunnelServer.id == att.tunnel_server_id)
    )
    if server is None:
        return None, None
    return server.id, server.agent_id


async def uses_antibot(db: AsyncSession, *, exclude_port_forward_id: uuid.UUID | None = None) -> bool:
    q = select(EdgeRouteConfig).where(EdgeRouteConfig.antibot.is_(True))
    if exclude_port_forward_id is not None:
        q = q.where(EdgeRouteConfig.port_forward_id != exclude_port_forward_id)
    return (await db.scalar(q.limit(1))) is not None

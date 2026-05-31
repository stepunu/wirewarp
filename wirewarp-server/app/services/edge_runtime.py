from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import yaml

from app.models.edge_config_version import EdgeConfigVersion
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_profile import EdgeProfile
from app.models.edge_route_config import EdgeRouteConfig
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.services.edge_ops import build_edge_desired_state


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode()).hexdigest()


async def rendered_edge_config(
    agent_id: uuid.UUID,
    db: AsyncSession,
    *,
    created_by: uuid.UUID | None = None,
) -> tuple[dict[str, Any], EdgeConfigVersion]:
    desired = await build_edge_desired_state(agent_id, db)
    dynamic = desired.get("traefik_dynamic_config") or {}
    static = desired.get("traefik_static_config") or {}
    cache_config = desired.get("nginx_cache_config") or {}
    desired_hash = digest(desired)
    dynamic_hash = digest(dynamic)
    static_hash = digest(static)
    cache_hash = digest(cache_config)
    existing = await db.scalar(
        select(EdgeConfigVersion)
        .where(
            EdgeConfigVersion.agent_id == agent_id,
            EdgeConfigVersion.desired_hash == desired_hash,
        )
        .order_by(EdgeConfigVersion.created_at.desc())
    )
    if existing is None:
        existing = EdgeConfigVersion(
            id=uuid.uuid4(),
            agent_id=agent_id,
            desired_hash=desired_hash,
            rendered_static_hash=static_hash,
            rendered_dynamic_hash=dynamic_hash,
            rendered_dynamic_yaml=yaml.safe_dump(dynamic, sort_keys=True),
            rendered_cache_hash=cache_hash,
            rendered_cache_config=yaml.safe_dump(cache_config, sort_keys=True),
            created_by=created_by,
        )
        db.add(existing)
        await db.commit()
        await db.refresh(existing)
    return (
        {
            "desired_hash": desired_hash,
            "static_hash": static_hash,
            "dynamic_hash": dynamic_hash,
            "cache_hash": cache_hash,
            "dynamic": dynamic,
            "cache": cache_config,
        },
        existing,
    )


async def desired_state_snapshot(
    agent_id: uuid.UUID,
    db: AsyncSession,
) -> dict[str, Any]:
    profiles = (await db.execute(select(EdgeProfile).order_by(EdgeProfile.slug))).scalars().all()
    policy = await db.get(EdgeNodePolicy, agent_id)
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    routes: list[dict[str, Any]] = []
    if server is not None:
        att_ids = (
            await db.execute(
                select(TunnelClientAttachment.id).where(TunnelClientAttachment.tunnel_server_id == server.id)
            )
        ).scalars().all()
        if att_ids:
            rows = (
                await db.execute(
                    select(PortForward)
                    .where(
                        PortForward.attachment_id.in_(att_ids),
                        PortForward.service_kind == "http",
                    )
                    .order_by(PortForward.domain)
                )
            ).scalars().all()
            routes = []
            for row in rows:
                ec = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.port_forward_id == row.id))
                routes.append(
                    {
                        "id": str(row.id),
                        "domain": row.domain,
                        "enabled": row.active,
                        "destination_ip": row.destination_ip,
                        "destination_port": row.destination_port,
                        "profile_id": str(ec.profile_id) if ec and ec.profile_id else None,
                        "priority": ec.priority if ec else 0,
                        "policy": ec.policy_json if ec else {},
                    }
                )
    upstream_pools = (
        await db.execute(select(EdgeUpstreamPool).where(EdgeUpstreamPool.agent_id == agent_id).order_by(EdgeUpstreamPool.name))
    ).scalars().all()
    return {
        "profiles": [
            {"id": str(row.id), "slug": row.slug, "name": row.name, "policy": row.policy_json or {}}
            for row in profiles
        ],
        "routes": routes,
        "upstream_pools": [
            {
                "id": str(row.id),
                "name": row.name,
                "description": row.description,
                "servers": row.servers or [],
                "health_check": row.health_check or {},
                "policy": row.policy_json or {},
            }
            for row in upstream_pools
        ],
        "effective": {
            "policy": policy.policy_json if policy is not None else {},
        },
    }

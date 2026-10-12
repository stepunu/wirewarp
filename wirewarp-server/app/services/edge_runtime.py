from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import yaml

from app.models.edge_config_version import EdgeConfigVersion
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_profile import EdgeProfile
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_fragment import EdgeFragment
from app.services.edge_ops import build_edge_desired_state
from app.services.edge_ownership import load_http_routes


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode()).hexdigest()


async def rendered_edge_config(
    agent_id: uuid.UUID,
    db: AsyncSession,
    *,
    created_by: uuid.UUID | None = None,
    desired: dict | None = None,
) -> tuple[dict[str, Any], EdgeConfigVersion]:
    if desired is None:
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
    from app.services.edge_config_snapshots import capture_edge_source
    source = await capture_edge_source(agent_id, db)
    if existing is None or existing.source_snapshot != source:
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
            source_snapshot=source,
            created_at=datetime.now(timezone.utc),
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
    profiles = (await db.execute(select(EdgeProfile).where((EdgeProfile.agent_id.is_(None)) | (EdgeProfile.agent_id == agent_id)).order_by(EdgeProfile.slug))).scalars().all()
    policy = await db.get(EdgeNodePolicy, agent_id)
    routes: list[dict[str, Any]] = []
    rows = await load_http_routes(db, agent_id)
    for row in rows:
        ec = row.edge_route_config
        routes.append({
            "id": str(row.id),
            "domain": row.domain,
            "enabled": row.active,
            "visibility": row.visibility,
            "destination_ip": row.destination_ip,
            "destination_port": row.destination_port,
            "profile_id": str(ec.profile_id) if ec and ec.profile_id else None,
            "priority": ec.priority if ec else 0,
            "policy": ec.policy_json if ec else {},
            "attachment_id": str(row.public_ingress.attachment_id) if row.public_ingress else None,
            "tunnel_server_ip_id": str(row.public_ingress.tunnel_server_ip_id) if row.public_ingress and row.public_ingress.tunnel_server_ip_id else None,
            "upstream_scheme": ec.upstream_scheme if ec else "http",
            "upstream_insecure_skip_verify": ec.upstream_insecure_skip_verify if ec else False,
        })
    upstream_pools = (
        await db.execute(select(EdgeUpstreamPool).where(EdgeUpstreamPool.agent_id == agent_id).order_by(EdgeUpstreamPool.name))
    ).scalars().all()
    path_rules = (await db.scalars(select(EdgePathRule).where(EdgePathRule.route_id.in_([row.id for row in rows])).order_by(EdgePathRule.id))).all()
    fragments = (await db.scalars(select(EdgeFragment).where(EdgeFragment.agent_id == agent_id).order_by(EdgeFragment.id))).all()
    return {
        "profiles": [
            {"id": str(row.id), "slug": row.slug, "name": row.name, "scope":row.scope, "agent_id":str(row.agent_id) if row.agent_id else None, "policy": row.policy_json or {}}
            for row in profiles
        ],
        "routes": routes,
        "path_rules": [{"id":str(row.id), "route_id":str(row.route_id), "name":row.name, "match":row.match, "priority":row.priority, "enabled":row.enabled, "policy":row.policy_json or {}} for row in path_rules],
        "fragments": [{"id":str(row.id), "route_id":str(row.route_id) if row.route_id else None, "name":row.name, "fragment_type":row.fragment_type, "content":row.content, "enabled":row.enabled} for row in fragments],
        "node_policy": {"default_profile_id":str(policy.default_profile_id) if policy.default_profile_id else None,
                        "client_ip_strategy":policy.client_ip_strategy, "trusted_proxy_cidrs":policy.trusted_proxy_cidrs,
                        "cloudflare_mode":policy.cloudflare_mode, "access_log_retention_hours":policy.access_log_retention_hours,
                        "security_event_retention_days":policy.security_event_retention_days, "policy":policy.policy_json or {}} if policy else None,
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

from __future__ import annotations

import re
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_profile import EdgeProfile
from app.models.edge_route_config import EdgeRouteConfig
from app.models.http_route import HTTPRoute
from app.models.edge_node import EdgeNode
from app.models.tunnel_server import TunnelServer
from app.services.edge_ownership import get_edge_owner
from app.schemas.edge import (
    EdgeEffectivePolicyRead,
    EdgeNodePolicyRead,
    EdgeProfileRead,
    EdgeRouteRead,
)


GLOBAL_EDGE_DEFAULTS: dict[str, Any] = {
    "waf_mode": "off",
    "rate_limit": None,
    "headers": {},
    "access": {},
    "tls": {"mode": "letsencrypt"},
    "origin": {},
    "cache": {"mode": "off"},
}


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "edge-profile"


def deep_merge(*layers: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for layer in layers:
        if not layer:
            continue
        for key, value in layer.items():
            if (
                isinstance(value, dict)
                and isinstance(out.get(key), dict)
            ):
                out[key] = deep_merge(out[key], value)
            else:
                out[key] = value
    return out


def profile_read(profile: EdgeProfile) -> EdgeProfileRead:
    return EdgeProfileRead(
        id=profile.id,
        name=profile.name,
        slug=profile.slug,
        description=profile.description,
        scope=profile.scope,
        agent_id=profile.agent_id,
        policy=profile.policy_json or {},
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


async def get_profile_by_id_or_slug(
    db: AsyncSession,
    profile_id_or_slug: str | uuid.UUID | None,
) -> EdgeProfile | None:
    if profile_id_or_slug is None:
        return None
    try:
        profile_id = uuid.UUID(str(profile_id_or_slug))
    except ValueError:
        profile_id = None
    if profile_id is not None:
        return await db.get(EdgeProfile, profile_id)
    return await db.scalar(select(EdgeProfile).where(EdgeProfile.slug == str(profile_id_or_slug)))


async def get_or_create_node_policy(
    db: AsyncSession,
    agent_id: uuid.UUID,
) -> EdgeNodePolicy:
    row = await db.get(EdgeNodePolicy, agent_id)
    if row is not None:
        return row
    row = EdgeNodePolicy(agent_id=agent_id)
    db.add(row)
    await db.flush()
    return row


async def node_policy_effective(
    db: AsyncSession,
    policy: EdgeNodePolicy,
) -> dict[str, Any]:
    profile_policy = {}
    if policy.default_profile_id:
        profile = await db.get(EdgeProfile, policy.default_profile_id)
        if profile is not None:
            profile_policy = profile.policy_json or {}
    return deep_merge(GLOBAL_EDGE_DEFAULTS, profile_policy, policy.policy_json or {})


async def node_policy_read(db: AsyncSession, policy: EdgeNodePolicy) -> EdgeNodePolicyRead:
    return EdgeNodePolicyRead(
        agent_id=policy.agent_id,
        default_profile_id=policy.default_profile_id,
        client_ip_strategy=policy.client_ip_strategy,
        trusted_proxy_cidrs=list(policy.trusted_proxy_cidrs or []),
        cloudflare_mode=policy.cloudflare_mode,
        access_log_retention_hours=policy.access_log_retention_hours,
        security_event_retention_days=policy.security_event_retention_days,
        policy=policy.policy_json or {},
        effective=await node_policy_effective(db, policy),
    )


async def server_for_route(db: AsyncSession, route: HTTPRoute) -> EdgeNode:
    return await get_edge_owner(db, route.agent_id)


async def route_edge_config(db: AsyncSession, route: HTTPRoute) -> EdgeRouteConfig:
    ec = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.port_forward_id == route.id))
    if ec is None:
        ec = EdgeRouteConfig(id=uuid.uuid4(), port_forward_id=route.id)
        db.add(ec)
        await db.flush()
    return ec


def route_desired_policy(ec: EdgeRouteConfig | None) -> dict[str, Any]:
    return dict(ec.policy_json or {}) if ec is not None else {}


async def route_effective_policy(
    db: AsyncSession,
    route: HTTPRoute,
    ec: EdgeRouteConfig | None = None,
    *,
    path_rule: EdgePathRule | None = None,
) -> EdgeEffectivePolicyRead:
    server = await server_for_route(db, route)
    if server is None:
        raise HTTPException(status_code=404, detail="Route server not found")
    node_policy = await db.get(EdgeNodePolicy, server.agent_id)
    if ec is not None and not ec.inherit_node_policy:
        node_policy = None
    profile_policy = {}
    profile_id = ec.profile_id if ec and ec.profile_id else node_policy.default_profile_id if node_policy else None
    if profile_id:
        profile = await db.get(EdgeProfile, profile_id)
        if profile is not None:
            profile_policy = profile.policy_json or {}
    desired = route_desired_policy(ec)
    path_policy = path_rule.policy_json if path_rule is not None else None
    from app.services.edge_render import effective_render_policy
    try:
        effective = await effective_render_policy(db, route, ec, path_rule)
    except ValueError as exc:
        raise HTTPException(422, detail={"code":"edge_policy_invalid", "detail":str(exc)}) from exc
    return EdgeEffectivePolicyRead(
        route_id=route.id,
        desired=desired,
        effective=effective,
        sources={
            "global": GLOBAL_EDGE_DEFAULTS,
            "node": (node_policy.policy_json or {}) if node_policy else {},
            "profile": profile_policy,
            "route": desired,
            **({"path_rule": path_policy or {}} if path_rule is not None else {}),
        },
    )


async def route_read(db: AsyncSession, route: HTTPRoute, ec: EdgeRouteConfig | None = None) -> EdgeRouteRead:
    if ec is None:
        ec = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.port_forward_id == route.id))
    owner = await server_for_route(db, route)
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == owner.agent_id))
    from app.models.http_public_ingress import HTTPPublicIngress
    ingress = await db.get(HTTPPublicIngress, route.id)
    effective = await route_effective_policy(db, route, ec)
    return EdgeRouteRead(
        id=route.id,
        node_id=owner.agent_id,
        server_id=server.id if server else None,
        attachment_id=ingress.attachment_id if ingress else None,
        public_port=ingress.public_port if ingress else None,
        tunnel_server_ip_id=ingress.tunnel_server_ip_id if ingress else None,
        visibility=route.visibility,
        domain=route.domain,
        enabled=route.active,
        priority=ec.priority if ec else 0,
        profile_id=ec.profile_id if ec else None,
        inherit_node_policy=ec.inherit_node_policy if ec else True,
        destination_ip=route.destination_ip,
        destination_port=route.destination_port,
        description=route.description,
        policy=route_desired_policy(ec),
        effective=effective.effective,
        created_at=route.created_at,
    )


def apply_policy_to_edge_config(ec: EdgeRouteConfig, policy: dict[str, Any] | None) -> None:
    if policy is None:
        return
    ec.policy_json = policy
    if "waf_mode" in policy and policy["waf_mode"] is not None:
        ec.waf_mode = str(policy["waf_mode"])
    rate = policy.get("rate_limit")
    if isinstance(rate, dict):
        if "requests" in rate:
            ec.rate_limit_rps = int(rate["requests"]) if rate["requests"] is not None else None
        if "burst" in rate:
            ec.rate_limit_burst = int(rate["burst"]) if rate["burst"] is not None else None
    for source, attr in (
        ("ip_allow", "ip_allow"),
        ("ip_deny", "ip_deny"),
        ("geo_block", "geo_block"),
        ("auth_mode", "auth_mode"),
        ("auth_config", "auth_config"),
        ("tls_source", "tls_source"),
    ):
        if source in policy:
            setattr(ec, attr, policy[source])

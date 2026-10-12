from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.edge_cache_snapshot import EdgeCacheSnapshot
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_route_config import EdgeRouteConfig
from app.services.edge_ownership import load_http_routes
from app.services.edge_render import policy_edge_config, render_variants, validate_path_cache
from app.models.edge_profile import EdgeProfile
from app.services.edge_resources import deep_merge


NGINX_CACHE_LISTEN = "127.0.0.1:18080"
NGINX_CACHE_URL = f"http://{NGINX_CACHE_LISTEN}"
DEFAULT_BYPASS_PATH_PREFIXES = ["/api", "/auth", "/login", "/admin", "/session"]
NON_BACKEND_CACHE_MODES = {"off", "headers_only", ""}
VALID_CACHE_PROOFS = {"miss_hit", "bypass"}


async def load_node_cache_policy(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> dict[str, Any]:
    row = await db.get(EdgeNodePolicy, uuid.UUID(str(agent_id)))
    policy = dict(row.policy_json or {}) if row is not None else {}
    if row is not None and row.default_profile_id:
        profile = await db.get(EdgeProfile, row.default_profile_id)
        if profile is None or profile.agent_id not in (None, uuid.UUID(str(agent_id))):
            raise ValueError("Cache profile must belong to this node or be global")
        policy = deep_merge(policy, profile.policy_json)
    cache = policy.get("cache")
    return normalize_cache_policy(cache if isinstance(cache, dict) else {})


def normalize_cache_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(policy or {})
    out["mode"] = str(out.get("mode") or "off")
    return out


def cache_policy_uses_backend(policy: dict[str, Any] | None) -> bool:
    return normalize_cache_policy(policy).get("mode") not in NON_BACKEND_CACHE_MODES


async def nginx_cache_backend_available(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> bool:
    snapshot = await db.scalar(
        select(EdgeCacheSnapshot).where(
            EdgeCacheSnapshot.agent_id == uuid.UUID(str(agent_id)),
            EdgeCacheSnapshot.backend == "nginx_proxy_cache",
        )
    )
    return bool(
        snapshot
        and snapshot.installed
        and snapshot.running
        and snapshot.phase == "healthy"
        and snapshot.last_test_status in VALID_CACHE_PROOFS
    )


def route_cache_policy(
    node_cache_policy: dict[str, Any],
    edge_config: EdgeRouteConfig | None,
) -> dict[str, Any]:
    route_policy = edge_config.policy_json if edge_config is not None else None
    route_cache = route_policy.get("cache") if isinstance(route_policy, dict) else None
    if isinstance(route_cache, dict) and route_cache.get("mode"):
        merged = dict(node_cache_policy)
        merged.update(route_cache)
        return normalize_cache_policy(merged)
    return normalize_cache_policy(node_cache_policy)


def route_uses_nginx_cache(
    node_cache_policy: dict[str, Any],
    edge_config: EdgeRouteConfig | None,
) -> bool:
    return cache_policy_uses_backend(route_cache_policy(node_cache_policy, edge_config))


def nginx_cache_service_url(node_cache_policy: dict[str, Any] | None = None) -> str:
    return NGINX_CACHE_URL


async def build_nginx_cache_config(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> dict[str, Any]:
    node_cache = await load_node_cache_policy(agent_id, db)
    routes: list[dict[str, Any]] = []

    forwards = await load_http_routes(db, agent_id, active_only=True)
    variants = await render_variants(db, forwards)
    for pf, stored_ec, path, effective in variants:
        policy = normalize_cache_policy(effective.get("cache"))
        if path:
            if cache_policy_uses_backend(policy):
                await validate_path_cache(db, pf, stored_ec, effective)
            continue
        ec = policy_edge_config(effective)
        if not cache_policy_uses_backend(policy):
            continue
        origin = effective.get("origin") or {}
        if origin.get("upstream_pool_id", effective.get("upstream_pool_id")) or origin.get("service"):
            raise ValueError("Backend cache requires a single managed origin")
        scheme = ec.upstream_scheme if ec is not None else "http"
        routes.append({
            "route_id": str(pf.id),
            "host": pf.domain,
            "origin_url": f"{scheme}://{pf.destination_ip}:{pf.destination_port}",
            "mode": policy.get("mode"),
            "cache_status_header": bool(policy.get("cache_status_header", True)),
            "edge_ttl_seconds": _int_or_default(policy.get("edge_ttl_seconds"), 600),
            "browser_ttl_seconds": _int_or_none(policy.get("browser_ttl_seconds")),
            "upstream_insecure_skip_verify": bool(ec.upstream_insecure_skip_verify if ec is not None else False),
            "bypass_path_prefixes": _list_of_strings(policy.get("bypass_path_prefixes"), DEFAULT_BYPASS_PATH_PREFIXES),
        })

    return {
        "enabled": bool(routes),
        "mode": "proxy_cache" if routes else node_cache.get("mode", "off"),
        "listen": NGINX_CACHE_LISTEN,
        "cache_path": str(node_cache.get("cache_path") or "/var/cache/wirewarp/nginx"),
        "keys_zone": str(node_cache.get("keys_zone") or "wirewarp_cache:64m"),
        "max_size": str(node_cache.get("max_size") or "1g"),
        "inactive": str(node_cache.get("inactive") or "60m"),
        "cache_status_header": bool(node_cache.get("cache_status_header", True)),
        "edge_ttl_seconds": _int_or_default(node_cache.get("edge_ttl_seconds"), 600),
        "browser_ttl_seconds": _int_or_none(node_cache.get("browser_ttl_seconds")),
        "routes": routes,
    }


def _int_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _list_of_strings(value: Any, default: list[str]) -> list[str]:
    if not isinstance(value, list):
        return list(default)
    out = [str(item) for item in value if str(item).strip()]
    return out or list(default)

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_route_config import EdgeRouteConfig
from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer


NGINX_CACHE_LISTEN = "127.0.0.1:18080"
NGINX_CACHE_URL = f"http://{NGINX_CACHE_LISTEN}"
DEFAULT_BYPASS_PATH_PREFIXES = ["/api", "/auth", "/login", "/admin", "/session"]
NON_BACKEND_CACHE_MODES = {"off", "headers_only", ""}


async def load_node_cache_policy(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> dict[str, Any]:
    row = await db.get(EdgeNodePolicy, uuid.UUID(str(agent_id)))
    policy = dict(row.policy_json or {}) if row is not None else {}
    cache = policy.get("cache")
    return normalize_cache_policy(cache if isinstance(cache, dict) else {})


def normalize_cache_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(policy or {})
    out["mode"] = str(out.get("mode") or "off")
    return out


def cache_policy_uses_backend(policy: dict[str, Any] | None) -> bool:
    return normalize_cache_policy(policy).get("mode") not in NON_BACKEND_CACHE_MODES


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
    policy = normalize_cache_policy(node_cache_policy)
    return str(policy.get("service_url") or NGINX_CACHE_URL)


async def build_nginx_cache_config(
    agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> dict[str, Any]:
    node_cache = await load_node_cache_policy(agent_id, db)
    routes: list[dict[str, Any]] = []

    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    if server is not None:
        att_ids = (
            await db.execute(
                select(TunnelClientAttachment.id).where(
                    TunnelClientAttachment.tunnel_server_id == server.id
                )
            )
        ).scalars().all()
        if att_ids:
            forwards = (
                await db.execute(
                    select(PortForward)
                    .where(
                        PortForward.attachment_id.in_(att_ids),
                        PortForward.service_kind == "http",
                        PortForward.active == True,  # noqa: E712
                    )
                    .order_by(PortForward.domain)
                )
            ).scalars().all()
            for pf in forwards:
                if not pf.domain:
                    continue
                ec = await db.scalar(
                    select(EdgeRouteConfig).where(EdgeRouteConfig.port_forward_id == pf.id)
                )
                policy = route_cache_policy(node_cache, ec)
                if not cache_policy_uses_backend(policy):
                    continue
                scheme = ec.upstream_scheme if ec is not None else "http"
                routes.append(
                    {
                        "route_id": str(pf.id),
                        "host": pf.domain,
                        "origin_url": f"{scheme}://{pf.destination_ip}:{pf.destination_port}",
                        "mode": policy.get("mode"),
                        "cache_status_header": bool(policy.get("cache_status_header", True)),
                        "edge_ttl_seconds": _int_or_default(policy.get("edge_ttl_seconds"), 600),
                        "browser_ttl_seconds": _int_or_none(policy.get("browser_ttl_seconds")),
                        "upstream_insecure_skip_verify": bool(
                            ec.upstream_insecure_skip_verify if ec is not None else False
                        ),
                        "bypass_path_prefixes": _list_of_strings(
                            policy.get("bypass_path_prefixes"),
                            DEFAULT_BYPASS_PATH_PREFIXES,
                        ),
                    }
                )

    return {
        "enabled": bool(routes),
        "mode": node_cache.get("mode", "off"),
        "listen": str(node_cache.get("listen") or NGINX_CACHE_LISTEN),
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

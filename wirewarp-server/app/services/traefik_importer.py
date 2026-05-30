from __future__ import annotations

import re
import tomllib
import uuid
from typing import Any
from urllib.parse import urlparse

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.schemas.security import (
    TraefikImportPreview,
    TraefikImportRequest,
    TraefikImportRoutePreview,
    TraefikImportSummary,
)


HOST_RE = re.compile(r"Host\((?P<args>[^)]*)\)")
QUOTED_HOST_RE = re.compile(r"[`'\"]([^`'\"]+)[`'\"]")
DOMAIN_FILTER_RE = re.compile(r"\{\{\s*domain\s*\|\s*replace\([^}]+\)\s*\}\}")
DOMAIN_VAR_RE = re.compile(r"\{\{\s*domain\s*\}\}")


def render_template_vars(content: str, domain_suffix: str | None) -> str:
    if not domain_suffix:
        return content
    rendered = DOMAIN_FILTER_RE.sub(domain_suffix.replace(".", r"\."), content)
    return DOMAIN_VAR_RE.sub(domain_suffix, rendered)


def parse_traefik_config(content: str, content_format: str = "auto") -> dict[str, Any]:
    fmt = content_format.lower()
    if fmt not in {"auto", "yaml", "yml", "toml"}:
        raise ValueError("content_format must be auto, yaml, yml, or toml")
    if fmt == "toml" or (fmt == "auto" and content.lstrip().startswith("[http")):
        loaded = tomllib.loads(content)
        return loaded if isinstance(loaded, dict) else {}

    merged: dict[str, Any] = {}
    for doc in yaml.safe_load_all(content):
        if isinstance(doc, dict):
            _deep_merge(merged, doc)
    return merged


async def preview_traefik_import(
    request: TraefikImportRequest,
    db: AsyncSession,
) -> TraefikImportPreview:
    attachment = await db.scalar(
        select(TunnelClientAttachment).where(
            TunnelClientAttachment.id == request.attachment_id,
            TunnelClientAttachment.tunnel_server_id == request.server_id,
        )
    )
    if attachment is None:
        raise ValueError("Attachment does not belong to the selected server")

    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == request.server_id))
    if server is None:
        raise ValueError("Tunnel server not found")

    config = _parse_import_request_config(request)
    http = config.get("http") if isinstance(config, dict) else {}
    if not isinstance(http, dict):
        http = {}
    routers = http.get("routers") if isinstance(http.get("routers"), dict) else {}
    services = http.get("services") if isinstance(http.get("services"), dict) else {}
    middlewares = http.get("middlewares") if isinstance(http.get("middlewares"), dict) else {}
    transports = (
        http.get("serversTransports")
        if isinstance(http.get("serversTransports"), dict)
        else {}
    )

    existing = await _existing_sites_by_domain(db, request.server_id)
    previews: list[TraefikImportRoutePreview] = []
    for router_name, router in sorted(routers.items()):
        if not isinstance(router, dict):
            continue
        previews.append(
            _preview_router(
                str(router_name),
                router,
                services,
                middlewares,
                transports,
                existing,
                overwrite=request.overwrite,
            )
        )

    importable = sum(1 for route in previews if route.importable)
    existing_count = sum(1 for route in previews if route.existing_site_id is not None)
    return TraefikImportPreview(
        summary=TraefikImportSummary(
            routers=len(previews),
            importable=importable,
            skipped=len(previews) - importable,
            existing=existing_count,
        ),
        routes=previews,
    )


def _parse_import_request_config(request: TraefikImportRequest) -> dict[str, Any]:
    content = render_template_vars(request.content, request.domain_suffix)
    config = parse_traefik_config(content, request.content_format)
    if request.middlewares_content:
        middlewares_content = render_template_vars(
            request.middlewares_content,
            request.domain_suffix,
        )
        _deep_merge(
            config,
            parse_traefik_config(middlewares_content, request.content_format),
        )
    return config


def _preview_router(
    router_name: str,
    router: dict[str, Any],
    services: dict[str, Any],
    middlewares: dict[str, Any],
    transports: dict[str, Any],
    existing: dict[str, uuid.UUID],
    *,
    overwrite: bool,
) -> TraefikImportRoutePreview:
    warnings: list[str] = []
    rule = str(router.get("rule") or "")
    hosts = _extract_hosts(rule)
    if len(hosts) > 1:
        warnings.append("Router has multiple Host() values; importing the first host only")
    domain = hosts[0] if hosts else None
    if not domain:
        warnings.append("Router has no Host() rule")

    service_name = _clean_ref(str(router.get("service") or ""))
    if not service_name:
        warnings.append("Router has no service")
    if service_name.endswith("@internal"):
        warnings.append("Traefik internal services are not importable")

    service = services.get(_clean_ref(service_name)) if service_name else None
    upstream_url, destination_ip, destination_port, upstream_scheme = _service_target(service)
    if service_name and service is None and not service_name.endswith("@internal"):
        warnings.append(f"Service {service_name} was not found in the imported config")
    if service is not None and upstream_url is None:
        warnings.append(f"Service {service_name} has no importable HTTP upstream URL")

    lb = service.get("loadBalancer") if isinstance(service, dict) else {}
    servers = lb.get("servers") if isinstance(lb, dict) else []
    if isinstance(servers, list) and len(servers) > 1:
        warnings.append("Service has multiple upstream servers; importing the first one only")
    transport_name = _clean_ref(str(lb.get("serversTransport") or "")) if isinstance(lb, dict) else ""
    transport = transports.get(transport_name) if transport_name else None
    upstream_insecure = bool(
        isinstance(transport, dict) and transport.get("insecureSkipVerify") is True
    )

    if destination_ip and ("{" in destination_ip or "}" in destination_ip):
        warnings.append("Upstream host still contains an unresolved template variable")
        destination_ip = None

    middleware_refs = [_clean_ref(str(item)) for item in _as_list(router.get("middlewares"))]
    mapped_policy, middleware_warnings = _map_middlewares(middleware_refs, middlewares)
    warnings.extend(middleware_warnings)

    tls_source = "letsencrypt" if router.get("tls") is not None else "none"
    existing_site_id = existing.get(domain or "")
    if existing_site_id and not overwrite:
        warnings.append("A WireWarp site already exists for this domain")

    importable = bool(
        domain
        and destination_ip
        and destination_port
        and not service_name.endswith("@internal")
        and (not existing_site_id or overwrite)
    )
    return TraefikImportRoutePreview(
        router_name=router_name,
        domain=domain,
        service_name=_clean_ref(service_name) or None,
        upstream_url=upstream_url,
        destination_ip=destination_ip,
        destination_port=destination_port,
        upstream_scheme=upstream_scheme,
        upstream_insecure_skip_verify=upstream_insecure,
        tls_source=tls_source,
        middlewares=middleware_refs,
        mapped_policy=mapped_policy,
        warnings=warnings,
        importable=importable,
        existing_site_id=existing_site_id,
    )


def _map_middlewares(
    middleware_refs: list[str],
    middlewares: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    mapped: dict[str, Any] = {
        "ip_allow": [],
        "ip_deny": [],
        "geo_block": [],
        "auth_mode": "none",
        "auth_config": None,
        "rate_limit_rps": None,
        "rate_limit_burst": None,
    }
    seen: set[str] = set()
    expanded = _expand_middlewares(middleware_refs, middlewares, seen, warnings)
    for name in expanded:
        cfg = middlewares.get(name)
        if not isinstance(cfg, dict):
            warnings.append(f"Middleware {name} was referenced but not found")
            continue
        if "ipAllowList" in cfg or "ipWhiteList" in cfg:
            body = cfg.get("ipAllowList") or cfg.get("ipWhiteList") or {}
            mapped["ip_allow"].extend(_as_list(body.get("sourceRange")))
            continue
        if "rateLimit" in cfg:
            body = cfg.get("rateLimit") or {}
            mapped["rate_limit_rps"] = body.get("average")
            mapped["rate_limit_burst"] = body.get("burst")
            continue
        if "basicAuth" in cfg:
            mapped["auth_mode"] = "basic"
            mapped["auth_config"] = cfg["basicAuth"]
            continue
        if "forwardAuth" in cfg:
            mapped["auth_mode"] = "forward"
            mapped["auth_config"] = cfg["forwardAuth"]
            continue
        plugin = cfg.get("plugin")
        if isinstance(plugin, dict):
            geoblock = plugin.get("geoblock")
            deny = plugin.get("denyip") or plugin.get("denyIp") or plugin.get("denyIP")
            if isinstance(geoblock, dict):
                mapped["geo_block"].extend(_as_list(geoblock.get("blockedCountries")))
                continue
            if isinstance(deny, dict):
                mapped["ip_deny"].extend(_as_list(deny.get("sourceRange") or deny.get("ips")))
                continue
        warnings.append(f"Middleware {name} is not modelled by WireWarp and will not be rendered")

    for key in ("ip_allow", "ip_deny", "geo_block"):
        mapped[key] = _dedupe([str(v) for v in mapped[key] if v])
    return mapped, warnings


def _expand_middlewares(
    refs: list[str],
    middlewares: dict[str, Any],
    seen: set[str],
    warnings: list[str],
) -> list[str]:
    expanded: list[str] = []
    for ref in refs:
        name = _clean_ref(ref)
        if not name or name in seen:
            continue
        seen.add(name)
        cfg = middlewares.get(name)
        if isinstance(cfg, dict) and isinstance(cfg.get("chain"), dict):
            chain_refs = [_clean_ref(str(v)) for v in _as_list(cfg["chain"].get("middlewares"))]
            expanded.extend(_expand_middlewares(chain_refs, middlewares, seen, warnings))
            continue
        expanded.append(name)
    return expanded


async def _existing_sites_by_domain(
    db: AsyncSession,
    server_id: uuid.UUID,
) -> dict[str, uuid.UUID]:
    att_ids = (
        await db.execute(
            select(TunnelClientAttachment.id).where(
                TunnelClientAttachment.tunnel_server_id == server_id
            )
        )
    ).scalars().all()
    if not att_ids:
        return {}
    rows = (
        await db.execute(
            select(PortForward.id, PortForward.domain).where(
                PortForward.attachment_id.in_(att_ids),
                PortForward.service_kind == "http",
                PortForward.domain.is_not(None),
            )
        )
    ).all()
    return {str(domain): pf_id for pf_id, domain in rows if domain}


def _service_target(service: Any) -> tuple[str | None, str | None, int | None, str]:
    if not isinstance(service, dict):
        return None, None, None, "http"
    lb = service.get("loadBalancer")
    if not isinstance(lb, dict):
        return None, None, None, "http"
    servers = lb.get("servers")
    if not isinstance(servers, list) or not servers:
        return None, None, None, "http"
    first = servers[0]
    if not isinstance(first, dict):
        return None, None, None, "http"
    url = first.get("url")
    if not isinstance(url, str):
        return None, None, None, "http"
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return url, None, None, parsed.scheme or "http"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return url, parsed.hostname, port, parsed.scheme


def _extract_hosts(rule: str) -> list[str]:
    out: list[str] = []
    for match in HOST_RE.finditer(rule):
        out.extend(QUOTED_HOST_RE.findall(match.group("args")))
    return _dedupe(out)


def _clean_ref(value: str) -> str:
    value = value.strip()
    if value.endswith("@file"):
        return value[:-5]
    return value


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def _deep_merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _deep_merge(dst[key], value)
        else:
            dst[key] = value

"""Resolve stored policies without changing desired state during rendering."""
from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlsplit
import uuid

from sqlalchemy import select
from fastapi import HTTPException

from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_profile import EdgeProfile
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.services.edge_resources import GLOBAL_EDGE_DEFAULTS, deep_merge


async def validate_edge_configuration(agent_id, db):
    """Validate the complete pending configuration before a resource is committed."""
    from app.services.edge_ops import build_edge_desired_state
    try:
        return await build_edge_desired_state(agent_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "edge_policy_invalid", "detail": str(exc)}) from exc


async def effective_render_policy(db, route, ec, path=None):
    node = await db.get(EdgeNodePolicy, route.agent_id)
    if ec is not None and not getattr(ec, "inherit_node_policy", True):
        node = None
    profile_id = ec.profile_id if ec and ec.profile_id else node.default_profile_id if node else None
    profile = await db.get(EdgeProfile, profile_id) if profile_id else None
    if profile_id and (profile is None or profile.agent_id not in (None, route.agent_id)):
        raise ValueError("Edge profile must exist and belong to this node or be global")
    legacy = {}
    if ec is not None and not ec.policy_json:
        legacy = {key: getattr(ec, key) for key in (
            "waf_mode", "antibot", "ip_allow", "ip_deny", "geo_block", "auth_mode",
            "auth_config", "tls_source", "upstream_scheme", "upstream_insecure_skip_verify",
        ) if getattr(ec, key, None) is not None}
        if ec.rate_limit_rps:
            legacy["rate_limit"] = {"requests": ec.rate_limit_rps, "burst": ec.rate_limit_burst}
        legacy["tls"] = {"mode": legacy.pop("tls_source", "letsencrypt")}
        legacy["origin"] = {"scheme": legacy.pop("upstream_scheme", "http"),
                            "insecure_skip_verify": legacy.pop("upstream_insecure_skip_verify", False)}
        legacy["access"] = {key: legacy.pop(key) for key in (
            "ip_allow", "ip_deny", "geo_block", "auth_mode", "auth_config"
        ) if key in legacy}
    return deep_merge(GLOBAL_EDGE_DEFAULTS, legacy, node.policy_json if node else {},
                      profile.policy_json if profile else {}, ec.policy_json if ec else {},
                      path.policy_json if path else {})


def policy_edge_config(policy):
    access = policy.get("access") or {}
    origin = policy.get("origin") or {}
    tls = policy.get("tls") or {}
    rate = policy.get("rate_limit") or {}
    return SimpleNamespace(
        policy_json=policy, waf_mode=policy.get("waf_mode", "off"),
        antibot=policy.get("antibot", False), rate_limit_rps=rate.get("requests", rate.get("average", policy.get("rate_limit_rps"))),
        rate_limit_burst=rate.get("burst", policy.get("rate_limit_burst")),
        ip_allow=access.get("ip_allow", policy.get("ip_allow")),
        ip_deny=access.get("ip_deny", policy.get("ip_deny")),
        geo_block=access.get("geo_block", policy.get("geo_block")),
        auth_mode=access.get("auth_mode", policy.get("auth_mode", "none")),
        auth_config=access.get("auth_config", policy.get("auth_config")),
        tls_source=policy.get("tls_source", tls.get("mode", "letsencrypt")),
        upstream_scheme=origin.get("scheme", policy.get("upstream_scheme", "http")),
        upstream_insecure_skip_verify=origin.get("insecure_skip_verify", policy.get("upstream_insecure_skip_verify", False)),
    )


def path_match(match):
    if "type" in match or "value" in match:
        kind = {"prefix": "path_prefix", "exact": "path", "regex": "path_regexp"}.get(match.get("type"))
        if not kind or set(match) != {"type", "value"}:
            raise ValueError("Unsupported Edge path match type")
        match = {kind: match["value"]}
    allowed = {"path", "path_prefix", "path_regexp", "method", "headers", "query"}
    if not match or set(match) - allowed:
        raise ValueError("Unsupported or empty Edge path match")
    terms = []
    def quoted(value):
        text = str(value)
        if "`" in text or any(ord(c) < 32 for c in text):
            raise ValueError("Invalid Edge matcher value")
        return f"`{text}`"
    for key, matcher in (("path", "Path"), ("path_prefix", "PathPrefix"), ("path_regexp", "PathRegexp"), ("method", "Method")):
        if key in match:
            terms.append(f"{matcher}({quoted(match[key])})")
    for key, matcher in (("headers", "Header"), ("query", "Query")):
        for name, value in (match.get(key) or {}).items():
            terms.append(f"{matcher}({quoted(name)}, {quoted(value)})")
    return " && ".join(terms)


def fragment_content(fragment, fragments):
    """Namespace dependencies and reject references outside this node or route."""
    from copy import deepcopy
    content = deepcopy(fragment.content)
    allowed = {
        "middleware": {"addPrefix", "basicAuth", "buffering", "chain", "circuitBreaker", "compress", "contentType", "digestAuth", "errors", "forwardAuth", "grpcWeb", "headers", "inFlightReq", "ipAllowList", "ipWhiteList", "passTLSClientCert", "plugin", "rateLimit", "redirectRegex", "redirectScheme", "replacePath", "replacePathRegex", "retry", "stripPrefix", "stripPrefixRegex"},
        "service": {"loadBalancer", "weighted", "mirroring", "failover"},
        "router": {"rule", "ruleSyntax", "entryPoints", "service", "middlewares", "priority", "tls", "observability"},
        "transport": {"serverName", "insecureSkipVerify", "rootCAs", "certificates", "maxIdleConnsPerHost", "forwardingTimeouts", "disableHTTP2", "peerCertURI", "spiffe"},
        "tls": {"certificates", "options", "stores"},
    }
    if not content or set(content) - allowed.get(fragment.fragment_type, set()):
        raise ValueError("Unsupported Edge fragment content")
    def resolve(ref, kind):
        target = next((item for item in fragments if item.name == ref and item.fragment_type == kind), None)
        if target is None or target.route_id not in (None, fragment.route_id):
            raise ValueError("Fragment dependency must belong to this node and route")
        return f"fragment-{target.id}"
    def visit(value):
        if isinstance(value, dict):
            for key, child in list(value.items()):
                if key == "service" and isinstance(child, str):
                    value[key] = resolve(child, "service")
                elif key == "serversTransport" and isinstance(child, str):
                    value[key] = resolve(child, "transport")
                elif key == "middlewares" and isinstance(child, list):
                    value[key] = [resolve(ref, "middleware") for ref in child]
                elif key == "services" and isinstance(child, list):
                    for item in child:
                        if "name" in item:
                            item["name"] = resolve(item["name"], "service")
                    visit(child)
                else:
                    visit(child)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(content)
    return content


async def render_variants(db, routes):
    variants = []
    for route in routes:
        ec = route.edge_route_config
        policy = await effective_render_policy(db, route, ec)
        validate_render_policy(policy)
        variants.append((route, ec, None, policy))
        paths = (await db.scalars(select(EdgePathRule).where(
            EdgePathRule.route_id == route.id, EdgePathRule.enabled.is_(True)
        ).order_by(EdgePathRule.id))).all()
        for path in paths:
            path_match(path.match)
            effective = await effective_render_policy(db, route, ec, path)
            validate_render_policy(effective)
            variants.append((route, ec, path, effective))
    return variants


def validate_render_policy(policy):
    allowed = {"waf_mode", "rate_limit", "rate_limit_rps", "rate_limit_burst", "antibot",
               "ip_allow", "ip_deny", "geo_block", "auth_mode", "auth_config", "access",
               "tls", "tls_source", "redirect_https", "hsts", "origin", "upstream_scheme",
               "upstream_insecure_skip_verify", "upstream_pool_id", "upstream_timeout", "retry_attempts",
               "headers", "request_transforms", "response_transforms", "cache", "middlewares"}
    unknown = set(policy) - allowed
    if unknown:
        raise ValueError(f"Unsupported Edge policy fields: {', '.join(sorted(unknown))}")
    nested = {
        "access": {"ip_allow", "ip_deny", "geo_block", "auth_mode", "auth_config"},
        "origin": {"scheme", "insecure_skip_verify", "upstream_pool_id", "service", "timeout", "retry_attempts"},
        "tls": {"mode"},
        "rate_limit": {"requests", "average", "burst"},
    }
    for key, fields in nested.items():
        value = policy.get(key)
        if value is not None and (not isinstance(value, dict) or set(value) - fields):
            raise ValueError(f"Unsupported Edge {key} policy fields")
    if policy.get("redirect_https") is False:
        raise ValueError("Managed Edge routes require HTTPS")


async def validate_path_cache(db, route, ec, policy):
    root = await effective_render_policy(db, route, ec)
    keys = ("cache", "origin", "upstream_scheme", "upstream_insecure_skip_verify", "upstream_pool_id")
    if any(policy.get(key) != root.get(key) for key in keys):
        raise ValueError("Path-specific backend cache requires path-aware cache support")


async def origin_load_balancer(db, route, policy, ec):
    origin = policy.get("origin") or {}
    pool_id = origin.get("upstream_pool_id", policy.get("upstream_pool_id"))
    lb = {"servers": [{"url": f"{ec.upstream_scheme}://{route.destination_ip}:{route.destination_port}"}]}
    if pool_id:
        pool = await db.get(EdgeUpstreamPool, uuid.UUID(str(pool_id)))
        if pool is None or pool.agent_id != route.agent_id:
            raise ValueError("Upstream pool must belong to this Edge node")
        if not pool.servers:
            raise ValueError("Upstream pool requires at least one server")
        servers = []
        for server in pool.servers:
            if set(server) - {"url", "preservePath"}:
                raise ValueError("Unsupported upstream server fields")
            parsed = urlsplit(server.get("url", ""))
            if parsed.scheme not in {"http", "https", "h2c"} or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Invalid upstream server URL")
            servers.append(dict(server))
        lb["servers"] = servers
        if pool.health_check:
            lb["healthCheck"] = dict(pool.health_check)
        if set(pool.policy_json or {}) - {"passHostHeader", "sticky", "responseForwarding"}:
            raise ValueError("Unsupported upstream pool policy fields")
        lb.update(pool.policy_json or {})
    return lb

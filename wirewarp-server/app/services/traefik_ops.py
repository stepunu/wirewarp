"""Traefik install + dynamic-config rendering.

The server owns the Traefik config schema; the agent is a dumb writer
that takes the rendered dict and writes it verbatim as YAML to
/etc/traefik/dynamic/wirewarp.yml, then reloads Traefik. This mirrors
how writeWhitelist works for CrowdSec.

Key functions:
  build_traefik_static_config  - static config dict for traefik_install
  build_traefik_dynamic_config - dynamic config dict for traefik_sync_config
  dispatch_traefik_sync        - build + send traefik_sync_config to an agent
"""
from __future__ import annotations

from dataclasses import dataclass
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.system_settings import SystemSettings
from app.models.edge_fragment import EdgeFragment
from app.services.edge_render import render_variants, policy_edge_config, path_match, origin_load_balancer, fragment_content, validate_path_cache
from app.services.edge_ownership import get_edge_owner, load_http_routes, route_entrypoints
from app.services.edge_cache_ops import (
    load_node_cache_policy,
    nginx_cache_service_url,
    nginx_cache_backend_available,
    route_uses_nginx_cache,
)
from app.services.secrets import get_captcha_secret_key, get_letsencrypt_cloudflare_api_token, get_letsencrypt_rfc2136_tsig_secret


LE_STAGING_CA_SERVER = "https://acme-staging-v02.api.letsencrypt.org/directory"
PINNED_TRAEFIK_UNSUPPORTED_FORWARDAUTH_KEYS = {"maxResponseBodySize"}


@dataclass(frozen=True)
class LetsEncryptConfig:
    enabled: bool = False
    email: str | None = None
    challenge: str = "dns-01"
    dns_provider: str | None = "cloudflare"
    dns_resolvers: list[str] | None = None
    use_staging: bool = False
    credentials_ready: bool = False
    dns_delay_seconds: int = 30

    @property
    def complete(self) -> bool:
        if not self.enabled or not self.email:
            return False
        if self.challenge == "dns-01":
            return self.dns_provider in {"cloudflare", "rfc2136"} and self.credentials_ready
        return self.challenge in {"tls-alpn-01", "http-01"}


def letsencrypt_from_settings(
    settings: SystemSettings | None,
    *,
    credentials_ready: bool = False,
) -> LetsEncryptConfig:
    if settings is None:
        return LetsEncryptConfig()
    resolvers = getattr(settings, "letsencrypt_dns_resolvers", None) or ["1.1.1.1:53"]
    return LetsEncryptConfig(
        enabled=bool(getattr(settings, "letsencrypt_enabled", False)),
        email=getattr(settings, "letsencrypt_email", None),
        challenge=getattr(settings, "letsencrypt_challenge", None) or "dns-01",
        dns_provider=getattr(settings, "letsencrypt_dns_provider", None) or "cloudflare",
        dns_resolvers=[str(v) for v in resolvers if str(v).strip()],
        use_staging=bool(getattr(settings, "letsencrypt_use_staging", False)),
        credentials_ready=credentials_ready,
        dns_delay_seconds=getattr(settings, "letsencrypt_dns_delay_seconds", 30),
    )


async def load_letsencrypt_config(db: AsyncSession) -> LetsEncryptConfig:
    row = await db.get(SystemSettings, 1)
    if row and row.letsencrypt_dns_provider == "rfc2136":
        ready = bool(
            row.letsencrypt_rfc2136_nameserver
            and row.letsencrypt_rfc2136_tsig_key
            and row.letsencrypt_rfc2136_tsig_algorithm
            and await get_letsencrypt_rfc2136_tsig_secret(db)
        )
    else:
        ready = bool(await get_letsencrypt_cloudflare_api_token(db))
    return letsencrypt_from_settings(
        row,
        credentials_ready=ready,
    )


async def letsencrypt_resolver_ready(db: AsyncSession) -> bool:
    return (await load_letsencrypt_config(db)).complete


def _render_forward_auth_config(config: dict) -> dict:
    return {
        key: value
        for key, value in config.items()
        if key not in PINNED_TRAEFIK_UNSUPPORTED_FORWARDAUTH_KEYS
    }


def _normalise_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    cleaned = domain.strip().strip(".").lower()
    if not cleaned or "`" in cleaned or "/" in cleaned:
        return None
    return cleaned


def _wildcard_cert_domain_for_host(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    return "*." + ".".join(labels[1:])


def _domain_sort_key(domain: str) -> tuple[int, int, str]:
    # Prefer exact names as the certificate main domain, then broader wildcards.
    return (domain.startswith("*."), domain.count("."), domain)


def _build_default_generated_cert_domain(domains: list[str]) -> dict | None:
    cert_domains = {
        _wildcard_cert_domain_for_host(domain)
        for raw in domains
        if (domain := _normalise_domain(raw))
    }
    if not cert_domains:
        return None
    ordered = sorted(cert_domains, key=_domain_sort_key)
    domain_cfg: dict = {"main": ordered[0]}
    if len(ordered) > 1:
        domain_cfg["sans"] = ordered[1:]
    return domain_cfg


def build_traefik_static_config(
    le_email: str | None = None,
    letsencrypt: LetsEncryptConfig | None = None,
    version: str | None = None,
) -> dict:
    """Build the Traefik static configuration dict.

    The agent writes this verbatim as /etc/traefik/traefik.yml. The
    file-provider watches /etc/traefik/dynamic/ so the server can push
    dynamic config separately without a full Traefik restart.

    `letsencrypt` enables managed ACME TLS when all required fields are
    present. The legacy `le_email` argument is kept for older install
    callers and renders the previous TLS-ALPN resolver shape.
    """
    cfg: dict = {
        "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
        "log": {"level": "INFO"},
        "accessLog": {
            "format": "json",
            "fields": {
                "defaultMode": "keep",
                "headers": {
                    "defaultMode": "drop",
                },
            },
        },
        "api": {"dashboard": False},
        "entryPoints": {
            "web": {
                "address": ":80",
                "http": {
                    "redirections": {
                        "entryPoint": {"to": "websecure", "scheme": "https"}
                    }
                },
            },
            "websecure": {"address": ":443"},
        },
        "providers": {
            "file": {
                "directory": "/etc/traefik/dynamic",
                "watch": True,
            }
        },
        # CrowdSec bouncer plugin — loaded here so it's available for every
        # dynamic config that references it. The plugin itself is installed
        # by the agent via 'traefik install --plugin'.
        "experimental": {
            "plugins": {
                "bouncer": {
                    "moduleName": "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin",
                    "version": "v1.4.5",
                },
                "denyip": {
                    "moduleName": "github.com/kvncrw/denyip",
                    "version": "v1.3.0",
                },
                "geoblock": {
                    "moduleName": "github.com/nscuro/traefik-plugin-geoblock",
                    "version": "v0.14.0",
                },
            }
        },
    }

    if letsencrypt and letsencrypt.complete:
        acme: dict = {
            "email": letsencrypt.email,
            "storage": "/etc/traefik/acme.json",
        }
        if letsencrypt.use_staging:
            acme["caServer"] = LE_STAGING_CA_SERVER
        if letsencrypt.challenge == "dns-01":
            acme["dnsChallenge"] = {
                # The pinned RFC2136 provider replaces sibling TXT values.
                "provider": "exec" if letsencrypt.dns_provider == "rfc2136" else letsencrypt.dns_provider,
                "resolvers": letsencrypt.dns_resolvers or ["1.1.1.1:53"],
            }
            if letsencrypt.dns_provider == "rfc2136":
                acme["dnsChallenge"]["delayBeforeCheck"] = letsencrypt.dns_delay_seconds
        elif letsencrypt.challenge == "http-01":
            acme["httpChallenge"] = {"entryPoint": "web"}
        else:
            acme["tlsChallenge"] = {}
        cfg["certificatesResolvers"] = {"wirewarp-le": {"acme": acme}}
    elif le_email:
        cfg["certificatesResolvers"] = {
            "wirewarp-le": {
                "acme": {
                    "email": le_email,
                    "storage": "/etc/traefik/acme.json",
                    "tlsChallenge": {},
                }
            }
        }

    return cfg


async def build_traefik_dynamic_config(
    server_agent_id: uuid.UUID | str,
    db: AsyncSession,
) -> dict:
    """Render owned HTTP routes and their policies for a server or gateway."""
    server = await get_edge_owner(db, server_agent_id)
    http_forwards = await load_http_routes(db, server_agent_id, active_only=True)

    variants = await render_variants(db, http_forwards)
    routes_with_paths = {route.id for route, _, path, _ in variants if path is not None}
    has_antibot = any(policy.get("antibot") for _, _, _, policy in variants)

    routers: dict = {}
    services: dict = {}
    middlewares: dict = {}
    from app.services.edge_ownership import is_gateway_edge
    gateway = await is_gateway_edge(db, server_agent_id)
    if gateway:
        middlewares["wirewarp-strip-forwarded"] = {"headers": {"customRequestHeaders": {"Forwarded": ""}}}
    servers_transports: dict = {}
    acme_ready = await letsencrypt_resolver_ready(db)
    node_cache_policy = await load_node_cache_policy(server_agent_id, db)
    cache_backend_available = await nginx_cache_backend_available(server_agent_id, db)
    letsencrypt_domains: list[str] = []
    letsencrypt_router_names: list[str] = []
    server_rate_limit = None
    if server.edge_rate_limit_rps:
        server_burst = server.edge_rate_limit_burst or server.edge_rate_limit_rps * 5
        server_rate_limit = {
            "average": server.edge_rate_limit_rps,
            "burst": server_burst,
        }
        middlewares["server-ratelimit"] = {"rateLimit": server_rate_limit}

    captcha: dict = {}
    if has_antibot:
        settings = await db.get(SystemSettings, 1)
        secret = await get_captcha_secret_key(db)
        if settings and settings.captcha_provider and settings.captcha_site_key and secret:
            captcha = {
                "captchaProvider": settings.captcha_provider,
                "captchaSiteKey": settings.captcha_site_key,
                "captchaSecretKey": secret,
                "captchaGracePeriodSeconds": 1800,
                "captchaHTMLFilePath": "/etc/traefik/captcha.html",
            }

    fragments = (await db.scalars(select(EdgeFragment).where(
        EdgeFragment.agent_id == server_agent_id, EdgeFragment.enabled.is_(True),
        EdgeFragment.validation_state == "valid",
    ))).all()
    fragment_names = {}
    tls_fragments = {}
    for fragment in fragments:
        if gateway and fragment.fragment_type in {"router", "tls"}:
            raise ValueError("Gateway fragments cannot create routers or TLS listeners")
        if fragment.fragment_type == "tls":
            tls_fragments.update(fragment_content(fragment, fragments))
            continue
        collection = {"middleware": middlewares, "service": services, "router": routers,
                      "transport": servers_transports}.get(fragment.fragment_type)
        if collection is None:
            raise ValueError("Unsupported Edge fragment type")
        if fragment.fragment_type in {"middleware", "service"} and any(
            key in fragment.content for key in ("routers", "entryPoints", "tls", "http", "tcp", "udp")
        ):
            raise ValueError("Edge fragment cannot inject listeners or routers")
        name = f"fragment-{fragment.id}"
        collection[name] = fragment_content(fragment, fragments)
        fragment_names[fragment.name] = (name, fragment)

    for pf, stored_ec, path, policy in variants:
        pf_id = str(pf.id)
        # Sanitise: replace dots/colons in domain for Traefik router name
        safe_name = (pf.domain or pf_id).replace(".", "-").replace(":", "-")
        if path:
            safe_name += f"-path-{path.id}"
        ec = policy_edge_config(policy)

        router_middlewares: list[str] = []
        if server_rate_limit:
            router_middlewares.append("server-ratelimit")

        # Rate limiting middleware
        if ec and ec.rate_limit_rps:
            mw_name = f"ratelimit-{safe_name}"
            burst = ec.rate_limit_burst or ec.rate_limit_rps * 5
            middlewares[mw_name] = {
                "rateLimit": {
                    "average": ec.rate_limit_rps,
                    "burst": burst,
                }
            }
            router_middlewares.append(mw_name)

        # IP allowlist middleware
        if ec and ec.ip_allow:
            mw_name = f"ipallow-{safe_name}"
            middlewares[mw_name] = {
                "ipAllowList": {"sourceRange": ec.ip_allow}
            }
            router_middlewares.append(mw_name)

        if ec and ec.ip_deny:
            mw_name = f"ipdeny-{safe_name}"
            middlewares[mw_name] = {
                "plugin": {"denyip": {"ipDenyList": ec.ip_deny}}
            }
            router_middlewares.append(mw_name)

        if ec and ec.geo_block:
            mw_name = f"geoblock-{safe_name}"
            middlewares[mw_name] = {
                "plugin": {
                    "geoblock": {
                        "enabled": True,
                        "blockedCountries": ec.geo_block,
                        "defaultAllow": True,
                        "allowPrivate": True,
                        "disallowedStatusCode": 403,
                    }
                }
            }
            router_middlewares.append(mw_name)

        # WAF / CrowdSec bouncer
        if ec and (ec.waf_mode != "off" or ec.antibot):
            if ec.waf_mode not in {"off", "observe", "block"}:
                raise ValueError("Unsupported WAF mode")
            mw_name = "crowdsec-bouncer" if ec.waf_mode == "block" and not ec.antibot else f"crowdsec-{ec.waf_mode}-{'antibot' if ec.antibot else 'waf'}"
            observer = ec.waf_mode == "observe"
            bouncer_cfg = {
                "enabled": True, "crowdsecMode": "appsec" if observer else "stream",
                "crowdsecLapiScheme": "http", "crowdsecLapiHost": "localhost:8080",
                "crowdsecLapiKey": "${WIREWARP_CROWDSEC_BOUNCER_KEY}", "httpTimeoutSeconds": 60,
                "crowdsecAppsecEnabled": ec.waf_mode != "off",
                "crowdsecAppsecHost": "127.0.0.1:7423" if observer else "127.0.0.1:7422",
                "crowdsecAppsecFailureBlock": ec.waf_mode == "block",
                "crowdsecAppsecUnreachableBlock": False,
            }
            if ec.antibot and not observer:
                bouncer_cfg.update(captcha)
            middlewares[mw_name] = {"plugin": {"bouncer": bouncer_cfg}}
            router_middlewares.append(mw_name)
            if observer and ec.antibot:
                bot_cfg = {**bouncer_cfg, **captcha, "crowdsecMode": "stream", "crowdsecAppsecEnabled": False}
                middlewares["crowdsec-antibot"] = {"plugin": {"bouncer": bot_cfg}}
                router_middlewares.append("crowdsec-antibot")

        headers = dict(policy.get("headers") or {})
        if "hsts" in headers:
            hsts = headers.pop("hsts")
            headers["stsSeconds"] = 31536000 if hsts is True else 0 if hsts is False else int(hsts)
        for field, target in (("request_transforms", "customRequestHeaders"), ("response_transforms", "customResponseHeaders")):
            if policy.get(field):
                headers[target] = {**headers.get(target, {}), **policy[field]}
        if policy.get("hsts"):
            headers["stsSeconds"] = int(policy["hsts"]) if not isinstance(policy["hsts"], bool) else 31536000
        cache = policy.get("cache") or {}
        if cache.get("mode") == "headers_only" or cache.get("mode") != "off" and cache.get("browser_ttl_seconds") is not None:
            ttl = int(cache.get("browser_ttl_seconds") or 0)
            headers.setdefault("customResponseHeaders", {})["Cache-Control"] = f"public, max-age={ttl}"
        if headers:
            mw_name = f"headers-{safe_name}"
            middlewares[mw_name] = {"headers": headers}
            router_middlewares.append(mw_name)
        for ref in policy.get("middlewares", []):
            named = fragment_names.get(ref)
            if not named or named[1].fragment_type != "middleware" or named[1].route_id not in (None, pf.id):
                raise ValueError("Middleware fragment must belong to this route or node")
            router_middlewares.append(named[0])
        for name, fragment in fragment_names.values():
            if fragment.fragment_type == "middleware" and fragment.route_id == pf.id and name not in router_middlewares:
                router_middlewares.append(name)

        # Basic auth
        if ec and ec.auth_mode == "basic" and ec.auth_config:
            mw_name = f"basicauth-{safe_name}"
            middlewares[mw_name] = {"basicAuth": ec.auth_config}
            router_middlewares.append(mw_name)

        # Forward auth
        if ec and ec.auth_mode == "forward" and ec.auth_config:
            mw_name = f"forwardauth-{safe_name}"
            middlewares[mw_name] = {"forwardAuth": _render_forward_auth_config(ec.auth_config)}
            router_middlewares.append(mw_name)

        # Router rule: Host header match or catch-all
        if pf.domain:
            rule = f"Host(`{pf.domain}`)"
        else:
            rule = f"PathPrefix(`/`)"
        if path:
            rule += f" && ({path_match(path.match)})"

        # TLS config
        tls_source = ec.tls_source if ec else "letsencrypt"
        tls_cfg: dict = {}
        if tls_source == "letsencrypt" and acme_ready:
            if pf.domain:
                letsencrypt_domains.append(pf.domain)
                letsencrypt_router_names.append(safe_name)

        routers[safe_name] = {
            "rule": rule,
            "service": f"svc-{safe_name}",
            "entryPoints": await route_entrypoints(db, pf),
            "tls": tls_cfg,
            **({"priority": path.priority or 10000} if path else {"priority": stored_ec.priority} if stored_ec and stored_ec.priority else {"priority": 1} if pf.id in routes_with_paths else {}),
            **({"middlewares": router_middlewares} if router_middlewares else {}),
        }

        # Validate origin ownership even while a cache backend serves this route.
        lb = await origin_load_balancer(db, pf, policy, ec)
        if path and route_uses_nginx_cache(node_cache_policy, ec):
            await validate_path_cache(db, pf, stored_ec, policy)
        if pf.domain and cache_backend_available and route_uses_nginx_cache(node_cache_policy, ec):
            origin = policy.get("origin") or {}
            if origin.get("upstream_pool_id", policy.get("upstream_pool_id")) or origin.get("service"):
                raise ValueError("Backend cache requires a single managed origin")
            lb = {
                "servers": [
                    {"url": nginx_cache_service_url(node_cache_policy)}
                ]
            }
            services[f"svc-{safe_name}"] = {"loadBalancer": lb}
            continue

        if ec and ec.upstream_insecure_skip_verify:
            servers_transports["wirewarp-insecure-skip-verify"] = {
                "insecureSkipVerify": True
            }
            lb["serversTransport"] = "wirewarp-insecure-skip-verify"

        services[f"svc-{safe_name}"] = {"loadBalancer": lb}
        origin = policy.get("origin") or {}
        if origin.get("timeout", policy.get("upstream_timeout")):
            transport = f"transport-{safe_name}"
            timeout = origin.get("timeout", policy.get("upstream_timeout"))
            servers_transports[transport] = {"insecureSkipVerify": bool(ec.upstream_insecure_skip_verify), "forwardingTimeouts": {"responseHeaderTimeout": str(timeout)}}
            lb["serversTransport"] = transport
        retry = origin.get("retry_attempts", policy.get("retry_attempts"))
        if retry:
            name = f"retry-{safe_name}"
            middlewares[name] = {"retry": {"attempts": int(retry)}}
            routers[safe_name].setdefault("middlewares", []).append(name)
        ref = origin.get("service")
        candidates = [value for value in fragment_names.values() if value[1].fragment_type == "service" and value[1].route_id == pf.id]
        if ref:
            selected = fragment_names.get(ref)
            if not selected or selected[1].fragment_type != "service" or selected[1].route_id not in (None, pf.id):
                raise ValueError("Service fragment must belong to this route or node")
            candidates = [selected]
        if len(candidates) > 1:
            raise ValueError("Route requires an explicit service fragment selection")
        if candidates:
            routers[safe_name]["service"] = candidates[0][0]

    cert_domain = _build_default_generated_cert_domain(letsencrypt_domains)
    if cert_domain:
        routers[letsencrypt_router_names[0]]["tls"] = {
            "certResolver": "wirewarp-le",
            "domains": [cert_domain],
        }

    result = _build_http_config(routers, services, middlewares, servers_transports)
    if tls_fragments:
        result["tls"] = tls_fragments
    return result


def _build_http_config(
    routers: dict,
    services: dict,
    middlewares: dict,
    servers_transports: dict | None = None,
) -> dict:
    servers_transports = servers_transports or {}
    if not routers and not services and not middlewares and not servers_transports:
        return {}
    http = {}
    if routers:
        http["routers"] = routers
    if services:
        http["services"] = services
    if middlewares:
        http["middlewares"] = middlewares
    if servers_transports:
        http["serversTransports"] = servers_transports
    return {"http": http}


async def dispatch_traefik_sync(
    agent_id: str,
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str]:
    """Build and dispatch traefik_sync_config to the given agent.

    Returns (sent, command_id). Not sent when agent is offline — the
    agent's heal loop re-asserts from disk on reconnect.
    """
    from app.services.agent_commands import send_command

    dynamic = await build_traefik_dynamic_config(agent_id, db)
    return await send_command(
        agent_id=agent_id,
        command_type="traefik_sync_config",
        params={"dynamic_config": dynamic},
        db=db,
        actor_user_id=actor_user_id,
    )

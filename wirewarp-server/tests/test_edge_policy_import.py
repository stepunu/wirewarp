from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.edge_route_config import EdgeRouteConfig
from app.models.port_forward import PortForward
from app.models.security_event import SecurityEvent
from app.models.system_settings import SystemSettings
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.services.secrets import encrypt_secret
from app.services.traefik_ops import build_traefik_dynamic_config


def _agent(agent_type: str, name: str) -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name=name,
        type=agent_type,
        hostname=f"{name}.example",
        status="connected",
        last_seen=datetime.now(timezone.utc),
    )


async def _server_with_attachment(session_maker):
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(
            id=uuid.uuid4(),
            agent_id=server_agent.id,
            tunnel_network="10.21.0.0/24",
        )
        gateway = TunnelClient(
            id=uuid.uuid4(),
            agent_id=gateway_agent.id,
            is_gateway=True,
            vm_network="192.168.20.0/24",
        )
        s.add_all([server, gateway])
        await s.commit()
        attachment = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=gateway.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        s.add(attachment)
        await s.commit()
        return server_agent.id, server.id, attachment.id


TRAEFIK_DYNAMIC = """
http:
  middlewares:
    internal-only:
      ipAllowList:
        sourceRange:
          - "192.168.0.0/16"
          - "10.100.0.0/24"
    secured:
      chain:
        middlewares:
          - internal-only@file
          - default-headers@file
    default-headers:
      headers:
        contentTypeNosniff: true
  serversTransports:
    insecureSkipVerify:
      insecureSkipVerify: true
  routers:
    jellyfin:
      entryPoints: [websecure]
      rule: "Host(`media.{{ domain }}`)"
      middlewares: [secured]
      service: jellyfin
      tls:
        certResolver: cloudflare
    proxmox:
      entryPoints: [websecure]
      rule: "Host(`px.infra.{{ domain }}`)"
      middlewares: [secured]
      service: proxmox
      tls:
        certResolver: cloudflare
  services:
    jellyfin:
      loadBalancer:
        servers:
          - url: "http://192.168.20.151:8096"
        passHostHeader: true
    proxmox:
      loadBalancer:
        servers:
          - url: "https://192.168.20.11:8006"
        passHostHeader: true
        serversTransport: insecureSkipVerify
"""


TRAEFIK_EXTERNAL_ONLY = """
http:
  serversTransports:
    insecureSkipVerify:
      insecureSkipVerify: true
  routers:
    proxmox:
      entryPoints: [websecure]
      rule: "Host(`px.infra.{{ domain }}`)"
      middlewares: [secured]
      service: proxmox
      tls:
        certResolver: cloudflare
  services:
    proxmox:
      loadBalancer:
        servers:
          - url: "https://192.168.20.11:8006"
        passHostHeader: true
        serversTransport: insecureSkipVerify
"""


TRAEFIK_MIDDLEWARES_ONLY = """
http:
  middlewares:
    internal-only:
      ipAllowList:
        sourceRange:
          - "192.168.0.0/16"
          - "10.100.0.0/24"
    default-headers:
      headers:
        contentTypeNosniff: true
    secured:
      chain:
        middlewares:
          - internal-only@file
          - default-headers@file
"""


@pytest.mark.asyncio
async def test_traefik_import_preview_maps_routes_and_middleware_policy(
    client,
    session_maker,
) -> None:
    _agent_id, server_id, attachment_id = await _server_with_attachment(session_maker)

    resp = await client.post(
        "/api/security/traefik/import/preview",
        json={
            "server_id": str(server_id),
            "attachment_id": str(attachment_id),
            "content": TRAEFIK_DYNAMIC,
            "domain_suffix": "ww.step1.ro",
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["importable"] == 2
    media = next(route for route in body["routes"] if route["router_name"] == "jellyfin")
    assert media["domain"] == "media.ww.step1.ro"
    assert media["destination_ip"] == "192.168.20.151"
    assert media["destination_port"] == 8096
    assert media["upstream_scheme"] == "http"
    assert media["mapped_policy"]["ip_allow"] == ["192.168.0.0/16", "10.100.0.0/24"]
    assert any("default-headers" in warning for warning in media["warnings"])

    proxmox = next(route for route in body["routes"] if route["router_name"] == "proxmox")
    assert proxmox["upstream_scheme"] == "https"
    assert proxmox["upstream_insecure_skip_verify"] is True


@pytest.mark.asyncio
async def test_traefik_import_preview_accepts_separate_middlewares_file(
    client,
    session_maker,
) -> None:
    _agent_id, server_id, attachment_id = await _server_with_attachment(session_maker)

    resp = await client.post(
        "/api/security/traefik/import/preview",
        json={
            "server_id": str(server_id),
            "attachment_id": str(attachment_id),
            "content": TRAEFIK_EXTERNAL_ONLY,
            "middlewares_content": TRAEFIK_MIDDLEWARES_ONLY,
            "domain_suffix": "ww.step1.ro",
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["importable"] == 1
    route = body["routes"][0]
    assert route["domain"] == "px.infra.ww.step1.ro"
    assert route["mapped_policy"]["ip_allow"] == ["192.168.0.0/16", "10.100.0.0/24"]
    assert any("default-headers" in warning for warning in route["warnings"])


@pytest.mark.asyncio
async def test_traefik_import_apply_creates_wirewarp_owned_sites_and_dispatches(
    client,
    session_maker,
    fake_manager,
) -> None:
    agent_id, server_id, attachment_id = await _server_with_attachment(session_maker)
    fake_manager.online.add(str(agent_id))

    resp = await client.post(
        "/api/security/traefik/import",
        json={
            "server_id": str(server_id),
            "attachment_id": str(attachment_id),
            "content": TRAEFIK_DYNAMIC,
            "domain_suffix": "ww.step1.ro",
            "activate": True,
        },
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["created"] == 2
    assert body["updated"] == 0
    assert body["skipped"] == 0

    async with session_maker() as s:
        rows = (
            await s.execute(
                select(PortForward)
                .where(PortForward.service_kind == "http")
                .order_by(PortForward.domain)
            )
        ).scalars().all()
        assert [row.domain for row in rows] == ["media.ww.step1.ro", "px.infra.ww.step1.ro"]
        media = rows[0]
        assert media.active is True
        ec = await s.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.port_forward_id == media.id))
        assert ec is not None
        assert ec.waf_mode == "observe"
        assert ec.ip_allow == ["192.168.0.0/16", "10.100.0.0/24"]
        assert ec.imported_router_name == "jellyfin"
        assert ec.imported_service_name == "jellyfin"

    assert fake_manager.sent
    assert fake_manager.sent[-1]["message"]["type"] == "edge_desired_state"


@pytest.mark.asyncio
async def test_server_edge_policy_renders_global_rate_limit_before_site_limit(
    session_maker,
) -> None:
    agent_id, server_id, attachment_id = await _server_with_attachment(session_maker)
    async with session_maker() as s:
        server = await s.get(TunnelServer, server_id)
        assert server is not None
        server.edge_rate_limit_rps = 100
        server.edge_rate_limit_burst = 200
        pf = PortForward(
            id=uuid.uuid4(),
            attachment_id=attachment_id,
            protocol="tcp",
            public_port=443,
            destination_ip="192.168.20.151",
            destination_port=8096,
            service_kind="http",
            domain="media.ww.step1.ro",
            active=True,
        )
        s.add(pf)
        await s.flush()
        s.add(
            EdgeRouteConfig(
                id=uuid.uuid4(),
                port_forward_id=pf.id,
                waf_mode="observe",
                rate_limit_rps=10,
                rate_limit_burst=20,
            )
        )
        await s.commit()

        cfg = await build_traefik_dynamic_config(agent_id, s)

    http = cfg["http"]
    assert http["middlewares"]["server-ratelimit"]["rateLimit"] == {"average": 100, "burst": 200}
    router = http["routers"]["media-ww-step1-ro"]
    assert router["middlewares"][:2] == ["server-ratelimit", "ratelimit-media-ww-step1-ro"]


@pytest.mark.asyncio
async def test_forward_auth_render_strips_unsupported_response_body_limit(
    session_maker,
) -> None:
    agent_id, _server_id, attachment_id = await _server_with_attachment(session_maker)
    async with session_maker() as s:
        pf = PortForward(
            id=uuid.uuid4(),
            attachment_id=attachment_id,
            protocol="tcp",
            public_port=443,
            destination_ip="192.168.20.150",
            destination_port=8989,
            service_kind="http",
            domain="sonarr.home.step1.ro",
            active=True,
        )
        s.add(pf)
        await s.flush()
        s.add(
            EdgeRouteConfig(
                id=uuid.uuid4(),
                port_forward_id=pf.id,
                waf_mode="observe",
                auth_mode="forward",
                auth_config={
                    "address": "http://192.168.20.112:9091/api/verify?rd=https://auth.step1.ro",
                    "trustForwardHeader": True,
                    "authResponseHeaders": ["Remote-User", "Remote-Groups"],
                    "maxResponseBodySize": 4096,
                },
            )
        )
        await s.commit()

        cfg = await build_traefik_dynamic_config(agent_id, s)

    forward_auth = cfg["http"]["middlewares"]["forwardauth-sonarr-home-step1-ro"]["forwardAuth"]
    assert forward_auth == {
        "address": "http://192.168.20.112:9091/api/verify?rd=https://auth.step1.ro",
        "trustForwardHeader": True,
        "authResponseHeaders": ["Remote-User", "Remote-Groups"],
    }


@pytest.mark.asyncio
async def test_letsencrypt_routes_share_default_wildcard_certificate(
    session_maker,
) -> None:
    agent_id, _server_id, attachment_id = await _server_with_attachment(session_maker)
    async with session_maker() as s:
        settings = await s.get(SystemSettings, 1)
        if settings is None:
            settings = SystemSettings(id=1)
            s.add(settings)
        settings.letsencrypt_enabled = True
        settings.letsencrypt_email = "admin@example.com"
        settings.letsencrypt_challenge = "dns-01"
        settings.letsencrypt_dns_provider = "cloudflare"
        settings.letsencrypt_cloudflare_api_token = encrypt_secret("cf-token")

        for domain in (
            "media.step1.ro",
            "wirewarp.step1.ro",
            "px.infra.step1.ro",
            "media.ww.step1.ro",
        ):
            pf = PortForward(
                id=uuid.uuid4(),
                attachment_id=attachment_id,
                protocol="tcp",
                public_port=443,
                destination_ip="192.168.20.151",
                destination_port=8096,
                service_kind="http",
                domain=domain,
                active=True,
            )
            s.add(pf)
            await s.flush()
            s.add(
                EdgeRouteConfig(
                    id=uuid.uuid4(),
                    port_forward_id=pf.id,
                    waf_mode="observe",
                    tls_source="letsencrypt",
                )
            )
        await s.commit()

        cfg = await build_traefik_dynamic_config(agent_id, s)

    tls_configs = [
        router["tls"]
        for router in cfg["http"]["routers"].values()
        if router["tls"].get("certResolver") == "wirewarp-le"
    ]
    assert len(tls_configs) == 1
    assert tls_configs[0]["domains"] == [{
        "main": "*.step1.ro",
        "sans": ["*.infra.step1.ro", "*.ww.step1.ro"],
    }]

    passive_tls = [
        router["tls"]
        for router in cfg["http"]["routers"].values()
        if router["tls"].get("certResolver") != "wirewarp-le"
    ]
    assert passive_tls
    assert all(tls == {} for tls in passive_tls)


@pytest.mark.asyncio
async def test_node_edge_includes_server_policy_and_effective_site_policy(
    client,
    session_maker,
) -> None:
    agent_id, server_id, attachment_id = await _server_with_attachment(session_maker)
    async with session_maker() as s:
        server = await s.get(TunnelServer, server_id)
        assert server is not None
        server.edge_rate_limit_rps = 25
        server.edge_rate_limit_burst = 50
        pf = PortForward(
            id=uuid.uuid4(),
            attachment_id=attachment_id,
            protocol="tcp",
            public_port=443,
            destination_ip="192.168.20.151",
            destination_port=8096,
            service_kind="http",
            domain="media.ww.step1.ro",
            active=True,
        )
        s.add(pf)
        await s.flush()
        s.add(EdgeRouteConfig(id=uuid.uuid4(), port_forward_id=pf.id, waf_mode="observe"))
        await s.commit()

    resp = await client.get(f"/api/nodes/{agent_id}/edge")

    assert resp.status_code == 200
    body = resp.json()
    assert body["policy"]["rate_limit_rps"] == 25
    assert body["policy"]["rate_limit_burst"] == 50
    site = body["sites"][0]
    assert site["effective_policy"]["rate_limit"]["global"]["rps"] == 25
    assert site["effective_policy"]["middleware_chain"][0] == "server-ratelimit"


@pytest.mark.asyncio
async def test_security_event_groups_count_repeated_traefik_events(
    client,
    session_maker,
) -> None:
    agent_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    async with session_maker() as s:
        agent = _agent("server", "edge-1")
        agent.id = agent_id
        s.add(agent)
        await s.flush()
        s.add_all(
            [
                SecurityEvent(
                    agent_id=agent_id,
                    source="traefik",
                    kind="rate_limit",
                    ip="37.252.189.57",
                    value="media-ww-step1-ro@file",
                    action="rate_limit",
                    raw={"path": "/web/index.html"},
                    occurred_at=now - timedelta(seconds=idx),
                )
                for idx in range(3)
            ]
        )
        s.add(
            SecurityEvent(
                agent_id=agent_id,
                source="crowdsec",
                kind="ban",
                ip="1.2.3.4",
                value="ssh",
                action="ban",
                raw={},
                occurred_at=now,
            )
        )
        await s.commit()

    resp = await client.get("/api/security/events/groups?source=traefik")

    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["count"] == 3
    assert body[0]["source"] == "traefik"
    assert body[0]["kind"] == "rate_limit"
    assert body[0]["ip"] == "37.252.189.57"

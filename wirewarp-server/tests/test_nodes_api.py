from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.models.edge_config_version import EdgeConfigVersion
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.edge_route_config import EdgeRouteConfig
from app.models.port_forward import PortForward
from app.models.system_settings import SystemSettings
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.traefik_snapshot import TraefikSnapshot
from app.services.secrets import encrypt_secret


def _agent(agent_type: str, name: str) -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name=name,
        type=agent_type,
        hostname=f"{name}.example",
        status="connected",
        last_seen=datetime.now(timezone.utc),
    )


def _enable_security_edge(server: TunnelServer):
    from app.models.edge_node import EdgeNode
    return EdgeNode(agent_id=server.agent_id, edge_mode="security_edge", edge_state="enabled", edge_install_phase="healthy")


@pytest.fixture
def rename_client(request):
    return request.getfixturevalue(request.param)


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["server", "gateway", "client"])
@pytest.mark.parametrize("rename_client", ["client", "operator_client"], indirect=True)
async def test_rename_node_persists_across_inventory_and_agent_reads(
    rename_client, session_maker, monkeypatch, role,
) -> None:
    client = rename_client
    agent = _agent("server" if role == "server" else "client", "original")
    agent.status = "disconnected"
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
        if role == "server":
            s.add(TunnelServer(agent_id=agent.id, tunnel_network="10.21.0.0/24"))
        else:
            s.add(TunnelClient(agent_id=agent.id, is_gateway=role == "gateway"))
        await s.commit()
    events = []
    monkeypatch.setattr("app.routers.nodes.emit_agent_changed", lambda: events.append("agent.changed"))

    response = await client.patch(f"/api/nodes/{agent.id}", json={"name": "  New display name  "})
    assert response.status_code == 200
    assert response.json()["name"] == "New display name"
    assert response.json()["role"] == role
    assert response.json()["hostname"] == "original.example"
    assert response.json()["status"] == "disconnected"
    assert events == ["agent.changed"]
    assert (await client.get(f"/api/nodes/{agent.id}")).json()["name"] == "New display name"
    assert (await client.get(f"/api/agents/{agent.id}")).json()["name"] == "New display name"
    assert (await client.get("/api/nodes")).json()[0]["name"] == "New display name"
    async with session_maker() as s:
        assert (await s.get(Agent, agent.id)).name == "New display name"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["", " \t\n ", "x" * 256, None])
async def test_rename_node_rejects_invalid_names(client, session_maker, name) -> None:
    agent = _agent("client", "original")
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
    response = await client.patch(f"/api/nodes/{agent.id}", json={"name": name})
    assert response.status_code == 422
    assert (await client.get(f"/api/nodes/{agent.id}")).json()["name"] == "original"


@pytest.mark.asyncio
async def test_rename_node_denies_viewers(viewer_client, session_maker) -> None:
    agent = _agent("server", "original")
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
    response = await viewer_client.patch(f"/api/nodes/{agent.id}", json={"name": "changed"})
    assert response.status_code == 403
    async with session_maker() as s:
        assert (await s.get(Agent, agent.id)).name == "original"


@pytest.mark.asyncio
async def test_rename_node_missing(client) -> None:
    response = await client.patch(f"/api/nodes/{uuid.uuid4()}", json={"name": "new name"})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_nodes_list_derives_server_gateway_client_roles(client, session_maker) -> None:
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    client_agent = _agent("client", "road-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent, client_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        s.add(_enable_security_edge(server))
        s.add(server)
        s.add(TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True, vm_network="192.168.1.0/24"))
        s.add(TunnelClient(id=uuid.uuid4(), agent_id=client_agent.id, is_gateway=False))
        s.add(
            CrowdSecSnapshot(
                agent_id=server_agent.id,
                installed=True,
                running=True,
                phase="healthy",
                appsec_enabled=True,
                bouncer_registered=True,
            )
        )
        s.add(
            TraefikSnapshot(
                agent_id=server_agent.id,
                installed=True,
                running=True,
                phase="healthy",
            )
        )
        await s.commit()

    resp = await client.get("/api/nodes")

    assert resp.status_code == 200
    by_name = {row["name"]: row for row in resp.json()}
    assert by_name["edge-1"]["role"] == "server"
    assert by_name["edge-1"]["edge_mode"] == "security_edge"
    assert by_name["edge-1"]["edge_state"] == "enabled"
    assert by_name["edge-1"]["edge_components"]["traefik"]["running"] is True
    assert by_name["edge-1"]["edge_components"]["appsec"]["phase"] == "healthy"
    assert by_name["gw-1"]["role"] == "gateway"
    assert by_name["gw-1"]["edge_mode"] == "tcp_udp_only"
    assert all(component["desired"] == "disabled" for component in by_name["gw-1"]["edge_components"].values())
    assert by_name["road-1"]["edge_components"] == {}
    assert by_name["road-1"]["role"] == "client"


@pytest.mark.asyncio
async def test_node_edge_rolls_up_component_phases(client, session_maker) -> None:
    agent = _agent("server", "edge-1")
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=agent.id, tunnel_network="10.21.0.0/24")
        s.add(_enable_security_edge(server))
        s.add(server)
        s.add(
            CrowdSecSnapshot(
                agent_id=agent.id,
                installed=True,
                running=True,
                phase="healthy",
                appsec_enabled=True,
                bouncer_registered=True,
            )
        )
        s.add(
            TraefikSnapshot(
                agent_id=agent.id,
                installed=True,
                running=False,
                phase="degraded",
                last_error="unit failed",
            )
        )
        await s.commit()

    resp = await client.get(f"/api/nodes/{agent.id}/edge")

    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_id"] == str(agent.id)
    assert body["mode"] == "security_edge"
    assert body["state"] == "enabled"
    assert body["phase"] == "degraded"
    assert body["crowdsec"]["phase"] == "healthy"
    assert body["crowdsec"]["appsec_enabled"] is True
    assert body["traefik"]["phase"] == "degraded"
    assert body["traefik"]["last_error"] == "unit failed"
    assert body["components"]["traefik"]["installed"] is True
    assert body["components"]["appsec"]["desired"] == "enabled"


@pytest.mark.asyncio
async def test_node_edge_defaults_to_tcp_udp_only_and_blocks_reconcile(client, session_maker) -> None:
    agent = _agent("server", "edge-1")
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
        s.add(TunnelServer(id=uuid.uuid4(), agent_id=agent.id, tunnel_network="10.21.0.0/24"))
        await s.commit()

    edge = await client.get(f"/api/nodes/{agent.id}/edge")
    assert edge.status_code == 200
    body = edge.json()
    assert body["mode"] == "tcp_udp_only"
    assert body["state"] == "disabled"
    assert body["phase"] == "disabled"
    assert body["unavailable_reason"] == "security_edge_not_enabled"
    assert body["components"]["traefik"]["desired"] == "disabled"

    reconcile = await client.post(f"/api/nodes/{agent.id}/edge/reconcile")
    assert reconcile.status_code == 409
    assert reconcile.json()["detail"]["code"] == "edge_feature_disabled"


@pytest.mark.asyncio
async def test_node_edge_capabilities_put_enable_disable_are_idempotent(
    client,
    session_maker,
    fake_manager,
) -> None:
    agent = _agent("server", "edge-1")
    async with session_maker() as s:
        s.add(agent)
        await s.commit()
        s.add(TunnelServer(id=uuid.uuid4(), agent_id=agent.id, tunnel_network="10.21.0.0/24"))
        await s.commit()

    put = await client.put(
        f"/api/nodes/{agent.id}/edge/capabilities",
        json={
            "mode": "security_edge",
            "state": "enabled",
            "components": {
                "traefik": "enabled",
                "crowdsec": "enabled",
                "appsec": "enabled",
                "access_log": "enabled",
                "nginx_cache": "disabled",
            },
        },
    )
    assert put.status_code == 200, put.text
    body = put.json()
    assert body["mode"] == "security_edge"
    assert body["state"] == "enabled"
    assert body["components"]["traefik"]["desired"] == "enabled"
    assert body["components"]["nginx_cache"]["desired"] == "disabled"

    second = await client.put(
        f"/api/nodes/{agent.id}/edge/capabilities",
        json={"mode": "security_edge", "state": "enabled", "components": {"traefik": "enabled"}},
    )
    assert second.status_code == 200
    assert second.json()["components"]["traefik"]["desired"] == "enabled"

    fake_manager.online.add(str(agent.id))
    disabled = await client.post(f"/api/nodes/{agent.id}/edge/disable")
    assert disabled.status_code == 202
    assert disabled.json()["sent"] is True
    assert fake_manager.sent[-1]["message"]["type"] == "edge_disable"
    assert fake_manager.sent[-1]["message"]["params"]["preserve_state"] is True

    enabled = await client.post(f"/api/nodes/{agent.id}/edge/enable")
    assert enabled.status_code == 202
    assert enabled.json()["sent"] is True
    assert fake_manager.sent[-1]["message"]["type"] == "edge_desired_state"

    final = await client.get(f"/api/nodes/{agent.id}/edge/capabilities")
    assert final.status_code == 200
    assert final.json()["state"] == "enabled"


@pytest.mark.asyncio
async def test_security_site_create_returns_edge_feature_disabled_for_tcp_udp_node(
    client,
    session_maker,
) -> None:
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        client_row = TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True)
        s.add_all([server, client_row])
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        s.add(att)
        await s.commit()

    resp = await client.post(
        "/api/security/sites",
        json={
            "attachment_id": str(att.id),
            "domain": "app.example.com",
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
        },
    )

    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "edge_feature_disabled"
    assert resp.json()["detail"]["reason"] == "security_edge_not_enabled"


@pytest.mark.asyncio
async def test_edge_reconcile_dispatches_unified_desired_state(client, session_maker, fake_manager) -> None:
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        s.add(_enable_security_edge(server))
        client_row = TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True)
        s.add_all([server, client_row])
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        s.add(att)
        await s.commit()
        from app.models.http_route import HTTPRoute
        from app.models.http_public_ingress import HTTPPublicIngress
        pf = HTTPRoute(
            id=uuid.uuid4(), agent_id=server_agent.id, visibility="public_only",
            public_ingress=HTTPPublicIngress(attachment_id=att.id, public_port=443),
            destination_ip="192.168.1.10", destination_port=8080,
            domain="app.example.com", active=True,
        )
        s.add(pf)
        await s.flush()
        s.add(EdgeRouteConfig(id=uuid.uuid4(), port_forward_id=pf.id, waf_mode="block"))
        await s.commit()

    fake_manager.online.add(str(server_agent.id))
    resp = await client.post(f"/api/nodes/{server_agent.id}/edge/reconcile")

    assert resp.status_code == 202
    assert fake_manager.sent
    msg = fake_manager.sent[-1]["message"]
    assert msg["type"] == "edge_desired_state"
    assert msg["params"]["runtime_mode"] == "security_edge"
    assert msg["params"]["public_ingress"] == []
    assert set(msg["params"]) == {
        "runtime_mode",
        "public_ingress",
        "whitelist",
        "traefik_static_config",
        "traefik_dynamic_config",
        "nginx_cache_config",
        "traefik_acme",
        "desired_hash",
        "config_version_id",
    }
    async with session_maker() as s:
        version = await s.get(EdgeConfigVersion, uuid.UUID(msg["params"]["config_version_id"]))
        assert version.agent_id == server_agent.id
        assert version.desired_hash == msg["params"]["desired_hash"]
        assert version.source_snapshot["agent_id"] == str(server_agent.id)
    router = msg["params"]["traefik_dynamic_config"]["http"]["routers"]["app-example-com"]
    assert router["tls"] == {}
    middleware = msg["params"]["traefik_dynamic_config"]["http"]["middlewares"]["crowdsec-bouncer"]
    assert middleware["plugin"]["bouncer"]["crowdsecAppsecEnabled"] is True


@pytest.mark.asyncio
async def test_edge_reconcile_sends_acme_token_but_redacts_command_log(client, session_maker, fake_manager) -> None:
    server_agent = _agent("server", "edge-1")
    async with session_maker() as s:
        s.add(server_agent)
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        s.add(_enable_security_edge(server))
        s.add(server)
        settings = await s.get(SystemSettings, 1)
        if settings is None:
            settings = SystemSettings(id=1)
            s.add(settings)
        settings.letsencrypt_enabled = True
        settings.letsencrypt_email = "admin@example.com"
        settings.letsencrypt_challenge = "dns-01"
        settings.letsencrypt_dns_provider = "cloudflare"
        settings.letsencrypt_dns_resolvers = ["1.1.1.1:53"]
        settings.letsencrypt_cloudflare_api_token = encrypt_secret("real-le-token")
        await s.commit()

    fake_manager.online.add(str(server_agent.id))
    resp = await client.post(f"/api/nodes/{server_agent.id}/edge/reconcile")

    assert resp.status_code == 202
    sent_params = fake_manager.sent[-1]["message"]["params"]
    assert sent_params["traefik_acme"]["cloudflare_dns_api_token"] == "real-le-token"
    resolver = sent_params["traefik_static_config"]["certificatesResolvers"]["wirewarp-le"]["acme"]
    assert resolver["dnsChallenge"]["provider"] == "cloudflare"

    async with session_maker() as s:
        logged = await s.scalar(
            select(CommandLog)
            .where(CommandLog.agent_id == server_agent.id)
            .order_by(CommandLog.executed_at.desc())
        )
        assert logged is not None
        assert logged.params["traefik_acme"]["cloudflare_dns_api_token"] == "[redacted]"


@pytest.mark.asyncio
async def test_security_sites_filter_by_agent_id_and_default_observe(client, session_maker, fake_manager) -> None:
    server_agent = _agent("server", "edge-1")
    other_agent = _agent("server", "edge-2")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, other_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        other = TunnelServer(id=uuid.uuid4(), agent_id=other_agent.id, tunnel_network="10.22.0.0/24")
        s.add(_enable_security_edge(server))
        s.add(_enable_security_edge(other))
        client_row = TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True)
        s.add_all([server, other, client_row])
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        other_att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=other.id,
            tunnel_ip="10.22.0.2",
            wg_interface="wg1",
            fwmark=0x102,
            route_table_id=101,
        )
        s.add_all([att, other_att])
        await s.commit()
        s.add(
            PortForward(
                id=uuid.uuid4(),
                attachment_id=other_att.id,
                protocol="tcp",
                public_port=443,
                destination_ip="192.168.1.20",
                destination_port=8080,
                service_kind="http",
                domain="other.example.com",
                active=True,
            )
        )
        await s.commit()

    fake_manager.online.add(str(server_agent.id))
    resp = await client.post(
        "/api/security/sites",
        json={
            "attachment_id": str(att.id),
            "domain": "app.example.com",
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
        },
    )
    assert resp.status_code == 201
    assert resp.json()["edge_config"]["waf_mode"] == "observe"

    filtered = await client.get(f"/api/security/sites?agent_id={server_agent.id}")
    assert filtered.status_code == 200
    assert [row["domain"] for row in filtered.json()] == ["app.example.com"]


@pytest.mark.asyncio
async def test_security_site_rejects_conflicting_raw_edge_forward(client, session_maker) -> None:
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        s.add(_enable_security_edge(server))
        client_row = TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True)
        s.add_all([server, client_row])
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        s.add(att)
        await s.commit()
        s.add(
            PortForward(
                id=uuid.uuid4(),
                attachment_id=att.id,
                protocol="tcp",
                public_port=443,
                destination_ip="192.168.1.2",
                destination_port=443,
                service_kind="raw",
                active=True,
            )
        )
        await s.commit()

    resp = await client.post(
        "/api/security/sites",
        json={
            "attachment_id": str(att.id),
            "domain": "app.example.com",
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
        },
    )

    assert resp.status_code == 409
    assert "Raw TCP port forward 443" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_antibot_requires_configured_captcha_keys(client, session_maker) -> None:
    server_agent = _agent("server", "edge-1")
    gateway_agent = _agent("client", "gw-1")
    async with session_maker() as s:
        s.add_all([server_agent, gateway_agent])
        await s.commit()
        server = TunnelServer(id=uuid.uuid4(), agent_id=server_agent.id, tunnel_network="10.21.0.0/24")
        s.add(_enable_security_edge(server))
        client_row = TunnelClient(id=uuid.uuid4(), agent_id=gateway_agent.id, is_gateway=True)
        s.add_all([server, client_row])
        await s.commit()
        att = TunnelClientAttachment(
            id=uuid.uuid4(),
            tunnel_client_id=client_row.id,
            tunnel_server_id=server.id,
            tunnel_ip="10.21.0.2",
            wg_interface="wg0",
            fwmark=0x101,
            route_table_id=100,
        )
        s.add(att)
        await s.commit()

    resp = await client.post(
        "/api/security/sites",
        json={
            "attachment_id": str(att.id),
            "domain": "app.example.com",
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
            "antibot": True,
        },
    )

    assert resp.status_code == 400
    assert "CAPTCHA" in resp.json()["detail"]

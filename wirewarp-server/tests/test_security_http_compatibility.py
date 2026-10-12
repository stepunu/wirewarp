import json

import pytest
from sqlalchemy import select

from app.models.edge_node import EdgeNode
from app.models.edge_route_config import EdgeRouteConfig
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.models.port_forward import PortForward
from app.models.tunnel_server_ip import TunnelServerIP

pytestmark = pytest.mark.asyncio


async def setup_server(db, factories):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    gateway = await factories.make_client(db)
    attachment = await factories.make_attachment(db, client=gateway, server=server)
    return server, gateway, attachment


async def test_legacy_sites_and_modern_routes_share_uuid_policies_and_ingress(client, db, factories, fake_manager):
    server, _, attachment = await setup_server(db, factories)
    fake_manager.online.add(str(server.agent_id))
    created = await client.post("/api/security/sites", json={"attachment_id": str(attachment.id), "domain": "public.example.test", "destination_ip": "192.168.1.20", "destination_port": 8080, "waf_mode": "block", "rate_limit_rps": 21, "auth_mode": "basic", "auth_config": {"users": ["user:hash"]}})
    assert created.status_code == 201, created.text
    site = created.json()
    assert site["attachment_id"] == str(attachment.id)
    assert site["visibility"] == "public_only"
    assert site["server_id"] == str(server.id)
    assert site["edge_config"]["port_forward_id"] == site["id"]
    modern = await client.get(f"/api/edge/routes/{site['id']}")
    assert modern.status_code == 200, modern.text
    assert modern.json()["policy"]["waf_mode"] == "block"
    assert modern.json()["policy"]["rate_limit"]["requests"] == 21
    assert await db.scalar(select(PortForward.id).where(PortForward.service_kind == "http")) is None
    assert (await db.get(HTTPPublicIngress, site["id"])).attachment_id == attachment.id
    updated = await client.patch(f"/api/security/sites/{site['id']}", json={"rate_limit_rps": None, "auth_config": None, "ip_allow": None, "description": None, "active": False, "waf_mode": "observe"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["edge_config"]["auth_config"] is None
    assert not updated.json()["active"]
    modern = await client.get(f"/api/edge/routes/{site['id']}")
    assert modern.json()["policy"]["rate_limit"]["requests"] is None
    assert modern.json()["policy"]["waf_mode"] == "observe"
    assert (await db.get(HTTPPublicIngress, site["id"], populate_existing=True)).active is False
    assert (await client.delete(f"/api/security/sites/{site['id']}")).status_code == 204
    assert (await client.get(f"/api/edge/routes/{site['id']}")).status_code == 404
    assert fake_manager.sent[-1]["agent_id"] == str(server.agent_id)


async def test_legacy_list_and_update_include_gateway_lan_routes(client, db, factories):
    gateway = await factories.make_client(db)
    db.add(EdgeNode(agent_id=gateway.agent_id, edge_mode="security_edge", edge_state="enabled", lan_bind_ip=gateway.lan_ip))
    route = HTTPRoute(agent_id=gateway.agent_id, domain="lan.example.test", destination_ip="192.168.1.20", destination_port=80, visibility="lan_only")
    db.add(route)
    await db.flush()
    db.add(EdgeRouteConfig(route_id=route.id))
    await db.commit()
    listed = await client.get("/api/security/sites", params={"agent_id": str(gateway.agent_id)})
    assert listed.status_code == 200, listed.text
    assert len(listed.json()) == 1
    assert listed.json()[0]["attachment_id"] is None
    assert listed.json()[0]["public_port"] is None
    assert listed.json()[0]["visibility"] == "lan_only"
    updated = await client.patch(f"/api/security/sites/{route.id}", json={"destination_port": 8081, "waf_mode": "block"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["destination_port"] == 8081
    assert updated.json()["edge_config"]["waf_mode"] == "block"
    assert (await client.get("/api/security/certs")).json()[0]["port_forward_id"] == str(route.id)


async def test_legacy_server_policy_updates_edge_node_and_preserves_server_identifier(client, db, factories):
    server, _, _ = await setup_server(db, factories)
    update = await client.patch(f"/api/security/servers/{server.id}/edge-policy", json={"rate_limit_rps": 44, "rate_limit_burst": 90})
    assert update.status_code == 200, update.text
    assert update.json()["server_id"] == str(server.id)
    assert (await db.get(EdgeNode, server.agent_id, populate_existing=True)).edge_rate_limit_rps == 44
    read = await client.get(f"/api/security/servers/{server.id}/edge-policy")
    assert read.json()["rate_limit_burst"] == 90


async def test_legacy_import_preserves_uuid_metadata_and_policy_across_overwrite(client, db, factories):
    server, _, attachment = await setup_server(db, factories)
    content = {"http": {"routers": {"app": {"rule": "Host(`import.example.test`)", "service": "origin", "middlewares": ["limit", "acl"], "tls": {}}}, "services": {"origin": {"loadBalancer": {"servers": [{"url": "https://192.168.1.20:8443"}]}}}, "middlewares": {"limit": {"rateLimit": {"average": 12, "burst": 24}}, "acl": {"ipAllowList": {"sourceRange": ["192.168.0.0/16"]}}}}}
    payload = {"server_id": str(server.id), "attachment_id": str(attachment.id), "content": json.dumps(content), "activate": True}
    first = await client.post("/api/security/traefik/import", json=payload)
    assert first.status_code == 201, first.text
    assert first.json()["created"] == 1
    route = await db.scalar(select(HTTPRoute))
    route_id = route.id
    config = await db.scalar(select(EdgeRouteConfig))
    assert config.imported_router_name == "app" and config.imported_service_name == "origin"
    assert config.upstream_scheme == "https"
    assert config.ip_allow == ["192.168.0.0/16"]
    assert config.rate_limit_rps == 12
    assert config.policy_json["rate_limit"]["requests"] == 12
    second = await client.post("/api/security/traefik/import", json={**payload, "overwrite": True})
    assert second.status_code == 201, second.text
    assert second.json()["updated"] == 1
    assert (await db.scalar(select(HTTPRoute))).id == route_id
    assert await db.scalar(select(PortForward.id).where(PortForward.service_kind == "http")) is None


async def test_legacy_create_rejects_wrong_server_ip_and_missing_captcha(client, db, factories):
    server, _, attachment = await setup_server(db, factories)
    other = await factories.make_server(db, network="10.22.0.0/24", primary_ip="1.2.3.5")
    other_ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == other.id))
    payload = {"attachment_id": str(attachment.id), "domain": "public.example.test", "destination_ip": "192.168.1.20", "destination_port": 80}
    rejected = await client.post("/api/security/sites", json={**payload, "tunnel_server_ip_id": str(other_ip.id)})
    assert rejected.status_code == 400, rejected.text
    captcha = await client.post("/api/security/sites", json={**payload, "antibot": True})
    assert captcha.status_code == 400 and "CAPTCHA" in captcha.text
    assert await db.scalar(select(HTTPRoute.id)) is None

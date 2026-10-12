from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.edge_node import EdgeNode
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_client import TunnelClient


async def gateway(session_maker, factories, *, lan_ip="192.168.20.110", is_gateway=True):
    async with session_maker() as db:
        node = await factories.make_client(db, lan_ip=lan_ip, is_gateway=is_gateway)
        return node.agent_id


@pytest.mark.asyncio
async def test_gateway_enables_with_lan_ip_and_no_attachments(client, session_maker, factories, fake_manager):
    agent_id = await gateway(session_maker, factories)
    fake_manager.online.add(str(agent_id))
    response = await client.post(f"/api/nodes/{agent_id}/edge/enable")
    assert response.status_code == 202, response.text
    assert response.json()["edge"]["lan_bind_ip"] == "192.168.20.110"
    assert response.json()["edge"]["public_ingress_available"] is False
    assert response.json()["sent"] is True
    async with session_maker() as db:
        owner = await db.get(EdgeNode, agent_id)
        assert owner.edge_mode == "security_edge"
        assert owner.edge_state == "enabled"
        assert (await db.scalars(select(TunnelClientAttachment))).all() == []
    inventory = (await client.get(f"/api/nodes/{agent_id}")).json()
    assert inventory["role"] == "gateway"
    assert inventory["edge_mode"] == "security_edge"
    assert inventory["lan_bind_ip"] == "192.168.20.110"


@pytest.mark.asyncio
async def test_gateway_global_rate_policy_persists_and_dispatches(client, session_maker, factories, fake_manager):
    agent_id = await gateway(session_maker, factories)
    fake_manager.online.add(str(agent_id))
    await client.post(f"/api/nodes/{agent_id}/edge/enable")
    response = await client.patch(f"/api/nodes/{agent_id}/edge/global-policy", json={"rate_limit_rps": 15, "rate_limit_burst": 40})
    assert response.status_code == 200, response.text
    assert response.json() == {"agent_id": str(agent_id), "server_id": None, "rate_limit_rps": 15, "rate_limit_burst": 40}
    desired = fake_manager.sent[-1]["message"]["params"]
    assert desired["traefik_dynamic_config"]["http"]["middlewares"]["server-ratelimit"]["rateLimit"] == {"average": 15, "burst": 40}
    response = await client.patch(f"/api/nodes/{agent_id}/edge/global-policy", json={"rate_limit_rps": None})
    assert response.json()["rate_limit_rps"] is None
    assert response.json()["rate_limit_burst"] == 40
    response = await client.patch(f"/api/nodes/{agent_id}/edge/global-policy", json={"rate_limit_burst": 0})
    assert response.status_code == 400
    async with session_maker() as db:
        owner = await db.get(EdgeNode, agent_id)
        assert owner.edge_rate_limit_burst == 40


@pytest.mark.asyncio
async def test_gateway_lan_route_crud_independent_of_attachment(client, session_maker, factories, fake_manager):
    agent_id = await gateway(session_maker, factories)
    fake_manager.online.add(str(agent_id))
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    response = await client.post(f"/api/nodes/{agent_id}/edge/routes", json={"domain": "app.example.test", "destination_ip": "192.168.20.12", "destination_port": 8080})
    assert response.status_code == 201, response.text
    route = response.json()
    assert route["visibility"] == "lan_only"
    assert route["attachment_id"] is None
    assert route["server_id"] is None
    assert route["public_port"] is None
    route_id = route["id"]
    response = await client.patch(f"/api/nodes/{agent_id}/edge/routes/{route_id}", json={"destination_port": 8081})
    assert response.status_code == 200, response.text
    assert response.json()["id"] == route_id
    assert response.json()["destination_port"] == 8081
    response = await client.get(f"/api/nodes/{agent_id}/edge")
    assert response.status_code == 200, response.text
    assert response.json()["sites"][0]["visibility"] == "lan_only"
    assert response.json()["sites"][0]["attachment_id"] is None
    assert (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json()[0]["id"] == route_id
    async with session_maker() as db:
        assert (await db.get(HTTPRoute, uuid.UUID(route_id))).agent_id == agent_id
        assert (await db.scalars(select(HTTPPublicIngress))).all() == []
    assert (await client.delete(f"/api/nodes/{agent_id}/edge/routes/{route_id}")).status_code == 204
    assert (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("visibility", ["public_only", "both"])
async def test_gateway_public_visibility_reports_unavailable(client, session_maker, factories, visibility):
    agent_id = await gateway(session_maker, factories)
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    response = await client.post(f"/api/nodes/{agent_id}/edge/routes", json={"domain": "app.example.test", "destination_ip": "192.168.20.12", "destination_port": 80, "visibility": visibility})
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "gateway_public_ingress_unavailable"
    async with session_maker() as db:
        assert (await db.scalars(select(HTTPRoute))).all() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("bind_ip", ["0.0.0.0", "::", "127.0.0.1", "224.0.0.1", "not-an-ip", "192.168.20.110:443"])
async def test_gateway_listener_rejects_implicit_or_invalid_address(client, session_maker, factories, bind_ip):
    agent_id = await gateway(session_maker, factories)
    response = await client.put(f"/api/nodes/{agent_id}/edge/capabilities", json={"state": "enabled", "lan_bind_ip": bind_ip})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_gateway_missing_bind_and_shared_public_bind_rejected(client, session_maker, factories):
    agent_id = await gateway(session_maker, factories, lan_ip=None)
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 409
    response = await client.put(f"/api/nodes/{agent_id}/edge/capabilities", json={"lan_bind_ip": "192.168.20.110", "public_bind_ip": "192.168.20.110"})
    assert response.status_code == 422
    response = await client.put(f"/api/nodes/{agent_id}/edge/capabilities", json={"state": "enabled", "lan_bind_ip": "192.168.20.110", "public_bind_ip": "10.21.0.10"})
    assert response.status_code == 422, response.text
    async with session_maker() as db:
        client_id = await db.scalar(select(TunnelClient.id).where(TunnelClient.agent_id == agent_id))
    response = await client.patch(f"/api/tunnel-clients/{client_id}", json={"lan_ip": "192.168.20.110", "vm_network": "192.168.20.0/24"})
    assert response.status_code == 200, response.text
    response = await client.put(f"/api/nodes/{agent_id}/edge/capabilities", json={"state": "enabled", "lan_bind_ip": "192.168.20.110", "public_bind_ip": "10.21.0.10"})
    assert response.status_code == 200, response.text
    assert response.json()["public_ingress_available"] is False


@pytest.mark.asyncio
async def test_ordinary_client_edge_unavailable(client, session_maker, factories):
    agent_id = await gateway(session_maker, factories, is_gateway=False)
    for path in ("edge", "edge/capabilities", "edge/routes", "edge/desired-state", "edge/access-events"):
        assert (await client.get(f"/api/nodes/{agent_id}/{path}")).status_code == 409
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 409


@pytest.mark.asyncio
async def test_gateway_import_requires_typed_content_and_router_fragment_cannot_bypass_visibility(client, session_maker, factories):
    agent_id = await gateway(session_maker, factories)
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    for action in ("preview", "apply", "upsert"):
        response = await client.post(f"/api/nodes/{agent_id}/edge/import/traefik/{action}", json={"config": {}})
        assert response.status_code == 422
    response = await client.post(f"/api/nodes/{agent_id}/edge/fragments", json={"name": "unsafe", "fragment_type": "router", "content": {"entryPoints": ["websecure"], "rule": "Host(`app.example.test`)"}})
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_gateway_desired_state_cannot_publish_or_cross_node(client, session_maker, factories):
    agent_id = await gateway(session_maker, factories)
    other_id = await gateway(session_maker, factories, lan_ip="192.168.20.111")
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    assert (await client.post(f"/api/nodes/{other_id}/edge/enable")).status_code == 202
    response = await client.put(f"/api/nodes/{agent_id}/edge/desired-state", json={"routes": [{"domain": "app.example.test", "destination_ip": "192.168.20.12", "destination_port": 80, "visibility": "both"}]})
    assert response.status_code == 409
    response = await client.post(f"/api/nodes/{other_id}/edge/routes", json={"domain": "other.example.test", "destination_ip": "192.168.20.12", "destination_port": 80})
    assert response.status_code == 201, response.text
    response = await client.put(f"/api/nodes/{agent_id}/edge/desired-state", json={"routes": [{"id": response.json()["id"], "enabled": False}]})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_gateway_mutations_require_admin(operator_client, session_maker, factories):
    agent_id = await gateway(session_maker, factories)
    assert (await operator_client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 403
    assert (await operator_client.post(f"/api/nodes/{agent_id}/edge/routes", json={"domain": "app.example.test"})).status_code == 403


@pytest.mark.asyncio
async def test_vps_route_retains_attachment_and_public_read_fields(client, session_maker, factories):
    async with session_maker() as db:
        server = await factories.make_server(db)
        lan = await factories.make_client(db)
        attachment = await factories.make_attachment(db, client=lan, server=server)
    assert (await client.post(f"/api/nodes/{server.agent_id}/edge/enable")).status_code == 202
    response = await client.put(f"/api/nodes/{server.agent_id}/edge/routes/by-domain/app.example.test", json={"attachment_id": str(attachment.id), "destination_ip": "192.168.1.12", "destination_port": 80})
    assert response.status_code == 200, response.text
    route = response.json()
    assert route["server_id"] == str(server.id)
    assert route["attachment_id"] == str(attachment.id)
    assert route["public_port"] == 443
    assert route["visibility"] == "public_only"
    response = await client.get(f"/api/nodes/{server.agent_id}/edge")
    assert response.status_code == 200
    assert response.json()["sites"][0]["id"] == route["id"]
    assert response.json()["sites"][0]["attachment_id"] == str(attachment.id)
    assert response.json()["policy"]["server_id"] == str(server.id)
    response = await client.patch(f"/api/nodes/{server.agent_id}/edge/routes/{route['id']}", json={"visibility": "lan_only"})
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_vps_public_ingress_rejects_other_server_attachment_and_ip(client, session_maker, factories):
    from app.models.tunnel_server_ip import TunnelServerIP

    async with session_maker() as db:
        server = await factories.make_server(db)
        other = await factories.make_server(db, network="10.22.0.0/24", primary_ip="5.6.7.8")
        lan = await factories.make_client(db)
        attachment = await factories.make_attachment(db, client=lan, server=server)
        foreign_attachment = await factories.make_attachment(db, client=lan, server=other, tunnel_ip="10.22.0.10", wg_interface="wg1", route_table_id=101, fwmark=0x102)
        foreign_ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == other.id))
    assert (await client.post(f"/api/nodes/{server.agent_id}/edge/enable")).status_code == 202
    body = {"domain": "app.example.test", "destination_ip": "192.168.1.12", "destination_port": 80, "attachment_id": str(foreign_attachment.id)}
    assert (await client.post(f"/api/nodes/{server.agent_id}/edge/routes", json=body)).status_code == 400
    body["attachment_id"] = str(attachment.id)
    body["tunnel_server_ip_id"] = str(foreign_ip.id)
    assert (await client.post(f"/api/nodes/{server.agent_id}/edge/routes", json=body)).status_code == 400
    async with session_maker() as db:
        assert (await db.scalars(select(HTTPRoute))).all() == []


@pytest.mark.asyncio
async def test_gateway_desired_routes_apply_atomically(client, session_maker, factories):
    agent_id = await gateway(session_maker, factories)
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    valid = {"domain": "app.example.test", "destination_ip": "192.168.20.12", "destination_port": 80}
    response = await client.put(f"/api/nodes/{agent_id}/edge/desired-state", json={"routes": [valid, {**valid, "domain": "public.example.test", "visibility": "public_only"}]})
    assert response.status_code == 409
    assert (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json() == []
    response = await client.put(f"/api/nodes/{agent_id}/edge/desired-state", json={"routes": [valid]})
    assert response.status_code == 200, response.text
    assert (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json()[0]["visibility"] == "lan_only"


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", ["app.example.test`) || Host(`other.example.test", "bad domain", "https://app.example.test"])
async def test_managed_route_rejects_rule_injection_domains(client, session_maker, factories, domain):
    agent_id = await gateway(session_maker, factories)
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    response = await client.post(f"/api/nodes/{agent_id}/edge/routes", json={"domain": domain, "destination_ip": "192.168.20.12", "destination_port": 80})
    assert response.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["gateway", "server"])
async def test_node_site_policy_reads_owner_rate_limit(client, session_maker, factories, role):
    attachment = None
    if role == "gateway":
        agent_id = await gateway(session_maker, factories)
    else:
        async with session_maker() as db:
            server = await factories.make_server(db)
            lan = await factories.make_client(db)
            attachment = await factories.make_attachment(db, client=lan, server=server)
            agent_id = server.agent_id
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    async with session_maker() as db:
        owner = await db.get(EdgeNode, agent_id)
        owner.edge_rate_limit_rps = 15
        owner.edge_rate_limit_burst = 40
        await db.commit()
    body = {"domain": "app.example.test", "destination_ip": "192.168.20.12", "destination_port": 80}
    if attachment:
        body["attachment_id"] = str(attachment.id)
    response = await client.post(f"/api/nodes/{agent_id}/edge/routes", json=body)
    assert response.status_code == 201, response.text
    response = await client.get(f"/api/nodes/{agent_id}/edge")
    assert response.status_code == 200, response.text
    assert response.json()["policy"]["rate_limit_rps"] == 15
    assert response.json()["sites"][0]["effective_policy"]["rate_limit"]["global"] == {"rps": 15, "burst": 40}


@pytest.mark.asyncio
@pytest.mark.parametrize("routes", [{}, ["invalid"], [{"id": "invalid"}]])
async def test_gateway_desired_state_rejects_malformed_routes(client, session_maker, factories, routes):
    agent_id = await gateway(session_maker, factories)
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    response = await client.put(f"/api/nodes/{agent_id}/edge/desired-state", json={"routes": routes})
    assert response.status_code == 422
    assert (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json() == []

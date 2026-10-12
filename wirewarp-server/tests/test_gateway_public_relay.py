import uuid

import pytest

from app.models.edge_node import EdgeNode
from app.services.edge_ops import build_edge_desired_state

pytestmark = pytest.mark.asyncio


async def topology(session_maker, factories):
    async with session_maker() as db:
        server = await factories.make_server(db, edge_mode="tcp_udp_only", edge_state="disabled")
        gateway = await factories.make_client(db, lan_ip="192.168.20.110")
        attachment = await factories.make_attachment(db, client=gateway, server=server)
        return gateway.agent_id, server.agent_id, attachment.id, attachment.tunnel_ip


async def publish(client, gateway, attachment, *, domain="app.example.test", visibility="both"):
    return await client.post(f"/api/nodes/{gateway}/edge/routes", json={
        "domain": domain, "destination_ip": "192.168.20.50", "destination_port": 8080,
        "visibility": visibility, "attachment_id": str(attachment),
    })


async def test_gateway_relay_preserves_tls_policy_and_reconciles_last_unpublication(client, session_maker, factories, fake_manager):
    gateway, hub, attachment, tunnel_ip = await topology(session_maker, factories)
    fake_manager.online.update([str(gateway), str(hub)])
    await client.post(f"/api/nodes/{gateway}/edge/enable")
    response = await publish(client, gateway, attachment)
    assert response.status_code == 201, response.text
    route = response.json()
    assert route["visibility"] == "both"
    async with session_maker() as db:
        gateway_state = await build_edge_desired_state(gateway, db)
        hub_state = await build_edge_desired_state(hub, db)
        assert (await db.get(EdgeNode, hub)).relay_enabled is True
    assert gateway_state["public_ingress"] == [{"interface": "wg0", "source_ip": "10.21.0.1", "listen_ip": tunnel_ip}]
    points = gateway_state["traefik_static_config"]["entryPoints"]
    assert points["websecure"]["address"] == tunnel_ip + ":443"
    assert points["websecure"]["proxyProtocol"] == {"trustedIPs": ["10.21.0.1/32"]}
    assert next(iter(gateway_state["traefik_dynamic_config"]["http"]["routers"].values()))["entryPoints"] == ["lansecure", "websecure"]
    assert hub_state["runtime_mode"] == "relay_only"
    assert hub_state["traefik_acme"] == {}
    assert "certificatesResolvers" not in hub_state["traefik_static_config"]
    tcp = hub_state["traefik_dynamic_config"]["tcp"]
    assert next(iter(tcp["routers"].values()))["tls"] == {"passthrough": True}
    assert next(iter(tcp["services"].values()))["loadBalancer"]["proxyProtocol"] == {"version": 2}
    response = await client.patch(f"/api/nodes/{gateway}/edge/routes/{route['id']}", json={"visibility": "lan_only"})
    assert response.status_code == 200, response.text
    assert response.json()["attachment_id"] is None
    async with session_maker() as db:
        assert (await db.get(EdgeNode, hub)).relay_enabled is False
        state = await build_edge_desired_state(gateway, db)
    assert state["public_ingress"] == []
    assert "websecure" not in state["traefik_static_config"]["entryPoints"]
    assert any(item["agent_id"] == str(hub) and item["message"]["type"] == "edge_disable" for item in fake_manager.sent)


async def test_gateway_disable_removes_hub_relay_and_enable_restores_it(client, session_maker, factories):
    gateway, hub, attachment, _ = await topology(session_maker, factories)
    await client.post(f"/api/nodes/{gateway}/edge/enable")
    response = await publish(client, gateway, attachment)
    assert response.status_code == 201, response.text
    assert (await client.post(f"/api/nodes/{gateway}/edge/disable")).status_code == 202
    async with session_maker() as db:
        assert (await db.get(EdgeNode, hub)).relay_enabled is False
    assert (await client.post(f"/api/nodes/{gateway}/edge/enable")).status_code == 202
    async with session_maker() as db:
        assert (await db.get(EdgeNode, hub)).relay_enabled is True


async def test_gateway_rejects_unowned_attachment_before_route_creation(client, session_maker, factories):
    gateway, _, attachment, _ = await topology(session_maker, factories)
    async with session_maker() as db:
        other = await factories.make_client(db)
    await client.post(f"/api/nodes/{other.agent_id}/edge/enable")
    response = await publish(client, other.agent_id, attachment)
    assert response.status_code in {400, 409}, response.text
    assert (await client.get(f"/api/nodes/{other.agent_id}/edge/routes")).json() == []

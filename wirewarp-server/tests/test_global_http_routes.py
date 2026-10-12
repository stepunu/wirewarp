import pytest
from sqlalchemy import select

from app.models.edge_access_event import EdgeAccessEvent
from app.models.edge_fragment import EdgeFragment
from app.models.edge_node import EdgeNode
from app.models.edge_route_config import EdgeRouteConfig
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute

pytestmark = pytest.mark.asyncio


async def gateway_route(db, factories, *, domain="lan.example.test"):
    gateway = await factories.make_client(db)
    db.add(EdgeNode(agent_id=gateway.agent_id, edge_mode="security_edge", edge_state="enabled", lan_bind_ip=gateway.lan_ip))
    route = HTTPRoute(agent_id=gateway.agent_id, domain=domain, destination_ip="192.168.1.20", destination_port=8080, visibility="lan_only")
    db.add(route)
    await db.flush()
    db.add(EdgeRouteConfig(route_id=route.id, waf_mode="off"))
    await db.commit()
    return gateway, route


async def test_global_gateway_route_crud_path_rules_and_owner_dispatch(client, db, factories, fake_manager):
    gateway, route = await gateway_route(db, factories)
    fake_manager.online.add(str(gateway.agent_id))
    route_url = f"/api/edge/routes/{route.id}"
    read = await client.get(route_url)
    assert read.status_code == 200, read.text
    assert read.json()["node_id"] == str(gateway.agent_id)
    assert read.json()["attachment_id"] is None
    update = await client.patch(route_url, json={"destination_port": 9090, "policy": {"waf_mode": "observe"}})
    assert update.status_code == 200, update.text
    assert update.json()["id"] == str(route.id)
    assert update.json()["destination_port"] == 9090
    created = await client.post(route_url + "/path-rules", json={"name": "private", "match": {"path_prefix": "/admin"}, "policy": {"waf_mode": "block"}})
    assert created.status_code == 201, created.text
    rule_url = f"/api/edge/path-rules/{created.json()['id']}"
    assert (await client.get(rule_url)).status_code == 200
    updated = await client.patch(rule_url, json={"name": "private", "match": {"path_prefix": "/admin"}, "policy": {"waf_mode": "observe"}})
    assert updated.status_code == 200, updated.text
    assert (await client.get(route_url + "/effective")).status_code == 200
    assert (await client.delete(rule_url)).status_code == 204
    db.add(EdgeAccessEvent(agent_id=gateway.agent_id, route_id=route.id))
    await db.commit()
    deleted = await client.delete(route_url)
    assert deleted.status_code == 204, deleted.text
    assert (await client.get(route_url)).status_code == 404
    event = await db.scalar(select(EdgeAccessEvent).execution_options(populate_existing=True))
    assert event.route_id is None
    commands = [sent for sent in fake_manager.sent if sent["message"]["type"] == "edge_desired_state"]
    assert len(commands) >= 4
    assert all(sent["agent_id"] == str(gateway.agent_id) for sent in commands)


async def test_global_patch_preserves_route_id_when_legacy_domains_collide(client, db, factories):
    gateway, first = await gateway_route(db, factories)
    second = HTTPRoute(agent_id=gateway.agent_id, domain=first.domain, destination_ip="192.168.1.21", destination_port=80, visibility="lan_only")
    db.add(second)
    await db.flush()
    db.add(EdgeRouteConfig(route_id=second.id))
    await db.commit()
    updated = await client.patch(f"/api/edge/routes/{second.id}", json={"destination_port": 8888})
    assert updated.status_code == 200, updated.text
    assert updated.json()["id"] == str(second.id)
    await db.refresh(first)
    assert first.destination_port == 8080


async def test_global_route_patch_rejects_attachment_from_another_server(client, db, factories):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    other = await factories.make_server(db, network="10.22.0.0/24", primary_ip="1.2.3.5")
    gateway = await factories.make_client(db)
    own_attachment = await factories.make_attachment(db, client=gateway, server=server)
    other_attachment = await factories.make_attachment(db, client=gateway, server=other, tunnel_ip="10.22.0.10", wg_interface="wg1", fwmark=258, route_table_id=101)
    route = HTTPRoute(agent_id=server.agent_id, domain="public.example.test", destination_ip="192.168.1.20", destination_port=80, visibility="public_only")
    db.add(route)
    await db.flush()
    db.add_all([EdgeRouteConfig(route_id=route.id), HTTPPublicIngress(route_id=route.id, attachment_id=own_attachment.id)])
    await db.commit()
    rejected = await client.patch(f"/api/edge/routes/{route.id}", json={"attachment_id": str(other_attachment.id)})
    assert rejected.status_code == 400, rejected.text
    ingress = await db.get(HTTPPublicIngress, route.id, populate_existing=True)
    assert ingress.attachment_id == own_attachment.id


async def test_gateway_fragment_update_cannot_bypass_visibility_or_cross_owner(client, db, factories):
    gateway, route = await gateway_route(db, factories)
    _, other_route = await gateway_route(db, factories, domain="other.example.test")
    fragment = EdgeFragment(agent_id=gateway.agent_id, route_id=route.id, name="headers", fragment_type="middleware", content={})
    db.add(fragment)
    await db.commit()
    url = f"/api/edge/fragments/{fragment.id}"
    router = await client.patch(url, json={"name": "unsafe", "fragment_type": "router", "content": {"entryPoints": ["websecure"]}, "route_id": str(route.id)})
    assert router.status_code == 409, router.text
    mismatch = await client.patch(url, json={"name": "other", "fragment_type": "middleware", "content": {}, "route_id": str(other_route.id)})
    assert mismatch.status_code == 400, mismatch.text
    await db.refresh(fragment)
    assert fragment.name == "headers" and fragment.route_id == route.id
    valid = await client.post(url + "/validate")
    assert valid.status_code == 200 and valid.json()["valid"]
    fragment.fragment_type = "router"
    await db.commit()
    invalid = await client.post(url + "/validate")
    assert not invalid.json()["valid"]


async def test_operator_can_read_but_cannot_mutate_gateway_route(operator_client, db, factories):
    _, route = await gateway_route(db, factories)
    url = f"/api/edge/routes/{route.id}"
    assert (await operator_client.get(url)).status_code == 200
    assert (await operator_client.patch(url, json={"enabled": False})).status_code == 403
    assert (await operator_client.delete(url)).status_code == 403

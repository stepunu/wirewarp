import uuid

import pytest
from fastapi import HTTPException

from app.models.edge_node import EdgeNode
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_route_config import EdgeRouteConfig
from app.models.http_route import HTTPRoute
from app.services.edge_ops import build_edge_desired_state
from app.services.edge_runtime import desired_state_snapshot


pytestmark = pytest.mark.asyncio


async def lan_route(db, factories):
    gateway = await factories.make_client(db, lan_ip="192.168.20.110")
    node = EdgeNode(agent_id=gateway.agent_id, edge_mode="security_edge", edge_state="enabled", lan_bind_ip=gateway.lan_ip)
    route = HTTPRoute(id=uuid.uuid4(), agent_id=gateway.agent_id, domain="service.example.com", destination_ip="192.168.20.50", destination_port=8080, visibility="lan_only")
    db.add_all([node, route])
    await db.flush()
    db.add(EdgeRouteConfig(route_id=route.id, waf_mode="block", tls_source="selfsigned"))
    await db.commit()
    return node, route


async def test_unattached_gateway_renders_lan_route_waf_and_snapshot(db, factories):
    node, route = await lan_route(db, factories)
    payload = await build_edge_desired_state(node.agent_id, db)
    points = payload["traefik_static_config"]["entryPoints"]
    assert set(points) == {"lan", "lansecure"}
    assert points["lan"]["address"] == "192.168.20.110:80"
    assert points["lansecure"]["address"] == "192.168.20.110:443"
    assert points["lansecure"]["forwardedHeaders"] == {"trustedIPs": []}
    assert points["lansecure"]["http"]["middlewares"] == ["wirewarp-strip-forwarded@file"]
    routers = payload["traefik_dynamic_config"]["http"]["routers"]
    assert len(routers) == 1
    router = next(iter(routers.values()))
    assert router["entryPoints"] == ["lansecure"]
    assert "crowdsec-bouncer" in router["middlewares"]
    snapshot = await desired_state_snapshot(node.agent_id, db)
    assert snapshot["routes"][0]["id"] == str(route.id)
    assert snapshot["routes"][0]["visibility"] == "lan_only"


async def test_unattached_gateway_cache_uses_owned_route(db, factories):
    node, route = await lan_route(db, factories)
    db.add(EdgeNodePolicy(agent_id=node.agent_id, policy_json={"cache": {"mode": "standard"}}))
    await db.commit()
    payload = await build_edge_desired_state(node.agent_id, db)
    cache = payload["nginx_cache_config"]
    assert cache["enabled"] is True
    assert cache["routes"][0]["route_id"] == str(route.id)
    assert cache["routes"][0]["origin_url"] == "http://192.168.20.50:8080"


@pytest.mark.parametrize("lan_ip,public_ip", [("0.0.0.0", None), ("192.168.20.110", "192.168.20.110")])
async def test_unsafe_gateway_listener_configuration_is_rejected(db, factories, lan_ip, public_ip):
    node, _ = await lan_route(db, factories)
    node.lan_bind_ip = lan_ip
    node.public_bind_ip = public_ip
    await db.commit()
    with pytest.raises(HTTPException) as error:
        await build_edge_desired_state(node.agent_id, db)
    assert error.value.status_code == 409


async def test_lan_route_is_excluded_from_configured_public_listener(db, factories):
    node, _ = await lan_route(db, factories)
    node.public_bind_ip = "10.21.0.2"
    await db.commit()
    payload = await build_edge_desired_state(node.agent_id, db)
    assert "websecure" not in payload["traefik_static_config"]["entryPoints"]
    assert all(router["entryPoints"] == ["lansecure"] for router in payload["traefik_dynamic_config"]["http"]["routers"].values())

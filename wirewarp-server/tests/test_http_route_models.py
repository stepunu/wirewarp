import uuid

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from app.models.edge_access_event import EdgeAccessEvent
from app.models.edge_fragment import EdgeFragment
from app.models.edge_node import EdgeNode
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_route_config import EdgeRouteConfig
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.models.tunnel_client_attachment import TunnelClientAttachment

pytestmark = pytest.mark.asyncio


async def test_gateway_lan_route_survives_attachment_removal(db, factories):
    server = await factories.make_server(db)
    gateway = await factories.make_client(db)
    attachment = await factories.make_attachment(db, client=gateway, server=server)
    route = HTTPRoute(agent_id=gateway.agent_id, domain="lan.example.test", destination_ip="192.168.20.3", destination_port=8006)
    db.add_all([route, EdgeNode(agent_id=gateway.agent_id)])
    await db.flush()
    config = EdgeRouteConfig(port_forward_id=route.id, waf_mode="block")
    db.add(config)
    await db.commit()
    route_id = route.id
    await db.execute(delete(TunnelClientAttachment).where(TunnelClientAttachment.id == attachment.id))
    await db.commit()
    assert await db.get(HTTPRoute, route_id) is not None
    assert config.route_id == route_id
    assert (await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.port_forward_id == route_id))).waf_mode == "block"


async def test_public_ingress_requires_attachment_cleanup_without_deleting_route(db, factories):
    server = await factories.make_server(db)
    gateway = await factories.make_client(db)
    attachment = await factories.make_attachment(db, client=gateway, server=server)
    route = HTTPRoute(agent_id=gateway.agent_id, domain="public.example.test", destination_ip="192.168.20.3", destination_port=80, visibility="both")
    db.add(route)
    await db.flush()
    route_id, attachment_id = route.id, attachment.id
    db.add(HTTPPublicIngress(route_id=route_id, attachment_id=attachment_id))
    await db.commit()
    with pytest.raises(IntegrityError):
        await db.execute(delete(TunnelClientAttachment).where(TunnelClientAttachment.id == attachment_id))
    await db.rollback()
    await db.execute(delete(HTTPPublicIngress).where(HTTPPublicIngress.route_id == route_id))
    await db.execute(delete(TunnelClientAttachment).where(TunnelClientAttachment.id == attachment_id))
    await db.commit()
    assert await db.get(HTTPRoute, route_id) is not None


async def test_http_route_delete_preserves_access_event_and_cascades_policy_resources(db, factories):
    gateway = await factories.make_client(db)
    route = HTTPRoute(agent_id=gateway.agent_id, domain="lan.example.test", destination_ip="192.168.20.3", destination_port=80)
    db.add(route)
    await db.flush()
    route_id = route.id
    config = EdgeRouteConfig(route_id=route_id)
    rule = EdgePathRule(route_id=route_id, name="admin", match={})
    fragment = EdgeFragment(agent_id=gateway.agent_id, route_id=route_id, name="headers", fragment_type="middleware", content={})
    event = EdgeAccessEvent(agent_id=gateway.agent_id, route_id=route_id)
    db.add_all([config, rule, fragment, event])
    await db.commit()
    config_id, rule_id, fragment_id, event_id = config.id, rule.id, fragment.id, event.id
    await db.execute(delete(HTTPRoute).where(HTTPRoute.id == route_id))
    await db.commit()
    db.expire_all()
    assert await db.get(EdgeRouteConfig, config_id) is None
    assert await db.get(EdgePathRule, rule_id) is None
    assert await db.get(EdgeFragment, fragment_id) is None
    assert (await db.get(EdgeAccessEvent, event_id)).route_id is None


async def test_http_route_visibility_constraint(db, factories):
    gateway = await factories.make_client(db)
    db.add(HTTPRoute(id=uuid.uuid4(), agent_id=gateway.agent_id, domain="lan.example.test", destination_ip="192.168.20.3", destination_port=80, visibility="unsafe"))
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()

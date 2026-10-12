import uuid

import pytest
from sqlalchemy import select

from app.models.command_log import CommandLog
from app.models.edge_config_version import EdgeConfigVersion
from app.models.edge_fragment import EdgeFragment
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_profile import EdgeProfile
from app.models.edge_route_config import EdgeRouteConfig
from app.models.http_route import HTTPRoute
from app.services.edge_ops import dispatch_edge_desired_state
from app.services.edge_runtime import rendered_edge_config
from app.websocket.handlers import handle_command_result


async def setup(client, db, factories):
    node = await factories.make_client(db, lan_ip="192.168.20.110")
    assert (await client.post(f"/api/nodes/{node.agent_id}/edge/enable")).status_code == 202
    response = await client.post(f"/api/nodes/{node.agent_id}/edge/routes", json={
        "domain":"app.example.test", "destination_ip":"192.168.20.12", "destination_port":8080,
        "policy":{"tls_source":"selfsigned"},
    })
    assert response.status_code == 201, response.text
    return node, uuid.UUID(response.json()["id"])


@pytest.mark.asyncio
async def test_rollback_restores_route_path_fragment_and_historical_profile(client, db, factories):
    node, route_id = await setup(client, db, factories)
    ec = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.route_id == route_id))
    profile = EdgeProfile(id=uuid.uuid4(), name="Shared", slug="shared", policy_json={"headers":{"customResponseHeaders":{"X-Version":"one"}}})
    db.add(profile)
    await db.flush()
    ec.profile_id = profile.id
    path = EdgePathRule(id=uuid.uuid4(), route_id=route_id, name="api", match={"path_prefix":"/api"}, policy_json={"rate_limit":{"requests":2}})
    fragment = EdgeFragment(id=uuid.uuid4(), agent_id=node.agent_id, route_id=route_id, name="extra", fragment_type="middleware", content={"headers":{"customRequestHeaders":{"X-Version":"one"}}})
    db.add_all([path, fragment])
    await db.commit()
    before, version = await rendered_edge_config(node.agent_id, db)
    version_id = version.id
    route = await db.get(HTTPRoute, route_id)
    route.destination_port = 8081
    path.match = {"path_prefix":"/changed"}
    fragment.content = {"headers":{"customRequestHeaders":{"X-Version":"two"}}}
    profile.policy_json = {"headers":{"customResponseHeaders":{"X-Version":"two"}}}
    await db.commit()
    response = await client.post(f"/api/nodes/{node.agent_id}/edge/versions/{version_id}/rollback")
    assert response.status_code == 200, response.text
    await db.refresh(route);await db.refresh(path);await db.refresh(fragment);await db.refresh(profile);await db.refresh(ec)
    assert route.destination_port == 8080
    assert path.match == {"path_prefix":"/api"}
    assert fragment.content["headers"]["customRequestHeaders"]["X-Version"] == "one"
    assert profile.policy_json["headers"]["customResponseHeaders"]["X-Version"] == "two"
    assert ec.profile_id != profile.id
    restored_profile = await db.get(EdgeProfile, ec.profile_id)
    assert restored_profile.agent_id == node.agent_id
    after, _ = await rendered_edge_config(node.agent_id, db)
    assert after["dynamic"] == before["dynamic"]
    assert after["cache"] == before["cache"]


@pytest.mark.asyncio
async def test_applied_version_requires_owned_command_and_matching_hash(client, db, factories):
    node, _ = await setup(client, db, factories)
    _, command_id = await dispatch_edge_desired_state(node.agent_id, db)
    log = await db.get(CommandLog, uuid.UUID(command_id))
    version = await db.get(EdgeConfigVersion, uuid.UUID(log.params["config_version_id"]))
    assert log.params["desired_hash"] == version.desired_hash
    assert version.applied_at is None
    other = await factories.make_client(db)
    await handle_command_result(str(other.agent_id), {"command_id":command_id,"success":True}, db)
    await db.refresh(version)
    assert version.applied_at is None
    await handle_command_result(str(node.agent_id), {"command_id":command_id,"success":True}, db)
    await db.refresh(version)
    assert version.applied_at is not None and version.agent_result == "applied"
    _, second_id = await dispatch_edge_desired_state(node.agent_id, db)
    await handle_command_result(str(node.agent_id), {"command_id":second_id,"success":False}, db)
    await db.refresh(version)
    assert version.applied_at is None and version.agent_result == "failed"


@pytest.mark.asyncio
async def test_snapshot_validation_preserves_absent_route_config(client, db, factories):
    node, route_id = await setup(client, db, factories)
    ec = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.route_id == route_id))
    route = await db.get(HTTPRoute, route_id)
    route.active = False
    await db.delete(ec)
    await db.commit()
    _, version = await rendered_edge_config(node.agent_id, db)
    response = await client.post(f"/api/nodes/{node.agent_id}/edge/versions/{version.id}/rollback")
    assert response.status_code == 200, response.text
    assert await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.route_id == route_id)) is None


@pytest.mark.asyncio
async def test_snapshot_validation_preserves_inactive_public_ingress(client, db, factories):
    from tests.test_edge_runtime_api import _server_route
    from app.models.http_public_ingress import HTTPPublicIngress
    node, route = await _server_route(client, db, factories)
    route_id = uuid.UUID(route["id"])
    ingress = await db.get(HTTPPublicIngress, route_id)
    ingress.active = False
    await db.commit()
    _, version = await rendered_edge_config(node.agent_id, db)
    response = await client.post(f"/api/nodes/{node.agent_id}/edge/versions/{version.id}/rollback")
    assert response.status_code == 200, response.text
    await db.refresh(ingress)
    assert ingress.active is False

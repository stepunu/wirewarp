from datetime import datetime, timezone
import json
import uuid

import pytest
from sqlalchemy import select

from app.models.command_log import CommandLog
from app.models.edge_config_version import EdgeConfigVersion
from app.models.edge_fragment import EdgeFragment
from app.models.edge_migration import EdgeMigration
from app.models.edge_node import EdgeNode
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_profile import EdgeProfile
from app.models.edge_route_config import EdgeRouteConfig
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.services.edge_migration import desired_hash, route_bundle
from app.services.edge_relay_ops import load_relay_routes

pytestmark = pytest.mark.asyncio
ROOT = "/api/edge/migrations"


async def fixture(db, factories):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    gateway = await factories.make_client(db)
    attachment = await factories.make_attachment(db, client=gateway, server=server)
    db.add(EdgeNode(agent_id=gateway.agent_id, edge_mode="security_edge", edge_state="enabled", lan_bind_ip=gateway.lan_ip, public_bind_ip=attachment.tunnel_ip))
    source_profile = EdgeProfile(name="source", slug="source", scope="node", agent_id=server.agent_id, policy_json={"headers": {"customResponseHeaders": {"X-Source": "yes"}}})
    pool = EdgeUpstreamPool(agent_id=server.agent_id, name="origins", servers=[{"url": "http://192.168.1.20:8080"}])
    db.add_all([source_profile, pool])
    await db.flush()
    db.add_all([EdgeNodePolicy(agent_id=server.agent_id, default_profile_id=source_profile.id, policy_json={"waf_mode": "observe"}), EdgeNodePolicy(agent_id=gateway.agent_id, policy_json={"waf_mode": "block", "origin": {"retry_attempts": 99}})])
    route = HTTPRoute(agent_id=server.agent_id, domain="app.example.test", destination_ip="192.168.1.20", destination_port=8080, active=True, visibility="public_only", description="source")
    db.add(route)
    await db.flush()
    config = EdgeRouteConfig(route_id=route.id, auth_mode="basic", auth_config={"users": ["synthetic-private-auth-value"]}, imported_router_name="old-imported-router", imported_service_name="old-service", imported_middlewares=["old-middleware"], import_warnings=["preserved warning"], policy_json={"origin": {"upstream_pool_id": str(pool.id)}, "access": {"auth_mode": "basic", "auth_config": {"users": ["synthetic-private-auth-value"]}}})
    path = EdgePathRule(route_id=route.id, name="admin", match={"path_prefix": "/admin"}, policy_json={"waf_mode": "block"})
    fragment = EdgeFragment(agent_id=server.agent_id, route_id=route.id, name="origin-headers", fragment_type="middleware", content={"headers": {"customResponseHeaders": {"X-Fragment": "yes"}}})
    db.add_all([config, path, fragment, HTTPPublicIngress(route_id=route.id, attachment_id=attachment.id, public_port=443)])
    await db.commit()
    return server, gateway, attachment, route, config, path, fragment


def request_body(gateway, attachment, route):
    return {"source_route_id": str(route.id), "target_agent_id": str(gateway.agent_id), "target_attachment_id": str(attachment.id), "visibility": "both"}


async def start(client, db, factories):
    topology = await fixture(db, factories)
    server, gateway, attachment, route, *_ = topology
    body = request_body(gateway, attachment, route)
    preview = await client.post(ROOT + "/preview", json=body)
    assert preview.status_code == 200, preview.text
    body["expected_source_fingerprint"] = preview.json()["source_fingerprint"]
    response = await client.post(ROOT, json=body)
    assert response.status_code == 201, response.text
    return topology, response.json()


async def action(client, state, name):
    response = await client.post(f"{ROOT}/{state['id']}/{name}", json={"revision": state["revision"]})
    return response


async def applied(db, command_id):
    command = await db.get(CommandLog, uuid.UUID(command_id))
    command.success = True
    version = await db.get(EdgeConfigVersion, uuid.UUID(command.params["config_version_id"]))
    version.applied_at = datetime.now(timezone.utc)
    version.agent_result = "applied"
    await db.commit()


async def provision_and_ack(client, db, state):
    response = await action(client, state, "provision")
    assert response.status_code == 200, response.text
    state = response.json()
    record = await db.get(EdgeMigration, uuid.UUID(state["id"]))
    await applied(db, str(record.stage_command_id))
    return state


async def test_first_public_migration_assigns_listener_only_on_provision(client, db, factories):
    server, gateway, attachment, route, *_ = await fixture(db, factories)
    target = await db.get(EdgeNode, gateway.agent_id)
    target.public_bind_ip = None
    await db.commit()
    body = request_body(gateway, attachment, route)
    response = await client.post(f"{ROOT}/preview", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["planned_changes"]["public_bind_ip"] == {"before": None, "after": attachment.tunnel_ip, "assigned_on_provision": True}
    body["expected_source_fingerprint"] = response.json()["source_fingerprint"]
    response = await client.post(ROOT, json=body)
    assert response.status_code == 201, response.text
    assert (await db.get(EdgeNode, gateway.agent_id)).public_bind_ip is None
    response = await action(client, response.json(), "provision")
    assert response.status_code == 200, response.text
    await db.refresh(target)
    assert target.public_bind_ip == attachment.tunnel_ip
    assert (await db.get(HTTPRoute, route.id)).agent_id == server.agent_id


async def test_stage_requires_current_reviewed_source_fingerprint(client, db, factories, fake_manager):
    _, gateway, attachment, route, config, *_ = await fixture(db, factories)
    body = request_body(gateway, attachment, route)
    preview = await client.post(ROOT + "/preview", json=body)
    assert preview.status_code == 200, preview.text
    missing = await client.post(ROOT, json=body)
    assert missing.status_code == 422, missing.text
    body["expected_source_fingerprint"] = preview.json()["source_fingerprint"]
    config.import_warnings = ["Changed after preview"]
    await db.commit()
    stale = await client.post(ROOT, json=body)
    assert stale.status_code == 409, stale.text
    assert "Preview" in stale.json()["detail"]
    assert not list((await db.scalars(select(EdgeMigration))).all())
    assert not fake_manager.sent
    fresh = await client.post(ROOT + "/preview", json=request_body(gateway, attachment, route))
    body["expected_source_fingerprint"] = fresh.json()["source_fingerprint"]
    accepted = await client.post(ROOT, json=body)
    assert accepted.status_code == 201, accepted.text


async def probe_and_ack(client, db, state, *, valid=True):
    response = await action(client, state, "test")
    assert response.status_code == 200, response.text
    state = response.json()
    command = await db.get(CommandLog, uuid.UUID(state["test_command_id"]))
    command.success = True
    command.output = json.dumps({**command.params, "status": "verified", "tls_verified": valid, "upstream_reachable": True, "route_response_received": True})
    await db.commit()
    return state


async def test_preview_and_stage_preserve_source_without_dispatch_or_secret_exposure(client, db, factories, fake_manager):
    server, gateway, attachment, route, config, path, fragment = await fixture(db, factories)
    route = await db.scalar(select(HTTPRoute).where(HTTPRoute.id == route.id))
    from app.services.edge_migration import load_route
    route = await load_route(db, route.id)
    original = desired_hash(await route_bundle(db, route))
    body = request_body(gateway, attachment, route)
    preview = await client.post(ROOT + "/preview", json=body)
    assert preview.status_code == 200, preview.text
    assert "synthetic-private-auth-value" not in preview.text
    assert not fake_manager.sent
    body["expected_source_fingerprint"] = preview.json()["source_fingerprint"]
    response = await client.post(ROOT, json=body)
    assert response.status_code == 201, response.text
    assert "synthetic-private-auth-value" not in response.text
    assert not fake_manager.sent
    source = await load_route(db, route.id)
    assert desired_hash(await route_bundle(db, source)) == original
    staged = await load_route(db, uuid.UUID(response.json()["stage_route_id"]))
    assert staged.id != route.id and staged.agent_id == gateway.agent_id
    assert staged.active is False and staged.public_ingress.active is False
    assert staged.edge_route_config.inherit_node_policy is False
    assert staged.edge_route_config.imported_router_name == "old-imported-router"
    assert source.edge_route_config.id == config.id
    assert (await db.get(EdgePathRule, path.id)).route_id == route.id
    assert (await db.get(EdgeFragment, fragment.id)).agent_id == server.agent_id


async def test_provision_reserves_unpublished_listener_and_freezes_source_policy(client, db, factories, fake_manager):
    topology, state = await start(client, db, factories)
    server, gateway, attachment, route, *_ = topology
    response = await action(client, state, "provision")
    assert response.status_code == 200, response.text
    record = await db.get(EdgeMigration, uuid.UUID(state["id"]))
    command = await db.get(CommandLog, record.stage_command_id)
    assert command.params["traefik_static_config"]["entryPoints"]["websecure"]["address"] == attachment.tunnel_ip + ":443"
    assert not await load_relay_routes(db, server.agent_id)
    assert (await db.get(HTTPRoute, route.id)).agent_id == server.agent_id
    dynamic = command.params["traefik_dynamic_config"]["http"]
    service = dynamic["services"]["svc-app-example-test"]
    assert service["loadBalancer"]["servers"] == [{"url": "http://192.168.1.20:8080"}]
    assert not any(value.get("retry", {}).get("attempts") == 99 for value in dynamic["middlewares"].values())


async def test_switch_requires_real_owned_ack_and_current_tls_probe(client, db, factories, fake_manager):
    topology, state = await start(client, db, factories)
    route = topology[3]
    response = await action(client, state, "provision")
    assert response.status_code == 200, response.text
    state = response.json()
    rejected = await action(client, state, "finalize")
    assert rejected.status_code == 409
    record = await db.get(EdgeMigration, uuid.UUID(state["id"]))
    # An old applied version cannot replace this pending command acknowledgement.
    version = await db.get(EdgeConfigVersion, record.stage_version_id)
    version.applied_at = datetime.now(timezone.utc)
    version.agent_result = "applied"
    await db.commit()
    rejected = await action(client, state, "test")
    assert rejected.status_code == 409
    await applied(db, str(record.stage_command_id))
    state = await probe_and_ack(client, db, state, valid=False)
    rejected = await action(client, state, "finalize")
    assert rejected.status_code == 409
    assert (await db.get(HTTPRoute, route.id)).agent_id == topology[0].agent_id


async def test_verified_switch_and_rollback_preserve_original_uuid_policy_and_fragments(client, db, factories, fake_manager):
    topology, state = await start(client, db, factories)
    server, gateway, _, route, config, path, fragment = topology
    state = await provision_and_ack(client, db, state)
    state = await probe_and_ack(client, db, state)
    response = await action(client, state, "finalize")
    assert response.status_code == 200, response.text
    state = response.json()
    moved = await db.get(HTTPRoute, route.id, populate_existing=True)
    assert moved.agent_id == gateway.agent_id and moved.visibility == "both"
    assert (await db.get(EdgeRouteConfig, config.id, populate_existing=True)).route_id == route.id
    assert (await db.get(EdgeFragment, fragment.id, populate_existing=True)).agent_id == gateway.agent_id
    assert (await db.get(EdgePathRule, path.id, populate_existing=True)).route_id == route.id
    assert state["phase"] == "switched" and not state["runtime_verified"]
    record = await db.get(EdgeMigration, uuid.UUID(state["id"]))
    for metadata in record.final_version_ids.values():
        await applied(db, metadata["command_id"])
    response = await client.get(ROOT + "/" + state["id"])
    assert response.json()["phase"] == "completed", response.text
    state = response.json()
    response = await action(client, state, "rollback")
    assert response.status_code == 200, response.text
    state = response.json()
    restored = await db.get(HTTPRoute, route.id, populate_existing=True)
    assert restored.agent_id == server.agent_id and restored.visibility == "public_only"
    restored_config = await db.get(EdgeRouteConfig, config.id, populate_existing=True)
    assert restored_config.auth_config == {"users": ["synthetic-private-auth-value"]}
    assert restored_config.imported_router_name == "old-imported-router"
    assert restored_config.inherit_node_policy is True
    assert (await db.get(EdgeFragment, fragment.id, populate_existing=True)).agent_id == server.agent_id
    assert state["phase"] == "rollback_pending" and not state["runtime_verified"]


async def test_migration_rejects_wrong_gateway_attachment_and_gateway_source(client, db, factories):
    server, gateway, attachment, route, *_ = await fixture(db, factories)
    other = await factories.make_client(db)
    rejected = await client.post(ROOT + "/preview", json=request_body(other, attachment, route))
    assert rejected.status_code == 400
    route.agent_id = gateway.agent_id
    route.visibility = "lan_only"
    await db.commit()
    rejected = await client.post(ROOT + "/preview", json=request_body(gateway, attachment, route))
    assert rejected.status_code == 409


async def test_mutation_after_stage_and_stale_revision_cannot_switch(client, db, factories):
    topology, state = await start(client, db, factories)
    state = await provision_and_ack(client, db, state)
    state = await probe_and_ack(client, db, state)
    rejected = await client.post(ROOT + "/" + state["id"] + "/finalize", json={"revision": 1})
    assert rejected.status_code == 409
    topology[4].import_warnings = ["changed after stage"]
    await db.commit()
    rejected = await action(client, state, "finalize")
    assert rejected.status_code == 409
    assert (await db.get(HTTPRoute, topology[3].id)).agent_id == topology[0].agent_id


async def test_operator_can_preview_but_cannot_stage(operator_client, db, factories):
    _, gateway, attachment, route, *_ = await fixture(db, factories)
    body = request_body(gateway, attachment, route)
    preview = await operator_client.post(ROOT + "/preview", json=body)
    assert preview.status_code == 200
    rejected = await operator_client.post(ROOT, json=body)
    assert rejected.status_code == 403


async def test_cancel_removes_only_owned_clones_and_allows_new_preview_after_discard(client, db, factories):
    topology, state = await start(client, db, factories)
    source_profile_id = (await db.get(EdgeNodePolicy, topology[0].agent_id)).default_profile_id
    record = await db.get(EdgeMigration, uuid.UUID(state["id"]))
    clone_profile_id = uuid.UUID(next(iter(record.resource_map["profiles"].values())))
    clone_pool_id = uuid.UUID(next(iter(record.resource_map["pools"].values())))
    canceled = await action(client, state, "cancel")
    assert canceled.status_code == 200, canceled.text
    state = canceled.json()
    assert state["phase"] == "canceled"
    assert await db.get(EdgeProfile, source_profile_id) is not None
    assert await db.get(EdgeProfile, clone_profile_id, populate_existing=True) is None
    assert await db.get(EdgeUpstreamPool, clone_pool_id, populate_existing=True) is None
    assert await db.get(EdgeRouteConfig, topology[4].id) is not None
    discarded = await client.delete(ROOT + "/" + state["id"], params={"revision": state["revision"]})
    assert discarded.status_code == 204
    again = await client.post(ROOT + "/preview", json=request_body(topology[1], topology[2], topology[3]))
    assert again.status_code == 200, again.text


async def test_provisioned_cancel_is_pending_until_gateway_cleanup_ack(client, db, factories):
    topology, state = await start(client, db, factories)
    state = await provision_and_ack(client, db, state)
    canceled = await action(client, state, "cancel")
    assert canceled.status_code == 200, canceled.text
    state = canceled.json()
    assert state["phase"] == "cancel_pending" and not state["runtime_verified"]
    rejected = await client.delete(ROOT + "/" + state["id"], params={"revision": state["revision"]})
    assert rejected.status_code == 409
    record = await db.get(EdgeMigration, uuid.UUID(state["id"]))
    for metadata in record.final_version_ids.values():
        await applied(db, metadata["command_id"])
    read = await client.get(ROOT + "/" + state["id"])
    assert read.json()["phase"] == "canceled", read.text
    assert (await db.get(HTTPRoute, topology[3].id)).agent_id == topology[0].agent_id


async def test_path_only_global_fragment_remains_explicit_and_rollback_keeps_other_consumer(client, db, factories):
    server, gateway, attachment, route, config, path, _ = await fixture(db, factories)
    global_fragment = EdgeFragment(agent_id=server.agent_id, route_id=None, name="path-only", fragment_type="middleware", content={"headers": {"customResponseHeaders": {"X-Path-Only": "yes"}}})
    path.policy_json = {"middlewares": ["path-only"]}
    db.add(global_fragment)
    await db.commit()
    body = request_body(gateway, attachment, route)
    preview = await client.post(ROOT + "/preview", json=body)
    assert preview.status_code == 200, preview.text
    body["expected_source_fingerprint"] = preview.json()["source_fingerprint"]
    created = await client.post(ROOT, json=body)
    assert created.status_code == 201, created.text
    state = await provision_and_ack(client, db, created.json())
    record = await db.get(EdgeMigration, uuid.UUID(state["id"]))
    clone_fragment_id = uuid.UUID(record.resource_map["fragments"][str(global_fragment.id)])
    assert (await db.get(EdgeFragment, clone_fragment_id)).route_id is None
    command = await db.get(CommandLog, record.stage_command_id)
    routers = command.params["traefik_dynamic_config"]["http"]["routers"]
    fragment_name = f"fragment-{clone_fragment_id}"
    assert fragment_name not in routers["app-example-test"]["middlewares"]
    assert fragment_name in next(item["middlewares"] for name, item in routers.items() if "-path-" in name)
    state = await probe_and_ack(client, db, state)
    finalized = await action(client, state, "finalize")
    assert finalized.status_code == 200, finalized.text
    state = finalized.json()
    # A later gateway route can use this cloned node fragment. Rollback must retain it.
    other_route = HTTPRoute(agent_id=gateway.agent_id, domain="other.example.test", destination_ip="192.168.1.30", destination_port=80, active=True, visibility="lan_only")
    db.add(other_route)
    await db.flush()
    db.add(EdgeRouteConfig(route_id=other_route.id, policy_json={"middlewares": ["path-only"]}))
    await db.commit()
    rolled = await action(client, state, "rollback")
    assert rolled.status_code == 200, rolled.text
    assert await db.get(EdgeFragment, global_fragment.id, populate_existing=True) is not None
    assert await db.get(EdgeFragment, clone_fragment_id, populate_existing=True) is not None

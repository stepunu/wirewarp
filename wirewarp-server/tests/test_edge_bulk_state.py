import uuid

import pytest
from sqlalchemy import select

from app.models.command_log import CommandLog
from app.models.http_route import HTTPRoute
from tests.test_edge_config_snapshots import setup

pytestmark = pytest.mark.asyncio


async def test_bulk_creates_referenced_resources_atomically_and_reports_offline(client, db, factories):
    node, _ = await setup(client, db, factories)
    route_id, pool_id, path_id = [str(uuid.uuid4()) for _ in range(3)]
    body = {
        "routes": [{"id":route_id, "domain":"pool.example.test", "destination_ip":"192.168.20.12", "destination_port":8080,
                    "policy":{"tls_source":"selfsigned", "origin":{"upstream_pool_id":pool_id}}}],
        "upstream_pools":[{"id":pool_id, "name":"pool", "servers":[{"url":"http://192.168.20.13:8080"}]}],
        "path_rules":[{"id":path_id, "route_id":route_id, "name":"api", "match":{"path_prefix":"/api"}, "policy":{"rate_limit":{"requests":3}}}],
    }
    url = f"/api/nodes/{node.agent_id}/edge/desired-state"
    before_logs = len((await db.scalars(select(CommandLog))).all())
    preview = await client.put(url + "?dry_run=true&return_diff=true", json=body)
    assert preview.status_code == 200, preview.text
    assert preview.json()["validation_errors"] == []
    assert await db.get(HTTPRoute, uuid.UUID(route_id)) is None
    assert len((await db.scalars(select(CommandLog))).all()) == before_logs
    result = await client.put(url, json=body)
    assert result.status_code == 200, result.text
    assert result.json()["reconcile_sent"] is False
    assert any(row["id"] == path_id for row in result.json()["path_rules"])
    rendered = await client.get(f"/api/nodes/{node.agent_id}/edge/rendered")
    services = rendered.json()["dynamic"]["http"]["services"]
    assert any(service.get("loadBalancer", {}).get("servers") == [{"url":"http://192.168.20.13:8080"}] for service in services.values())
    # An invalid update must preserve the complete stored batch.
    body["path_rules"][0]["match"] = {"unknown":"/bad"}
    rejected = await client.put(url, json=body)
    assert rejected.status_code == 422, rejected.text
    current = (await client.get(url)).json()
    assert next(row for row in current["path_rules"] if row["id"] == path_id)["match"] == {"path_prefix":"/api"}


async def test_validate_checks_saved_configuration(client, db, factories):
    node, route_id = await setup(client, db, factories)
    from app.models.edge_route_config import EdgeRouteConfig
    config = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.route_id == route_id))
    config.policy_json = {"unsupported":True}
    await db.commit()
    result = await client.post(f"/api/nodes/{node.agent_id}/edge/validate")
    assert result.status_code == 422
    assert result.json()["detail"]["code"] == "edge_policy_invalid"


async def test_sensitive_export_is_explicit_and_masked_import_is_rejected(client, db, factories):
    node, route_id = await setup(client, db, factories)
    from app.models.edge_route_config import EdgeRouteConfig
    config = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.route_id == route_id))
    config.policy_json = {"tls_source":"selfsigned", "headers":{"customRequestHeaders":{"Authorization":"synthetic-test-credential"}}}
    await db.commit()
    url = f"/api/nodes/{node.agent_id}/edge/desired-state"
    masked = await client.get(url)
    assert masked.status_code == 200
    assert masked.json()["contains_credentials"] is True
    assert masked.json()["sensitive_values_redacted"] is True
    assert "synthetic-test-credential" not in masked.text
    rendered = await client.get(f"/api/nodes/{node.agent_id}/edge/rendered")
    assert "synthetic-test-credential" not in rendered.text
    assert "[redacted]" in rendered.text
    unmasked = await client.get(url + "?include_sensitive=true")
    assert unmasked.json()["sensitive_values_redacted"] is False
    assert "synthetic-test-credential" in unmasked.text
    rejected = await client.put(url, json=masked.json())
    assert rejected.status_code == 422
    assert "masked configuration" in rejected.json()["detail"]
    await db.refresh(config)
    assert config.policy_json["headers"]["customRequestHeaders"]["Authorization"] == "synthetic-test-credential"


async def test_route_cache_desired_metadata_matches_payload_without_faking_stop(client, db, factories):
    from app.models.edge_component_state import EdgeComponentState
    from app.services.edge_ops import dispatch_edge_desired_state
    node, route_id = await setup(client, db, factories)
    result = await client.patch(f"/api/nodes/{node.agent_id}/edge/routes/{route_id}", json={
        "policy":{"tls_source":"selfsigned", "cache":{"mode":"proxy_cache", "edge_ttl_seconds":30}},
    })
    assert result.status_code == 200, result.text
    state = await db.scalar(select(EdgeComponentState).where(EdgeComponentState.agent_id == node.agent_id, EdgeComponentState.component == "nginx_cache"))
    assert state.desired == "enabled"
    state.running = True
    state.phase = "healthy"
    route = await db.get(HTTPRoute, route_id)
    route.active = False
    await db.commit()
    await dispatch_edge_desired_state(node.agent_id, db)
    await db.refresh(state)
    assert state.desired == "disabled"
    assert state.running is True
    assert state.phase == "pending"

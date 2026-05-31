from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.edge_access_event import EdgeAccessEvent
from app.services.edge_runtime import digest
from app.websocket.handlers import dispatch


pytestmark = pytest.mark.asyncio


async def _server_route(client, db, factories):
    server = await factories.make_server(
        db,
        edge_mode="security_edge",
        edge_state="enabled",
        edge_install_phase="healthy",
    )
    gateway = await factories.make_client(db)
    attachment = await factories.make_attachment(db, client=gateway, server=server)
    route = await client.put(
        f"/api/nodes/{server.agent_id}/edge/routes/by-domain/app.example.com",
        json={
            "attachment_id": str(attachment.id),
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
            "policy": {"waf_mode": "block"},
        },
    )
    assert route.status_code == 200, route.text
    return server, route.json()


async def test_access_events_filter_by_node_host_status_and_action(client, db, factories):
    server, route = await _server_route(client, db, factories)
    db.add_all(
        [
            EdgeAccessEvent(
                agent_id=server.agent_id,
                route_id=route["id"],
                request_id="req-1",
                occurred_at=datetime.now(timezone.utc),
                host="app.example.com",
                path="/",
                method="GET",
                status_code=200,
                client_ip="198.51.100.10",
                action="pass",
                source="traefik",
                latency_ms=12,
                cache_status="not_configured",
            ),
            EdgeAccessEvent(
                agent_id=server.agent_id,
                route_id=route["id"],
                request_id="req-2",
                occurred_at=datetime.now(timezone.utc),
                host="app.example.com",
                path="/.env",
                method="GET",
                status_code=403,
                client_ip="198.51.100.11",
                action="block",
                source="appsec",
                latency_ms=4,
                cache_status="not_configured",
            ),
        ]
    )
    await db.commit()

    resp = await client.get(
        f"/api/nodes/{server.agent_id}/edge/access-events?host=app.example.com&status=403&action=block"
    )

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["path"] == "/.env"
    assert body["items"][0]["action"] == "block"


async def test_websocket_edge_access_events_persist_and_query(client, db, factories):
    server, route = await _server_route(client, db, factories)

    await dispatch(
        str(server.agent_id),
        {
            "type": "edge_access_events",
            "events": [
                {
                    "route_id": route["id"],
                    "request_id": "req-json",
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "host": "app.example.com",
                    "path": "/api",
                    "method": "POST",
                    "status_code": 201,
                    "client_ip": "203.0.113.20",
                    "action": "pass",
                    "source": "traefik",
                    "latency_ms": 42,
                    "cache_status": "bypass",
                }
            ],
        },
        db,
    )

    resp = await client.get(f"/api/nodes/{server.agent_id}/edge/access-events?method=POST")
    assert resp.status_code == 200
    assert resp.json()["items"][0]["request_id"] == "req-json"
    assert resp.json()["items"][0]["cache_status"] == "bypass"


async def test_edge_cache_status_enables_proxy_cache_desired_state_and_rendered_hash(
    client, db, factories, fake_manager
):
    server, _route = await _server_route(client, db, factories)
    fake_manager.online.add(str(server.agent_id))

    await dispatch(
        str(server.agent_id),
        {
            "type": "edge_cache_status",
            "backend": "nginx_proxy_cache",
            "installed": True,
            "running": True,
            "phase": "healthy",
            "version": "1.24.0",
            "cache_path": "/var/cache/wirewarp/nginx",
            "current_size_bytes": 4096,
            "max_size_bytes": 1073741824,
            "last_test_status": "miss_hit",
        },
        db,
    )

    patched = await client.patch(
        f"/api/nodes/{server.agent_id}/edge/cache",
        json={
            "mode": "proxy_cache",
            "browser_ttl_seconds": 120,
            "edge_ttl_seconds": 600,
            "cache_status_header": True,
        },
    )

    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["available"] is True
    assert body["backend"]["phase"] == "healthy"
    assert body["backend"]["last_test_status"] == "miss_hit"

    sent = fake_manager.sent[-1]["message"]
    assert sent["type"] == "edge_desired_state"
    cache_config = sent["params"]["nginx_cache_config"]
    assert cache_config["enabled"] is True
    assert cache_config["mode"] == "proxy_cache"
    assert cache_config["routes"][0]["host"] == "app.example.com"
    assert cache_config["routes"][0]["origin_url"] == "http://192.168.1.10:8080"

    service = sent["params"]["traefik_dynamic_config"]["http"]["services"]["svc-app-example-com"]
    assert service["loadBalancer"]["servers"][0]["url"] == "http://127.0.0.1:18080"

    rendered = await client.get(f"/api/nodes/{server.agent_id}/edge/rendered")
    assert rendered.status_code == 200, rendered.text
    assert rendered.json()["cache_hash"] != digest({})


async def test_access_events_filter_by_route_country_and_time_range(client, db, factories):
    server, route = await _server_route(client, db, factories)
    now = datetime.now(timezone.utc)
    db.add_all(
        [
            EdgeAccessEvent(
                agent_id=server.agent_id,
                route_id=route["id"],
                occurred_at=now - timedelta(minutes=5),
                host="app.example.com",
                path="/login",
                method="POST",
                status_code=429,
                client_ip="198.51.100.50",
                client_country="US",
                action="rate_limit",
                source="traefik",
            ),
            EdgeAccessEvent(
                agent_id=server.agent_id,
                route_id=route["id"],
                occurred_at=now - timedelta(days=3),
                host="app.example.com",
                path="/old",
                method="GET",
                status_code=200,
                client_ip="198.51.100.51",
                client_country="DE",
                action="pass",
                source="traefik",
            ),
        ]
    )
    await db.commit()

    resp = await client.get(
        "/api/edge/access-events",
        params={
            "route_id": route["id"],
            "country": "US",
            "since": (now - timedelta(hours=1)).isoformat(),
            "until": (now + timedelta(minutes=1)).isoformat(),
        },
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["path"] == "/login"
    assert body["items"][0]["client_country"] == "US"


async def test_cache_headers_only_is_allowed_but_real_purge_requires_backend(client, db, factories):
    server, _route = await _server_route(client, db, factories)

    patched = await client.patch(
        f"/api/nodes/{server.agent_id}/edge/cache",
        json={"mode": "headers_only", "browser_ttl_seconds": 300},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["policy"]["mode"] == "headers_only"
    assert patched.json()["available"] is True

    purge = await client.post(
        f"/api/nodes/{server.agent_id}/edge/cache/purge",
        json={"scope": "node"},
    )
    assert purge.status_code == 409
    assert purge.json()["detail"]["code"] == "edge_cache_unavailable"


async def test_rendered_versions_fragments_and_desired_state_dry_run(client, db, factories):
    server, route = await _server_route(client, db, factories)

    rendered = await client.get(f"/api/nodes/{server.agent_id}/edge/rendered")
    assert rendered.status_code == 200, rendered.text
    assert rendered.json()["dynamic_hash"]

    versions = await client.get(f"/api/nodes/{server.agent_id}/edge/versions")
    assert versions.status_code == 200
    assert versions.json()[0]["rendered_dynamic_hash"] == rendered.json()["dynamic_hash"]

    fragment = await client.post(
        f"/api/nodes/{server.agent_id}/edge/fragments",
        json={
            "name": "extra-headers",
            "fragment_type": "middleware",
            "content": {"headers": {"contentTypeNosniff": True}},
            "route_id": route["id"],
        },
    )
    assert fragment.status_code == 201, fragment.text
    assert fragment.json()["validation_state"] == "valid"

    desired = await client.get(f"/api/nodes/{server.agent_id}/edge/desired-state")
    assert desired.status_code == 200
    assert desired.json()["routes"][0]["domain"] == "app.example.com"

    dry_run = await client.put(
        f"/api/nodes/{server.agent_id}/edge/desired-state?dry_run=true&return_diff=true",
        json={"routes": [{"domain": "dry.example.com"}]},
    )
    assert dry_run.status_code == 200
    assert dry_run.json()["dry_run"] is True
    assert "dry.example.com" in dry_run.json()["diff"]


async def test_path_rules_can_update_and_delete_by_id(client, db, factories):
    server, route = await _server_route(client, db, factories)

    created = await client.post(
        f"/api/edge/routes/{route['id']}/path-rules",
        json={
            "name": "api",
            "match": {"type": "prefix", "value": "/api"},
            "priority": 10,
            "policy": {"waf_mode": "observe"},
        },
    )
    assert created.status_code == 201, created.text

    updated = await client.put(
        f"/api/edge/path-rules/{created.json()['id']}",
        json={
            "name": "api",
            "match": {"type": "prefix", "value": "/api/private"},
            "priority": 30,
            "enabled": False,
            "policy": {"waf_mode": "block"},
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["priority"] == 30
    assert updated.json()["enabled"] is False
    assert updated.json()["effective"]["waf_mode"] == "block"

    deleted = await client.delete(f"/api/edge/path-rules/{created.json()['id']}")
    assert deleted.status_code == 204

    listed = await client.get(f"/api/edge/routes/{route['id']}/path-rules")
    assert listed.status_code == 200
    assert listed.json() == []


async def test_upstream_pool_crud_by_node_and_id(client, db, factories):
    server, _route = await _server_route(client, db, factories)

    created = await client.post(
        f"/api/nodes/{server.agent_id}/edge/upstream-pools",
        json={
            "name": "app-pool",
            "description": "primary app backends",
            "servers": [
                {"url": "http://10.21.0.20:8080", "weight": 1},
                {"url": "http://10.21.0.21:8080", "weight": 2},
            ],
            "health_check": {"path": "/healthz", "interval_seconds": 15},
            "policy": {"pass_host_header": True},
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["name"] == "app-pool"
    assert len(created.json()["servers"]) == 2

    listed = await client.get(f"/api/nodes/{server.agent_id}/edge/upstream-pools")
    assert listed.status_code == 200
    assert [row["name"] for row in listed.json()] == ["app-pool"]

    updated = await client.put(
        f"/api/edge/upstream-pools/{created.json()['id']}",
        json={
            "name": "app-pool",
            "description": "updated",
            "servers": [{"url": "http://10.21.0.22:8080", "weight": 1}],
            "health_check": {"path": "/ready"},
            "policy": {"pass_host_header": False},
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["description"] == "updated"
    assert updated.json()["servers"][0]["url"] == "http://10.21.0.22:8080"

    deleted = await client.delete(f"/api/edge/upstream-pools/{created.json()['id']}")
    assert deleted.status_code == 204


async def test_desired_state_apply_updates_routes_and_profiles(client, db, factories):
    server, route = await _server_route(client, db, factories)

    applied = await client.put(
        f"/api/nodes/{server.agent_id}/edge/desired-state?return_diff=true",
        json={
            "profiles": [
                {
                    "slug": "api-profile",
                    "name": "API profile",
                    "policy": {"waf_mode": "observe"},
                }
            ],
            "routes": [
                {
                    "id": route["id"],
                    "domain": "app.example.com",
                    "enabled": False,
                    "destination_ip": "192.168.1.20",
                    "destination_port": 9090,
                    "profile": "api-profile",
                    "policy": {"waf_mode": "observe"},
                }
            ],
        },
    )
    assert applied.status_code == 200, applied.text
    assert applied.json()["changed"] is True
    assert "192.168.1.20" in applied.json()["diff"]

    fetched = await client.get(f"/api/edge/routes/{route['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["enabled"] is False
    assert fetched.json()["destination_ip"] == "192.168.1.20"
    assert fetched.json()["destination_port"] == 9090
    assert fetched.json()["effective"]["waf_mode"] == "observe"

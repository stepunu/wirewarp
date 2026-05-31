from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.models.edge_access_event import EdgeAccessEvent


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

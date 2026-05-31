from __future__ import annotations

import pytest


pytestmark = pytest.mark.asyncio


async def _security_edge_server_with_attachment(db, factories):
    server = await factories.make_server(
        db,
        edge_mode="security_edge",
        edge_state="enabled",
        edge_install_phase="healthy",
    )
    gateway = await factories.make_client(db)
    attachment = await factories.make_attachment(db, client=gateway, server=server)
    return server, gateway, attachment


async def test_profiles_put_is_idempotent(client, db):
    first = await client.put(
        "/api/edge/profiles/public-app",
        json={
            "name": "Public app",
            "scope": "global",
            "policy": {"waf_mode": "block", "rate_limit": {"requests": 100}},
        },
    )
    assert first.status_code == 200, first.text
    assert first.json()["slug"] == "public-app"
    assert first.json()["policy"]["waf_mode"] == "block"

    second = await client.put(
        "/api/edge/profiles/public-app",
        json={
            "name": "Public app v2",
            "scope": "global",
            "policy": {"waf_mode": "observe"},
        },
    )
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["name"] == "Public app v2"
    assert second.json()["policy"]["waf_mode"] == "observe"

    listed = await client.get("/api/edge/profiles")
    assert listed.status_code == 200
    assert [row["slug"] for row in listed.json()] == ["public-app"]


async def test_route_by_domain_upsert_and_effective_policy_inheritance(
    client,
    db,
    factories,
    fake_manager,
):
    server, _gateway, attachment = await _security_edge_server_with_attachment(db, factories)
    fake_manager.online.add(str(server.agent_id))

    profile = await client.put(
        "/api/edge/profiles/public-app",
        json={
            "name": "Public app",
            "scope": "global",
            "policy": {
                "waf_mode": "block",
                "rate_limit": {"requests": 100, "burst": 25},
            },
        },
    )
    assert profile.status_code == 200

    node_policy = await client.patch(
        f"/api/nodes/{server.agent_id}/edge/policy",
        json={
            "default_profile_id": profile.json()["id"],
            "cloudflare_mode": "trust_headers",
            "trusted_proxy_cidrs": ["10.0.0.0/8"],
            "policy": {
                "waf_mode": "observe",
                "headers": {"hsts": True},
            },
        },
    )
    assert node_policy.status_code == 200, node_policy.text

    route = await client.put(
        f"/api/nodes/{server.agent_id}/edge/routes/by-domain/app.example.com",
        json={
            "attachment_id": str(attachment.id),
            "enabled": True,
            "profile_id": profile.json()["id"],
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
            "policy": {"rate_limit": {"requests": 10}},
        },
    )
    assert route.status_code == 200, route.text
    body = route.json()
    assert body["domain"] == "app.example.com"
    assert body["enabled"] is True
    assert body["profile_id"] == profile.json()["id"]

    second = await client.put(
        f"/api/nodes/{server.agent_id}/edge/routes/by-domain/app.example.com",
        json={
            "attachment_id": str(attachment.id),
            "destination_ip": "192.168.1.11",
            "destination_port": 8081,
            "policy": {"rate_limit": {"requests": 20}},
        },
    )
    assert second.status_code == 200
    assert second.json()["id"] == body["id"]
    assert second.json()["destination_ip"] == "192.168.1.11"

    effective = await client.get(f"/api/edge/routes/{body['id']}/effective")
    assert effective.status_code == 200
    policy = effective.json()["effective"]
    assert policy["waf_mode"] == "block"
    assert policy["headers"]["hsts"] is True
    assert policy["rate_limit"]["requests"] == 20

    path_rule = await client.post(
        f"/api/edge/routes/{body['id']}/path-rules",
        json={
            "name": "login",
            "match": {"type": "prefix", "value": "/login"},
            "priority": 20,
            "policy": {"waf_mode": "off"},
        },
    )
    assert path_rule.status_code == 201, path_rule.text
    assert path_rule.json()["effective"]["waf_mode"] == "off"
    assert path_rule.json()["effective"]["rate_limit"]["requests"] == 20

    routes = await client.get(f"/api/nodes/{server.agent_id}/edge/routes")
    assert routes.status_code == 200
    assert [row["domain"] for row in routes.json()] == ["app.example.com"]
    assert fake_manager.sent[-1]["message"]["type"] == "edge_desired_state"


async def test_edge_route_create_returns_feature_disabled_for_tcp_udp_node(client, db, factories):
    server = await factories.make_server(db)
    gateway = await factories.make_client(db)
    attachment = await factories.make_attachment(db, client=gateway, server=server)

    resp = await client.put(
        f"/api/nodes/{server.agent_id}/edge/routes/by-domain/app.example.com",
        json={
            "attachment_id": str(attachment.id),
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
        },
    )

    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "edge_feature_disabled"

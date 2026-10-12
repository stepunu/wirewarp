import uuid

import pytest
from sqlalchemy import select

from app.models.http_route import HTTPRoute


CONFIG = """
http:
  routers:
    app:
      rule: Host(`App.example.test`)
      entryPoints: [untrusted]
      service: app
      tls: {}
  services:
    app:
      loadBalancer:
        servers:
          - url: http://192.168.20.12:8080
"""


async def enabled_gateway(client, session_maker, factories):
    async with session_maker() as db:
        gateway = await factories.make_client(db, is_gateway=True, lan_ip="192.168.20.110")
        agent_id = gateway.agent_id
    assert (await client.post(f"/api/nodes/{agent_id}/edge/enable")).status_code == 202
    return agent_id


@pytest.mark.asyncio
async def test_gateway_import_preview_and_apply_without_attachment(client, session_maker, factories, fake_manager):
    agent_id = await enabled_gateway(client, session_maker, factories)
    base = f"/api/nodes/{agent_id}/edge/import/traefik"
    before = len(fake_manager.sent)
    preview = await client.post(base + "/preview", json={"content": CONFIG})
    assert preview.status_code == 200, preview.text
    route = preview.json()["routes"][0]
    assert route["importable"] is True
    assert route["domain"] == "app.example.test"
    assert route["visibility"] == "lan_only"
    assert route["managed_entrypoints"] == ["lan", "lansecure"]
    assert route["action"] == "create"
    assert len(fake_manager.sent) == before
    async with session_maker() as db:
        assert (await db.scalars(select(HTTPRoute))).all() == []
    applied = await client.post(base + "/apply", json={"content": CONFIG})
    assert applied.status_code == 200, applied.text
    assert applied.json()["created"] == 1
    routes = (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json()
    assert len(routes) == 1
    assert routes[0]["visibility"] == "lan_only"
    assert routes[0]["attachment_id"] is None
    assert routes[0]["enabled"] is False
    route_id = routes[0]["id"]
    changed = CONFIG.replace(":8080", ":8081")
    applied = await client.post(base + "/apply", json={"content": changed, "overwrite": True})
    assert applied.status_code == 200, applied.text
    assert applied.json()["updated"] == 1
    routes = (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json()
    assert routes[0]["id"] == route_id
    assert routes[0]["destination_port"] == 8081


@pytest.mark.asyncio
async def test_import_preview_reports_unavailable_public_ingress(client, session_maker, factories):
    agent_id = await enabled_gateway(client, session_maker, factories)
    response = await client.post(f"/api/nodes/{agent_id}/edge/import/traefik/preview",
                                 json={"content": CONFIG, "visibility": "public_only"})
    assert response.status_code == 200, response.text
    route = response.json()["routes"][0]
    assert route["importable"] is False
    assert any("gateway_public_ingress_unavailable" in warning for warning in route["warnings"])
    async with session_maker() as db:
        assert (await db.scalars(select(HTTPRoute))).all() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [CONFIG.replace("Host(`App.example.test`)", "Host(`App.example.test`) && PathPrefix(`/private`)"), CONFIG.replace("Host(`App.example.test`)", "Host(`App.example.test`, `other.example.test`)"), CONFIG.replace("service: app", "service: app\n      middlewares: [missing-auth]")])
async def test_import_does_not_drop_restrictions(client, session_maker, factories, content):
    agent_id = await enabled_gateway(client, session_maker, factories)
    response = await client.post(f"/api/nodes/{agent_id}/edge/import/traefik/apply", json={"content": content})
    assert response.status_code == 200, response.text
    assert response.json()["created"] == 0
    assert response.json()["skipped"] == 1
    async with session_maker() as db:
        assert (await db.scalars(select(HTTPRoute))).all() == []


@pytest.mark.asyncio
async def test_import_rejects_other_url_owner_and_malformed_yaml(client, session_maker, factories):
    agent_id = await enabled_gateway(client, session_maker, factories)
    base = f"/api/nodes/{agent_id}/edge/import/traefik/preview"
    response = await client.post(base, json={"content": CONFIG, "server_id": str(uuid.uuid4())})
    assert response.status_code == 400
    response = await client.post(base, json={"content": "http: ["})
    assert response.status_code == 400

import pytest


async def gateway_route(client, db, factories):
    gateway = await factories.make_client(db, lan_ip="192.168.20.110")
    assert (await client.post(f"/api/nodes/{gateway.agent_id}/edge/enable")).status_code == 202
    response = await client.post(f"/api/nodes/{gateway.agent_id}/edge/routes", json={"domain":"app.example.test", "destination_ip":"192.168.20.12", "destination_port":8080})
    assert response.status_code == 201, response.text
    return gateway.agent_id, response.json()["id"]


@pytest.mark.asyncio
async def test_invalid_active_path_never_persists(client, db, factories):
    _, route_id = await gateway_route(client, db, factories)
    response = await client.post(f"/api/edge/routes/{route_id}/path-rules", json={"name":"bad", "match":{"unknown":"/private"}})
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "edge_policy_invalid"
    assert (await client.get(f"/api/edge/routes/{route_id}/path-rules")).json() == []


@pytest.mark.asyncio
async def test_gateway_middleware_cannot_inject_router_fields(client, db, factories):
    agent_id, route_id = await gateway_route(client, db, factories)
    response = await client.post(f"/api/nodes/{agent_id}/edge/fragments", json={"name":"bad", "fragment_type":"middleware", "route_id":route_id, "content":{"entryPoints":["websecure"]}})
    assert response.status_code == 422, response.text
    assert (await client.get(f"/api/nodes/{agent_id}/edge/fragments")).json() == []


@pytest.mark.asyncio
async def test_unknown_profile_policy_is_rejected_before_storage(client):
    response = await client.post("/api/edge/profiles", json={"name":"bad", "policy":{"unsupported":True}})
    assert response.status_code == 422, response.text
    assert (await client.get("/api/edge/profiles")).json() == []


@pytest.mark.asyncio
async def test_invalid_route_and_node_policy_preserve_saved_state(client, db, factories):
    agent_id, route_id = await gateway_route(client, db, factories)
    before = (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json()
    response = await client.patch(f"/api/nodes/{agent_id}/edge/routes/{route_id}", json={"policy":{"unsupported":True}})
    assert response.status_code == 422, response.text
    assert (await client.get(f"/api/nodes/{agent_id}/edge/routes")).json() == before
    response = await client.patch(f"/api/nodes/{agent_id}/edge/policy", json={"policy":{"unsupported":True}})
    assert response.status_code == 422, response.text
    assert (await client.get(f"/api/nodes/{agent_id}/edge/policy")).json()["policy"] == {}

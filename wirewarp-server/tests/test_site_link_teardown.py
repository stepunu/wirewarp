import json
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.models.command_log import CommandLog
from app.models.site_link import SiteLinkAgentGeneration, SiteLinkAgentState
from app.services.site_link_ops import dispatch_site_links_for_agent, prepare_snapshots
from app.services.agent_commands import send_command
from app.services.site_link_topology import require_unlinked_agent, refresh_site_link_topology
from app.websocket.handlers import dispatch
from tests.test_site_links import topology, apply_all

pytestmark = pytest.mark.asyncio
ROOT = "/api/site-links"


def reviewed(read):
    return {"confirm_restore_normal_forwarding": True, "expected_states": [
        {key: item[key] for key in ("agent_id", "revision", "desired_hash")} for item in read["states"]]}


async def empty_applied(client, db, factories, fake_manager):
    topo = await topology(db, factories, fake_manager)
    response = await client.post(ROOT, json=topo[-1])
    assert response.status_code == 201, response.text
    assert (await client.delete(ROOT + "/" + response.json()["id"])).status_code == 204
    await apply_all(db)
    read = (await client.get(ROOT + "/retained-state")).json()
    assert read["can_teardown"] and not read["has_links"]
    return topo, read


async def receipt(db, agent_id, *, output=None, success=True, authenticated_agent=None):
    command = await db.scalar(select(CommandLog).where(CommandLog.agent_id == uuid.UUID(str(agent_id)), CommandLog.command_type == "site_link_teardown").order_by(CommandLog.executed_at.desc()))
    assert command is not None
    result = {"released": True, "revision": command.params["revision"], "desired_hash": command.params["desired_hash"]}
    await dispatch(str(authenticated_agent or agent_id), {"type": "command_result", "command_id": str(command.id), "success": success, "output": json.dumps(result) if output is None else output}, db)
    return command


async def test_teardown_requires_exact_review_no_links_and_applied_empty_state(client, db, factories, fake_manager):
    topo = await topology(db, factories, fake_manager)
    created = await client.post(ROOT, json=topo[-1])
    await apply_all(db)
    for enabled in (True, False):
        if not enabled:
            assert (await client.patch(ROOT + "/" + created.json()["id"], json={"enabled": False})).status_code == 200
        read = (await client.get(ROOT + "/retained-state")).json()
        assert read["has_links"] and not read["can_teardown"]
        assert (await client.post(ROOT + "/teardown", json=reviewed(read))).status_code == 409
    assert (await client.delete(ROOT + "/" + created.json()["id"])).status_code == 204
    pending = (await client.get(ROOT + "/retained-state")).json()
    assert not pending["can_teardown"]
    assert (await client.post(ROOT + "/teardown", json=reviewed(pending))).status_code == 409
    await apply_all(db)
    read = (await client.get(ROOT + "/retained-state")).json()
    body = reviewed(read)
    body["expected_states"][0]["revision"] += 1
    assert (await client.post(ROOT + "/teardown", json=body)).status_code == 409
    body = reviewed(read)
    body["expected_states"].pop()
    assert (await client.post(ROOT + "/teardown", json=body)).status_code == 409
    body = reviewed(read)
    body["expected_states"].append(body["expected_states"][0])
    assert (await client.post(ROOT + "/teardown", json=body)).status_code == 409
    body = reviewed(read)
    body["confirm_restore_normal_forwarding"] = False
    assert (await client.post(ROOT + "/teardown", json=body)).status_code == 422
    assert not any(item["message"]["type"] == "site_link_teardown" for item in fake_manager.sent)


async def test_ownership_retained_until_all_receipts_and_new_generation_increases(client, db, factories, fake_manager):
    topo, read = await empty_applied(client, db, factories, fake_manager)
    response = await client.post(ROOT + "/teardown", json=reviewed(read))
    assert response.status_code == 200, response.text
    assert all(item["phase"] == "teardown_pending" for item in response.json()["states"])
    first, second, last = [item["agent_id"] for item in read["states"]]
    await receipt(db, first)
    retained = (await client.get(ROOT + "/retained-state")).json()
    assert len(retained["states"]) == 3
    assert next(item for item in retained["states"] if item["agent_id"] == first)["phase"] == "teardown_applied"
    for agent_id in (first, second):
        with pytest.raises(HTTPException) as error:
            await require_unlinked_agent(db, uuid.UUID(agent_id))
        assert error.value.status_code == 409
    assert (await client.post(ROOT, json=topo[-1])).status_code == 409
    with pytest.raises(HTTPException) as blocked:
        await send_command(first, "wg_update_endpoint", {"server_endpoint": "192.0.2.1:51820"}, db)
    assert blocked.value.status_code == 409
    with pytest.raises(HTTPException):
        await prepare_snapshots({uuid.UUID(first)}, db)
    await refresh_site_link_topology(db)
    await dispatch(first, {"type": "site_link_state", "phase": "applied", "revision": retained["states"][0]["revision"], "desired_hash": retained["states"][0]["desired_hash"]}, db)
    assert len((await client.get(ROOT + "/retained-state")).json()["states"]) == 3
    await receipt(db, second)
    await receipt(db, last)
    released = (await client.get(ROOT + "/retained-state")).json()
    assert released == {"states": [], "can_teardown": False, "has_links": False}
    await require_unlinked_agent(db, uuid.UUID(first))
    generations = list((await db.scalars(select(SiteLinkAgentGeneration))).all())
    assert len(generations) == 3
    old = {item["agent_id"]: item["revision"] for item in read["states"]}
    created = await client.post(ROOT, json=topo[-1])
    assert created.status_code == 201, created.text
    assert all(item["revision"] > old[item["agent_id"]] for item in created.json()["agent_states"])
    await receipt(db, first)
    assert len(list((await db.scalars(select(SiteLinkAgentState))).all())) == 3


async def test_bad_foreign_failed_receipts_retry_and_reconnect_do_not_release(client, db, factories, fake_manager):
    _, read = await empty_applied(client, db, factories, fake_manager)
    a, b, c = [item["agent_id"] for item in read["states"]]
    fake_manager.online.remove(c)
    response = await client.post(ROOT + "/teardown", json=reviewed(read))
    assert response.status_code == 200, response.text
    states = response.json()["states"]
    assert next(item for item in states if item["agent_id"] == c)["phase"] == "teardown_error"
    await receipt(db, a, authenticated_agent=b)
    await receipt(db, a, output="not-json")
    state = (await client.get(ROOT + "/retained-state")).json()
    assert next(item for item in state["states"] if item["agent_id"] == a)["phase"] == "teardown_error"
    await receipt(db, b, success=False)
    await receipt(db, b, output=json.dumps({"released": True, "revision": 999, "desired_hash": "0" * 64}))
    assert len((await client.get(ROOT + "/retained-state")).json()["states"]) == 3
    retry = await client.post(ROOT + "/teardown", json=reviewed(read))
    assert retry.status_code == 200
    assert reviewed(retry.json()) == reviewed(read)
    await receipt(db, a)
    before = len(fake_manager.sent)
    await dispatch_site_links_for_agent(a, db)
    assert len(fake_manager.sent) == before + 1
    assert fake_manager.sent[-1]["message"]["type"] == "site_link_teardown"
    applied = (await client.get(ROOT + "/retained-state")).json()
    assert next(item for item in applied["states"] if item["agent_id"] == a)["phase"] == "teardown_applied"
    await receipt(db, b)
    fake_manager.online.add(c)
    await dispatch_site_links_for_agent(c, db)
    assert fake_manager.sent[-1]["message"]["type"] == "site_link_teardown"
    await receipt(db, c)
    assert not (await client.get(ROOT + "/retained-state")).json()["states"]


async def test_receipt_can_arrive_before_state_command_id_is_assigned(client, db, factories, fake_manager, monkeypatch):
    _, read = await empty_applied(client, db, factories, fake_manager)
    real_send = fake_manager.send

    async def acknowledge_during_send(agent_id, message):
        result = await real_send(agent_id, message)
        if message["type"] == "site_link_teardown":
            await receipt(db, agent_id)
        return result

    monkeypatch.setattr(fake_manager, "send", acknowledge_during_send)
    response = await client.post(ROOT + "/teardown", json=reviewed(read))
    assert response.status_code == 200, response.text
    assert not response.json()["states"]


async def test_pending_teardown_preserves_unrelated_network_and_vpn_commands(client, db, factories, fake_manager):
    topo, read = await empty_applied(client, db, factories, fake_manager)
    assert (await client.post(ROOT + "/teardown", json=reviewed(read))).status_code == 200
    server = await factories.make_server(db)
    client_node = await factories.make_client(db, vm_network="192.168.40.0/24", lan_ip="192.168.40.110")
    attachment = await factories.make_attachment(db, client=client_node, server=server)
    fake_manager.online.update({str(server.agent_id), str(client_node.agent_id)})
    await require_unlinked_agent(db, server.agent_id)
    await require_unlinked_agent(db, client_node.agent_id)
    from app.services.site_link_topology import validate_managed_hub_peer, require_unlinked_client_hubs, require_unpublished_attachment
    await validate_managed_hub_peer(db, server, client_node, attachment.tunnel_ip)
    await require_unlinked_client_hubs(db, client_node.id)
    await require_unpublished_attachment(db, attachment.id)
    with pytest.raises(HTTPException):
        await validate_managed_hub_peer(db, topo[0], client_node, "10.21.0.12")
    with pytest.raises(HTTPException):
        await send_command(str(client_node.agent_id), "wg_attach", {"attachment_id": str(topo[3].id)}, db)
    assert (await send_command(str(server.agent_id), "wg_init", {"tunnel_network": server.tunnel_network}, db))[0]
    assert (await send_command(str(client_node.agent_id), "vpn_peer_add", {"public_key": "unrelated-profile"}, db))[0]
    assert (await send_command(str(client_node.agent_id), "vpn_endpoint_up", {"network": "10.99.0.0/24"}, db))[0]
    assert len((await client.get(ROOT + "/retained-state")).json()["states"]) == 3

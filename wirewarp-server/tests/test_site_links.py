import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.command_log import CommandLog
from app.models.site_link import SiteLink, SiteLinkAgentState
from app.models.vpn_endpoint import VpnEndpoint
from app.models.wg_peer_snapshot import WgPeerSnapshot
from app.services.site_link_ops import acknowledge_site_link_state, aggregate_payload, dispatch_site_links_for_agent
from app.services.agent_commands import send_command
from app.websocket.handlers import dispatch

pytestmark = pytest.mark.asyncio


async def topology(db, factories, fake_manager):
    hub = await factories.make_server(db)
    a = await factories.make_client(db, vm_network="192.168.20.0/24", lan_ip="192.168.20.110")
    b = await factories.make_client(db, vm_network="192.168.0.0/24", lan_ip="192.168.0.110")
    aa = await factories.make_attachment(db, client=a, server=hub, public_key="AKEY")
    ba = await factories.make_attachment(db, client=b, server=hub, tunnel_ip="10.21.0.11", public_key="BKEY")
    fake_manager.online.update(str(value) for value in (hub.agent_id, a.agent_id, b.agent_id))
    body = {"name": "Home to Vienna", "site_a_gateway_id": str(a.agent_id), "site_b_gateway_id": str(b.agent_id), "site_a_attachment_id": str(aa.id), "site_b_attachment_id": str(ba.id), "hub_agent_id": str(hub.agent_id), "site_a_subnets": [a.vm_network], "site_b_subnets": [b.vm_network], "direction": "a_to_b"}
    return hub, a, b, aa, ba, body


async def apply_all(db):
    states = list((await db.scalars(select(SiteLinkAgentState))).all())
    for state in states:
        await dispatch(str(state.agent_id), {"type": "site_link_state", "revision": state.revision, "desired_hash": state.desired_hash, "phase": "applied"}, db)


async def test_pending_new_peer_is_in_deny_inventory_before_public_key_arrives(client, db, factories, fake_manager):
    hub, _, _, _, _, body = await topology(db, factories, fake_manager)
    assert (await client.post("/api/site-links", json=body)).status_code == 201
    other = await factories.make_client(db, vm_network="192.168.30.0/24", lan_ip="192.168.30.110")
    attachment = await factories.make_attachment(db, client=other, server=hub, tunnel_ip="10.21.0.12", public_key=None)
    attachment.wg_public_key = None
    await db.commit()
    payload = await aggregate_payload(hub.agent_id, db)
    peer = next(peer for peer in payload["transit_peers"] if peer["attachment_id"] == str(attachment.id))
    assert peer["wireguard_public_key"] == ""
    assert peer["advertised_subnets"] == ["192.168.30.0/24"]


async def test_gateway_peer_command_requires_local_site_guard_on_managed_hub(client, db, factories, fake_manager):
    hub, _, _, aa, _, body = await topology(db, factories, fake_manager)
    assert (await client.post("/api/site-links", json=body)).status_code == 201
    await send_command(str(hub.agent_id), "wg_add_peer", {"public_key":aa.wg_public_key}, db)
    assert fake_manager.sent[-1]["message"]["params"]["site_link_guard_required"] is True
    await send_command(str(hub.agent_id), "wg_add_peer", {"public_key":"ordinary-peer"}, db)
    assert "site_link_guard_required" not in fake_manager.sent[-1]["message"]["params"]


async def test_site_links_complete_payload_and_applied_readiness(client, db, factories, fake_manager):
    hub, a, b, _, _, body = await topology(db, factories, fake_manager)
    response = await client.post("/api/site-links", json=body)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["phase"] == "pending"
    assert result["lan_routing_prerequisite"]["status"] == "unverified"
    assert result["path"] == [str(a.agent_id), str(hub.agent_id), str(b.agent_id)]
    messages = [record["message"]["params"] for record in fake_manager.sent]
    assert len(messages) == 3
    for payload in messages:
        assert payload["revision"] == 1 and len(payload["desired_hash"]) == 64
        assert len(payload["transit_peers"]) == 2
        link = payload["links"][0]
        assert link["allow_new_a_to_b"] and not link["allow_new_b_to_a"]
        assert link["snat_at_b"] == "gateway_lan_ip"
        assert "interface" not in str(payload)
    await apply_all(db)
    read = await client.get(f"/api/site-links/{result['id']}")
    assert read.json()["phase"] == "applied"
    assert read.json()["lan_routing_prerequisite"]["status"] == "unverified"
    options = (await client.get("/api/site-links/options")).json()
    assert len(options["gateways"]) == 2
    assert all(gateway["attachments"][0]["initialized"] for gateway in options["gateways"])


async def test_site_links_disable_remove_keep_hub_deny_inventory_and_revision(client, db, factories, fake_manager):
    hub, a, _, aa, _, body = await topology(db, factories, fake_manager)
    created = await client.post("/api/site-links", json=body)
    link_id = created.json()["id"]
    await apply_all(db)
    disabled = await client.patch(f"/api/site-links/{link_id}", json={"enabled": False})
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["revision"] == 2
    assert all(state["phase"] == "pending" for state in disabled.json()["agent_states"])
    assert all(not record["message"]["params"]["links"][0]["enabled"] for record in fake_manager.sent[-3:])
    assert (await client.delete(f"/api/site-links/{link_id}")).status_code == 204
    assert all(not record["message"]["params"]["links"] for record in fake_manager.sent[-3:])
    hub_payload = next(record["message"]["params"] for record in fake_manager.sent[-3:] if record["agent_id"] == str(hub.agent_id))
    assert len(hub_payload["transit_peers"]) == 2
    states = list((await db.scalars(select(SiteLinkAgentState))).all())
    assert len(states) == 3 and all(state.revision == 3 for state in states)
    await dispatch_site_links_for_agent(str(hub.agent_id), db)
    assert fake_manager.sent[-1]["message"]["params"]["revision"] == 3
    # Empty managed ownership is replayed after the final link disappears.
    assert fake_manager.sent[-1]["message"]["params"]["links"] == []


async def test_site_links_ack_rejects_cross_agent_and_stale_revision(client, db, factories, fake_manager):
    _, a, _, _, _, body = await topology(db, factories, fake_manager)
    result = (await client.post("/api/site-links", json=body)).json()
    state = await db.get(SiteLinkAgentState, a.agent_id)
    msg = {"revision": state.revision, "desired_hash": state.desired_hash, "phase": "applied"}
    await acknowledge_site_link_state(str(uuid.uuid4()), msg, db)
    await acknowledge_site_link_state(str(a.agent_id), {**msg, "desired_hash": "wrong"}, db)
    await db.refresh(state)
    assert state.applied_revision is None
    await client.patch(f"/api/site-links/{result['id']}", json={"enabled": False})
    await acknowledge_site_link_state(str(a.agent_id), msg, db)
    await db.refresh(state)
    assert state.revision == 2 and state.applied_revision is None
    await acknowledge_site_link_state(str(a.agent_id), {"revision": 2, "desired_hash": state.desired_hash, "phase": "error", "error": "route verification failed"}, db)
    await db.refresh(state)
    assert state.phase == "error" and state.last_error == "route verification failed"


async def test_site_links_rejects_plain_client_wrong_hub_and_uninitialized_peer(client, db, factories, fake_manager):
    _, a, _, aa, _, body = await topology(db, factories, fake_manager)
    a.is_gateway = False
    await db.commit()
    assert (await client.post("/api/site-links", json=body)).status_code == 409
    a.is_gateway = True
    aa.wg_public_key = None
    await db.commit()
    assert (await client.post("/api/site-links", json=body)).status_code == 409
    aa.wg_public_key = "AKEY"
    other_hub = await factories.make_server(db, network="10.22.0.0/24")
    body["hub_agent_id"] = str(other_hub.agent_id)
    assert (await client.post("/api/site-links", json=body)).status_code == 409
    assert not list((await db.scalars(select(SiteLink))).all())


async def test_site_links_rejects_overlapping_unrelated_hub_peer_vpn_and_observed_mesh(client, db, factories, fake_manager):
    hub, a, _, _, _, body = await topology(db, factories, fake_manager)
    extra = await factories.make_client(db, vm_network="192.168.20.0/25", lan_ip="192.168.20.10")
    extra_attachment = await factories.make_attachment(db, client=extra, server=hub, tunnel_ip="10.21.0.12", public_key="CKEY")
    response = await client.post("/api/site-links", json=body)
    assert response.status_code == 409 and "AllowedIPs overlap" in response.text
    await db.delete(extra_attachment)
    await db.delete(extra)
    await db.commit()
    endpoint = VpnEndpoint(tunnel_client_id=a.id, vpn_network="192.168.0.0/25", public_endpoint="vpn.example.test:51821", remote_subnets=[])
    db.add(endpoint)
    await db.commit()
    response = await client.post("/api/site-links", json=body)
    assert response.status_code == 409 and "VPN" in response.text
    await db.delete(endpoint)
    db.add(WgPeerSnapshot(agent_id=hub.agent_id, interface="wg0", kind="mesh", public_key="UNKNOWNKEY", allowed_ips="192.168.0.0/24"))
    await db.commit()
    response = await client.post("/api/site-links", json=body)
    assert response.status_code == 409 and "Observed hub peer" in response.text


async def test_site_links_validates_subnet_scope_rules_and_duplicate_pair(client, db, factories, fake_manager):
    _, _, _, _, _, body = await topology(db, factories, fake_manager)
    assert (await client.post("/api/site-links", json={**body, "site_b_subnets": ["192.168.1.0/24"]})).status_code == 422
    assert (await client.post("/api/site-links", json={**body, "site_b_subnets": ["::/64"]})).status_code == 422
    rule = {"direction": "a_to_b", "destination_cidrs": ["192.168.0.20/32"], "protocol": "tcp", "destination_ports": [443]}
    assert (await client.post("/api/site-links", json={**body, "access_rules": [{**rule, "destination_cidrs": ["192.168.2.20/32"]}]})).status_code == 422
    assert (await client.post("/api/site-links", json={**body, "access_rules": [{**rule, "direction": "b_to_a"}]})).status_code == 422
    assert (await client.post("/api/site-links", json={**body, "access_rules": [{**rule, "protocol": "icmp"}]})).status_code == 422
    assert (await client.post("/api/site-links", json={**body, "access_rules": [rule]})).status_code == 201
    assert (await client.post("/api/site-links", json=body)).status_code == 409


async def test_site_links_probe_binds_saved_scope_requires_applied_and_no_whole_lan_claim(client, db, factories, fake_manager):
    _, a, _, _, _, body = await topology(db, factories, fake_manager)
    rule = {"direction": "a_to_b", "destination_cidrs": ["192.168.0.20/32"], "protocol": "tcp", "destination_ports": [443]}
    created = await client.post("/api/site-links", json={**body, "access_rules": [rule]})
    url = f"/api/site-links/{created.json()['id']}/test"
    service = {"direction": "a_to_b", "destination_ip": "192.168.0.20", "destination_port": 443}
    assert (await client.post(url, json=service)).status_code == 409
    await apply_all(db)
    assert (await client.post(url, json={**service, "destination_port": 80})).status_code == 422
    assert (await client.post(url, json={**service, "direction": "b_to_a"})).status_code == 409
    probe = await client.post(url, json=service)
    assert probe.status_code == 202, probe.text
    sent = fake_manager.sent[-1]
    assert sent["agent_id"] == str(a.agent_id)
    assert sent["message"]["type"] == "site_link_test"
    assert "source_ip" not in sent["message"]["params"]
    assert sent["message"]["params"]["timeout_seconds"] == 5
    command_id = probe.json()["command_id"]
    log = await db.get(CommandLog, uuid.UUID(command_id))
    log.success = True
    log.output = '{"connected":true,"duration_ms":12,"unknown":"excluded"}'
    await db.commit()
    status = (await client.get(url + "/" + command_id)).json()
    assert status["status"] == "success" and status["result"] == {"connected": True, "duration_ms": 12}
    assert status["scope"] == "source_gateway_only" and status["lan_routing_prerequisite"] == "unverified"
    log.output = "unstructured success"
    await db.commit()
    assert (await client.get(url + "/" + command_id)).json()["status"] == "failure"
    log.success = None
    log.executed_at = datetime.now(timezone.utc) - timedelta(seconds=20)
    await db.commit()
    assert (await client.get(url + "/" + command_id)).json()["status"] == "timeout"


async def test_site_links_disconnected_stays_unapplied_and_attachment_delete_restricted(client, db, factories, fake_manager):
    _, a, _, aa, _, body = await topology(db, factories, fake_manager)
    fake_manager.online.discard(str(a.agent_id))
    response = await client.post("/api/site-links", json=body)
    assert response.status_code == 201
    state = next(state for state in response.json()["agent_states"] if state["agent_id"] == str(a.agent_id))
    assert state["phase"] == "disconnected" and state["applied_revision"] is None
    await db.delete(aa)
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_site_links_read_allowed_operator_write_denied(operator_client, db, factories, fake_manager):
    _, _, _, _, _, body = await topology(db, factories, fake_manager)
    assert (await operator_client.get("/api/site-links")).status_code == 200
    assert (await operator_client.get("/api/site-links/options")).status_code == 200
    assert (await operator_client.post("/api/site-links", json=body)).status_code == 403

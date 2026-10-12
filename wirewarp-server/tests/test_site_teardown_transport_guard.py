import pytest
from sqlalchemy import select

from app.models.tunnel_server_ip import TunnelServerIP
from app.models.port_forward import PortForward
from app.models.command_log import CommandLog
from app.services.agent_commands import CommandResultState
from tests.test_site_link_teardown import empty_applied, reviewed

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("field,value", [("wg_port", 51821), ("public_iface", "eth1")])
async def test_pending_teardown_rejects_cohort_transport_changes_before_commit(client, db, factories, fake_manager, field, value):
    topology, state = await empty_applied(client, db, factories, fake_manager)
    server = topology[0]
    old = getattr(server, field)
    assert (await client.post("/api/site-links/teardown", json=reviewed(state))).status_code == 200
    sent = len(fake_manager.sent)
    result = await client.patch(f"/api/tunnel-servers/{server.id}", json={field:value})
    assert result.status_code == 409, result.text
    await db.refresh(server)
    assert getattr(server, field) == old
    assert len(fake_manager.sent) == sent
    unrelated = await factories.make_server(db, network="10.22.0.0/24")
    allowed = await client.patch(f"/api/tunnel-servers/{unrelated.id}", json={field:value})
    assert allowed.status_code == 200, allowed.text
    await db.refresh(unrelated)
    assert getattr(unrelated, field) == value


async def test_pending_teardown_freezes_primary_endpoint_but_preserves_ip_labels(client, db, factories, fake_manager):
    topology, state = await empty_applied(client, db, factories, fake_manager)
    server = topology[0]
    ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id, TunnelServerIP.is_primary.is_(True)))
    old = ip.address
    assert (await client.post("/api/site-links/teardown", json=reviewed(state))).status_code == 200
    sent = len(fake_manager.sent)
    rejected = await client.patch(f"/api/tunnel-server-ips/{ip.id}", json={"address":"192.0.2.45"})
    assert rejected.status_code == 409, rejected.text
    created = await client.post("/api/tunnel-server-ips", json={"tunnel_server_id":str(server.id), "address":"192.0.2.46", "is_primary":True})
    assert created.status_code == 409, created.text
    await db.refresh(ip)
    assert ip.address == old
    assert len(fake_manager.sent) == sent
    updated = await client.patch(f"/api/tunnel-server-ips/{ip.id}", json={"label":"Alwyzon"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["label"] == "Alwyzon"


@pytest.mark.parametrize("operation", ["create", "update"])
async def test_teardown_during_raw_rule_removal_preserves_endpoint_and_restores_rule(client, db, factories, fake_manager, monkeypatch, operation):
    from app.services import port_forward_ops
    topology, state = await empty_applied(client, db, factories, fake_manager)
    server, _, _, attachment, *_ = topology
    primary = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id, TunnelServerIP.is_primary.is_(True)))
    old_address = primary.address
    old_ids = set((await db.scalars(select(TunnelServerIP.id).where(TunnelServerIP.tunnel_server_id == server.id))).all())
    forward = PortForward(attachment_id=attachment.id, service_kind="raw", protocol="tcp", public_port=8443, destination_ip="192.168.20.20", destination_port=443, active=True)
    db.add(forward)
    await db.commit()
    started_teardown = False

    async def acknowledge_removal_then_start_teardown(command_id, agent_id, session, **kwargs):
        nonlocal started_teardown
        import uuid
        command = await session.get(CommandLog, uuid.UUID(command_id))
        assert command.command_type == "iptables_remove_forward"
        command.success = True
        command.output = "Synthetic rule removal acknowledged"
        await session.commit()
        # The command-log commit ended the original Site Links transaction lock.
        response = await client.post("/api/site-links/teardown", json=reviewed(state))
        assert response.status_code == 200, response.text
        started_teardown = True
        return CommandResultState.SUCCESS

    monkeypatch.setattr(port_forward_ops, "wait_for_command_result", acknowledge_removal_then_start_teardown)
    before = len(fake_manager.sent)
    if operation == "create":
        response = await client.post("/api/tunnel-server-ips", json={"tunnel_server_id": str(server.id), "address": "192.0.2.47", "is_primary": True})
    else:
        response = await client.patch(f"/api/tunnel-server-ips/{primary.id}", json={"address": "192.0.2.47"})
    assert started_teardown
    assert response.status_code == 409, response.text
    await db.refresh(primary)
    assert primary.address == old_address and primary.is_primary
    assert set((await db.scalars(select(TunnelServerIP.id).where(TunnelServerIP.tunnel_server_id == server.id))).all()) == old_ids
    raw = [item["message"] for item in fake_manager.sent[before:] if item["message"]["type"].startswith("iptables_")]
    assert [message["type"] for message in raw] == ["iptables_remove_forward", "iptables_add_forward"]
    assert raw[0]["params"] == raw[1]["params"]
    assert raw[1]["params"]["public_ip"] == old_address
    assert not any(item["message"]["type"] in {"wg_init", "wg_update_endpoint"} for item in fake_manager.sent[before:])

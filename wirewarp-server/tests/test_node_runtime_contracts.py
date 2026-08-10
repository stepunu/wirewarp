"""Runtime-authoritative contracts for unified node management actions."""

import uuid

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.gateway_lan_client import GatewayLanClient
from app.models.port_forward import PortForward
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.vpn_endpoint import VpnEndpoint
from app.routers import tunnel_server_ips as tunnel_server_ips_router
from app.websocket.handlers import handle_command_result


pytestmark = pytest.mark.asyncio


def _messages(fake_manager, command_type: str) -> list[dict]:
    return [
        item
        for item in fake_manager.sent
        if item["message"]["type"] == command_type
    ]


def _acknowledge_forward_removals(
    fake_manager,
    session_maker,
    *,
    success: bool = True,
):
    """Route removal results through the production WebSocket handler."""
    original_send = fake_manager.send

    async def send_with_result(agent_id, message):
        sent = await original_send(agent_id, message)
        if sent and message["type"] == "iptables_remove_forward":
            async with session_maker() as result_db:
                await handle_command_result(
                    agent_id,
                    {
                        "command_id": message["id"],
                        "success": success,
                        "output": "removed" if success else "remove failed",
                    },
                    result_db,
                )
        return sent

    fake_manager.send = send_with_result


async def test_primary_ip_changes_replay_every_attachment_even_when_offline(
    client,
    db,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="203.0.113.10")
    first_client = await factories.make_client(db)
    second_client = await factories.make_client(db)
    await factories.make_attachment(
        db,
        client=first_client,
        server=server,
        tunnel_ip="10.21.0.10",
    )
    await factories.make_attachment(
        db,
        client=second_client,
        server=server,
        tunnel_ip="10.21.0.11",
    )
    old_primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert old_primary is not None

    # Keep every agent offline. The write must still succeed, command delivery
    # is best effort, and reconnect replay remains authoritative.
    added = await client.post(
        "/api/tunnel-server-ips",
        json={
            "tunnel_server_id": str(server.id),
            "address": "203.0.113.20",
            "is_primary": False,
        },
    )

    assert added.status_code == 201, added.text
    assert added.json()["is_primary"] is False
    assert not fake_manager.sent

    promoted = await client.patch(
        f"/api/tunnel-server-ips/{added.json()['id']}",
        json={"is_primary": True},
    )
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["is_primary"] is True
    attach_messages = _messages(fake_manager, "wg_attach")
    assert len(attach_messages) == 2
    assert {item["agent_id"] for item in attach_messages} == {
        str(first_client.agent_id),
        str(second_client.agent_id),
    }
    assert {
        item["message"]["params"]["server_endpoint"]
        for item in attach_messages
    } == {"203.0.113.20:51820"}
    assert _messages(fake_manager, "wg_init")[-1]["message"]["params"]["public_ip"] == (
        "203.0.113.20"
    )

    new_primary_id = promoted.json()["id"]
    fake_manager.sent.clear()
    changed = await client.patch(
        f"/api/tunnel-server-ips/{new_primary_id}",
        json={"address": "203.0.113.21"},
    )

    assert changed.status_code == 200, changed.text
    assert changed.json()["address"] == "203.0.113.21"
    assert {
        item["message"]["params"]["server_endpoint"]
        for item in _messages(fake_manager, "wg_attach")
    } == {"203.0.113.21:51820"}

    fake_manager.sent.clear()
    blocked = await client.delete(f"/api/tunnel-server-ips/{new_primary_id}")
    assert blocked.status_code == 409
    assert "set another ip as primary first" in blocked.text.lower()
    assert not fake_manager.sent

    stored = await db.scalar(
        select(TunnelServerIP).where(TunnelServerIP.id == uuid.UUID(new_primary_id))
    )
    assert stored is not None
    assert stored.is_primary is True

    fake_manager.sent.clear()
    deleted_secondary = await client.delete(
        f"/api/tunnel-server-ips/{old_primary.id}"
    )
    assert deleted_secondary.status_code == 204
    assert not fake_manager.sent


async def test_tunnel_server_endpoint_config_replays_attached_client(
    client,
    db,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="203.0.113.30")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None
    db.add(
        GatewayLanClient(
            tunnel_client_id=tunnel_client.id,
            lan_ip="192.168.1.90",
            egress_attachment_id=attachment.id,
            egress_tunnel_server_ip_id=primary.id,
        )
    )
    await db.commit()

    updated = await client.patch(
        f"/api/tunnel-servers/{server.id}",
        json={"wg_port": 51999, "public_iface": "ens18"},
    )

    assert updated.status_code == 200, updated.text
    assert updated.json()["wg_port"] == 51999
    assert updated.json()["public_iface"] == "ens18"
    assert [item["message"]["type"] for item in fake_manager.sent] == [
        "wg_init",
        "reconcile_lan_snat",
        "wg_add_peer",
        "wg_attach",
    ]
    wg_init = _messages(fake_manager, "wg_init")[-1]["message"]["params"]
    assert wg_init["wg_port"] == 51999
    assert wg_init["public_iface"] == "ens18"
    wg_attach = _messages(fake_manager, "wg_attach")[-1]["message"]["params"]
    assert wg_attach["server_endpoint"] == "203.0.113.30:51999"
    assert _messages(fake_manager, "reconcile_lan_snat")[0]["message"]["params"] == {
        "pins": [
            {"lan_ip": "192.168.1.90", "public_ip": "203.0.113.30"}
        ]
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"wg_port": 0},
        {"wg_port": 65536},
        {"public_iface": ""},
        {"public_iface": "interface-name-too-long"},
        {"public_iface": "eth0;bad"},
    ],
)
async def test_tunnel_server_config_validation_preserves_state(
    client,
    db,
    factories,
    fake_manager,
    payload,
):
    server = await factories.make_server(db, primary_ip="203.0.113.31")

    response = await client.patch(f"/api/tunnel-servers/{server.id}", json=payload)

    assert response.status_code == 422, response.text
    await db.refresh(server)
    assert server.wg_port == 51820
    assert server.public_iface == "eth0"
    assert not fake_manager.sent


@pytest.mark.parametrize(
    "payload",
    [
        {"vm_network": "192.168.1.1/24"},
        {"vm_network": "2001:db8::/64"},
        {"lan_ip": "2001:db8::1"},
        {"lan_ip": "192.168.2.10"},
        {"lan_ip": "192.168.1.0"},
        {"lan_ip": "192.168.1.255"},
    ],
)
async def test_gateway_network_validation_preserves_state(
    client,
    db,
    factories,
    fake_manager,
    payload,
):
    tunnel_client = await factories.make_client(
        db,
        is_gateway=True,
        vm_network="192.168.1.0/24",
        lan_ip="192.168.1.110",
    )

    response = await client.patch(
        f"/api/tunnel-clients/{tunnel_client.id}",
        json=payload,
    )

    assert response.status_code == 422, response.text
    await db.refresh(tunnel_client)
    assert tunnel_client.vm_network == "192.168.1.0/24"
    assert tunnel_client.lan_ip == "192.168.1.110"
    assert tunnel_client.is_gateway is True
    assert not fake_manager.sent


async def test_endpoint_write_does_not_report_failure_when_immediate_dispatch_fails(
    client,
    db,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="203.0.113.40")
    tunnel_client = await factories.make_client(db)
    await factories.make_attachment(db, client=tunnel_client, server=server)
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None

    async def fail_delivery(_agent_id, _message):
        raise RuntimeError("simulated websocket failure")

    fake_manager.send = fail_delivery
    response = await client.patch(
        f"/api/tunnel-server-ips/{primary.id}",
        json={"address": "203.0.113.41"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["address"] == "203.0.113.41"
    stored = await db.scalar(
        select(TunnelServerIP).where(TunnelServerIP.id == primary.id)
    )
    assert stored is not None
    await db.refresh(stored)
    assert stored.address == "203.0.113.41"


async def test_primary_promotion_moves_only_inherited_raw_forward(
    client,
    db,
    session_maker,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="203.0.113.50")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    old_primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert old_primary is not None
    secondary = TunnelServerIP(
        tunnel_server_id=server.id,
        address="203.0.113.51",
        is_primary=False,
    )
    inherited = PortForward(
        attachment_id=attachment.id,
        protocol="tcp",
        public_port=8080,
        destination_ip="192.168.1.10",
        destination_port=80,
        service_kind="raw",
        active=True,
    )
    explicit = PortForward(
        attachment_id=attachment.id,
        tunnel_server_ip_id=old_primary.id,
        protocol="tcp",
        public_port=8081,
        destination_ip="192.168.1.11",
        destination_port=80,
        service_kind="raw",
        active=True,
    )
    db.add_all([secondary, inherited, explicit])
    await db.commit()
    await db.refresh(secondary)
    fake_manager.online.add(str(server.agent_id))
    _acknowledge_forward_removals(fake_manager, session_maker)

    response = await client.patch(
        f"/api/tunnel-server-ips/{secondary.id}",
        json={"is_primary": True},
    )

    assert response.status_code == 200, response.text
    forward_commands = [
        item["message"]
        for item in fake_manager.sent
        if item["message"]["type"].startswith("iptables_")
    ]
    assert [message["type"] for message in forward_commands] == [
        "iptables_remove_forward",
        "iptables_add_forward",
    ]
    assert [message["params"]["public_ip"] for message in forward_commands] == [
        "203.0.113.50",
        "203.0.113.51",
    ]
    assert {message["params"]["public_port"] for message in forward_commands} == {
        8080
    }
    snat_reconciles = _messages(fake_manager, "reconcile_lan_snat")
    assert len(snat_reconciles) == 1
    assert snat_reconciles[0]["message"]["params"] == {"pins": []}


async def test_primary_promotion_reconfirms_shared_forward_accept_survivor(
    client,
    db,
    session_maker,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="203.0.113.55")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    old_primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert old_primary is not None
    secondary = TunnelServerIP(
        tunnel_server_id=server.id,
        address="203.0.113.56",
        is_primary=False,
    )
    db.add_all(
        [
            secondary,
            PortForward(
                attachment_id=attachment.id,
                protocol="tcp",
                public_port=8082,
                destination_ip="192.168.1.12",
                destination_port=80,
                service_kind="raw",
                active=True,
            ),
            PortForward(
                attachment_id=attachment.id,
                tunnel_server_ip_id=old_primary.id,
                protocol="tcp",
                public_port=8083,
                destination_ip="192.168.1.12",
                destination_port=80,
                service_kind="raw",
                active=True,
            ),
        ]
    )
    await db.commit()
    await db.refresh(secondary)
    fake_manager.online.add(str(server.agent_id))
    original_send = fake_manager.send

    async def acknowledge_runtime_rules(agent_id, message):
        sent = await original_send(agent_id, message)
        if sent and message["type"].startswith("iptables_"):
            async with session_maker() as result_db:
                await handle_command_result(
                    agent_id,
                    {
                        "command_id": message["id"],
                        "success": True,
                        "output": "applied",
                    },
                    result_db,
                )
        return sent

    fake_manager.send = acknowledge_runtime_rules
    response = await client.patch(
        f"/api/tunnel-server-ips/{secondary.id}",
        json={"is_primary": True},
    )

    assert response.status_code == 200, response.text
    commands = [
        item["message"]
        for item in fake_manager.sent
        if item["message"]["type"].startswith("iptables_")
    ]
    assert [message["type"] for message in commands] == [
        "iptables_remove_forward",
        "iptables_add_forward",
        "iptables_add_forward",
    ]
    assert [message["params"]["public_port"] for message in commands] == [
        8082,
        8083,
        8082,
    ]


async def test_primary_address_change_moves_inherited_and_bound_raw_forwards(
    client,
    db,
    session_maker,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="203.0.113.60")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None
    db.add_all(
        [
            PortForward(
                attachment_id=attachment.id,
                protocol="tcp",
                public_port=9000,
                destination_ip="192.168.1.20",
                destination_port=90,
                service_kind="raw",
                active=True,
            ),
            PortForward(
                attachment_id=attachment.id,
                tunnel_server_ip_id=primary.id,
                protocol="tcp",
                public_port=9001,
                destination_ip="192.168.1.21",
                destination_port=90,
                service_kind="raw",
                active=True,
            ),
        ]
    )
    await db.commit()
    fake_manager.online.add(str(server.agent_id))
    _acknowledge_forward_removals(fake_manager, session_maker)

    response = await client.patch(
        f"/api/tunnel-server-ips/{primary.id}",
        json={"address": "203.0.113.61"},
    )

    assert response.status_code == 200, response.text
    forward_commands = [
        item["message"]
        for item in fake_manager.sent
        if item["message"]["type"].startswith("iptables_")
    ]
    removes = [
        message for message in forward_commands
        if message["type"] == "iptables_remove_forward"
    ]
    adds = [
        message for message in forward_commands
        if message["type"] == "iptables_add_forward"
    ]
    assert {message["params"]["public_port"] for message in removes} == {9000, 9001}
    assert {message["params"]["public_ip"] for message in removes} == {
        "203.0.113.60"
    }
    assert {message["params"]["public_port"] for message in adds} == {9000, 9001}
    assert {message["params"]["public_ip"] for message in adds} == {
        "203.0.113.61"
    }


async def test_ip_address_change_replays_complete_lan_snat_desired_state(
    client,
    db,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="192.0.2.10")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None
    db.add_all(
        [
            GatewayLanClient(
                tunnel_client_id=tunnel_client.id,
                lan_ip="192.168.1.42",
                egress_attachment_id=attachment.id,
                egress_tunnel_server_ip_id=primary.id,
            ),
            GatewayLanClient(
                tunnel_client_id=tunnel_client.id,
                lan_ip="192.168.1.41",
                egress_attachment_id=attachment.id,
                egress_tunnel_server_ip_id=primary.id,
            ),
        ]
    )
    await db.commit()
    fake_manager.online.add(str(server.agent_id))

    response = await client.patch(
        f"/api/tunnel-server-ips/{primary.id}",
        json={"address": "192.0.2.11"},
    )

    assert response.status_code == 200, response.text
    reconciles = _messages(fake_manager, "reconcile_lan_snat")
    assert len(reconciles) == 1
    assert reconciles[0]["message"]["params"] == {
        "pins": [
            {"lan_ip": "192.168.1.41", "public_ip": "192.0.2.11"},
            {"lan_ip": "192.168.1.42", "public_ip": "192.0.2.11"},
        ]
    }


async def test_ip_delete_reports_and_blocks_lan_egress_pins(
    client,
    db,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="192.0.2.20")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    secondary = TunnelServerIP(
        tunnel_server_id=server.id,
        address="192.0.2.21",
        is_primary=False,
    )
    db.add(secondary)
    await db.commit()
    await db.refresh(secondary)
    db.add(
        GatewayLanClient(
            tunnel_client_id=tunnel_client.id,
            lan_ip="192.168.1.91",
            egress_attachment_id=attachment.id,
            egress_tunnel_server_ip_id=secondary.id,
        )
    )
    await db.commit()

    listed = await client.get(
        f"/api/tunnel-server-ips?tunnel_server_id={server.id}"
    )
    deleted = await client.delete(f"/api/tunnel-server-ips/{secondary.id}")

    assert listed.status_code == 200, listed.text
    row = next(item for item in listed.json() if item["id"] == str(secondary.id))
    assert row["lan_egress_pin_count"] == 1
    assert deleted.status_code == 409, deleted.text
    assert "lan egress pin" in deleted.text.lower()
    assert await db.get(TunnelServerIP, secondary.id) is not None
    assert not fake_manager.sent


async def test_forward_remove_is_precommit_and_add_failure_keeps_saved_endpoint(
    client,
    db,
    session_maker,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="198.51.100.10")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None
    db.add(
        PortForward(
            attachment_id=attachment.id,
            protocol="tcp",
            public_port=9443,
            destination_ip="192.168.1.30",
            destination_port=443,
            service_kind="raw",
            active=True,
        )
    )
    await db.commit()
    fake_manager.online.add(str(server.agent_id))
    original_send = fake_manager.send

    async def fail_after_old_remove(agent_id, message):
        if message["type"] == "iptables_remove_forward":
            sent = await original_send(agent_id, message)
            async with session_maker() as result_db:
                await handle_command_result(
                    agent_id,
                    {
                        "command_id": message["id"],
                        "success": True,
                        "output": "removed",
                    },
                    result_db,
                )
            return sent
        raise RuntimeError("simulated post-commit delivery failure")

    fake_manager.send = fail_after_old_remove
    response = await client.patch(
        f"/api/tunnel-server-ips/{primary.id}",
        json={"address": "198.51.100.11"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["address"] == "198.51.100.11"
    removes = _messages(fake_manager, "iptables_remove_forward")
    assert len(removes) == 1
    assert removes[0]["message"]["params"]["public_ip"] == "198.51.100.10"
    stored = await db.scalar(
        select(TunnelServerIP).where(TunnelServerIP.id == primary.id)
    )
    assert stored is not None
    await db.refresh(stored)
    assert stored.address == "198.51.100.11"


async def test_forward_remove_failure_keeps_endpoint_desired_state(
    client,
    db,
    session_maker,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="198.51.100.20")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None
    db.add(
        PortForward(
            attachment_id=attachment.id,
            protocol="tcp",
            public_port=9444,
            destination_ip="192.168.1.31",
            destination_port=443,
            service_kind="raw",
            active=True,
        )
    )
    await db.commit()
    fake_manager.online.add(str(server.agent_id))
    _acknowledge_forward_removals(
        fake_manager,
        session_maker,
        success=False,
    )

    response = await client.patch(
        f"/api/tunnel-server-ips/{primary.id}",
        json={"address": "198.51.100.21"},
    )

    assert response.status_code == 503, response.text
    assert "(failure)" in response.text
    await db.refresh(primary)
    assert primary.address == "198.51.100.20"
    restores = _messages(fake_manager, "iptables_add_forward")
    assert len(restores) == 1
    assert restores[0]["message"]["params"]["public_ip"] == "198.51.100.20"


async def test_later_forward_remove_failure_restores_full_old_batch(
    client,
    db,
    session_maker,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="198.51.100.25")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None
    db.add_all(
        [
            PortForward(
                attachment_id=attachment.id,
                protocol="tcp",
                public_port=9450 + offset,
                destination_ip=f"192.168.1.{40 + offset}",
                destination_port=443,
                service_kind="raw",
                active=True,
            )
            for offset in range(2)
        ]
    )
    await db.commit()
    fake_manager.online.add(str(server.agent_id))
    original_send = fake_manager.send
    remove_count = 0

    async def fail_second_remove(agent_id, message):
        nonlocal remove_count
        sent = await original_send(agent_id, message)
        if sent and message["type"] == "iptables_remove_forward":
            remove_count += 1
            async with session_maker() as result_db:
                await handle_command_result(
                    agent_id,
                    {
                        "command_id": message["id"],
                        "success": remove_count == 1,
                        "output": "removed" if remove_count == 1 else "failed",
                    },
                    result_db,
                )
        return sent

    fake_manager.send = fail_second_remove
    response = await client.patch(
        f"/api/tunnel-server-ips/{primary.id}",
        json={"address": "198.51.100.26"},
    )

    assert response.status_code == 503, response.text
    await db.refresh(primary)
    assert primary.address == "198.51.100.25"
    restores = _messages(fake_manager, "iptables_add_forward")
    assert {item["message"]["params"]["public_port"] for item in restores} == {
        9450,
        9451,
    }


async def test_forward_remove_timeout_keeps_endpoint_desired_state(
    client,
    db,
    factories,
    fake_manager,
    monkeypatch,
):
    server = await factories.make_server(db, primary_ip="198.51.100.30")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None
    db.add(
        PortForward(
            attachment_id=attachment.id,
            protocol="tcp",
            public_port=9445,
            destination_ip="192.168.1.32",
            destination_port=443,
            service_kind="raw",
            active=True,
        )
    )
    await db.commit()
    fake_manager.online.add(str(server.agent_id))
    monkeypatch.setattr(
        tunnel_server_ips_router,
        "FORWARD_REMOVE_RESULT_TIMEOUT_SECONDS",
        0.05,
    )

    response = await client.patch(
        f"/api/tunnel-server-ips/{primary.id}",
        json={"address": "198.51.100.31"},
    )

    assert response.status_code == 503, response.text
    assert "0.05 seconds (timeout)" in response.text
    await db.refresh(primary)
    assert primary.address == "198.51.100.30"
    restores = _messages(fake_manager, "iptables_add_forward")
    assert len(restores) == 1
    assert restores[0]["message"]["params"]["public_ip"] == "198.51.100.30"


@pytest.mark.parametrize(
    "payload",
    [
        {"protocol": "sctp"},
        {"public_port": 0},
        {"destination_port": 65536},
        {"public_port_end": 9001},
        {"public_port_end": 8999, "destination_port_end": 9001},
        {"public_port_end": 9002, "destination_port_end": 9001},
        {"destination_ip": "2001:db8::1"},
        {"destination_ip": "192.168.001.10"},
    ],
)
async def test_raw_forward_create_validation_rejects_invalid_rules(
    client,
    db,
    factories,
    fake_manager,
    payload,
):
    server = await factories.make_server(db, primary_ip="203.0.113.120")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    body = {
        "attachment_id": str(attachment.id),
        "protocol": "tcp",
        "public_port": 9000,
        "destination_ip": "192.168.1.10",
        "destination_port": 9000,
    }
    body.update(payload)

    response = await client.post("/api/port-forwards", json=body)

    assert response.status_code == 422, response.text
    assert not fake_manager.sent


async def test_raw_forward_rejects_cross_server_ip_and_missing_primary(
    client,
    db,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="203.0.113.119")
    server_primary = await db.scalar(
        select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id)
    )
    assert server_primary is not None
    await db.delete(server_primary)
    await db.commit()
    other = await factories.make_server(
        db, network="10.23.0.0/24", primary_ip="203.0.113.121"
    )
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    other_ip = await db.scalar(
        select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == other.id)
    )
    assert other_ip is not None
    base = {
        "attachment_id": str(attachment.id),
        "protocol": "tcp",
        "public_port": 9100,
        "destination_ip": "192.168.1.10",
        "destination_port": 9100,
    }

    cross = await client.post(
        "/api/port-forwards",
        json={**base, "tunnel_server_ip_id": str(other_ip.id)},
    )
    missing = await client.post("/api/port-forwards", json=base)

    assert cross.status_code == 422, cross.text
    assert missing.status_code == 409, missing.text
    assert not fake_manager.sent


async def test_http_edge_route_rejects_raw_patch_and_delete(
    client,
    db,
    factories,
    fake_manager,
):
    server = await factories.make_server(db, primary_ip="203.0.113.122")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db, client=tunnel_client, server=server
    )
    route = PortForward(
        attachment_id=attachment.id,
        protocol="tcp",
        public_port=443,
        destination_ip="192.168.1.10",
        destination_port=8443,
        service_kind="http",
        domain="example.test",
        active=True,
    )
    db.add(route)
    await db.commit()
    await db.refresh(route)

    patched = await client.patch(
        f"/api/port-forwards/{route.id}", json={"destination_port": 9443}
    )
    deleted = await client.delete(f"/api/port-forwards/{route.id}")

    assert patched.status_code == 409, patched.text
    assert deleted.status_code == 409, deleted.text
    await db.refresh(route)
    assert route.destination_port == 8443
    assert not fake_manager.sent


async def test_gateway_role_change_replays_client_and_replaces_server_peers(
    client,
    db,
    factories,
    fake_manager,
):
    tunnel_client = await factories.make_client(
        db,
        is_gateway=True,
        vm_network="192.168.50.0/24",
        lan_ip="192.168.50.2",
    )
    first_server = await factories.make_server(db, network="10.21.0.0/24")
    second_server = await factories.make_server(db, network="10.22.0.0/24")
    await factories.make_attachment(
        db,
        client=tunnel_client,
        server=first_server,
        tunnel_ip="10.21.0.10",
        wg_interface="wg0",
    )
    await factories.make_attachment(
        db,
        client=tunnel_client,
        server=second_server,
        tunnel_ip="10.22.0.10",
        wg_interface="wg1",
        fwmark=0x102,
        route_table_id=101,
    )

    # Offline updates remain valid desired state. Each server gets a remove
    # then add so obsolete LAN AllowedIPs and routes can be removed.
    updated = await client.patch(
        f"/api/tunnel-clients/{tunnel_client.id}",
        json={"is_gateway": False, "vm_network": None, "lan_ip": None},
    )

    assert updated.status_code == 200, updated.text
    assert updated.json()["is_gateway"] is False
    assert updated.json()["vm_network"] is None
    assert updated.json()["lan_ip"] is None

    assert len(_messages(fake_manager, "wg_remove_peer")) == 2
    assert len(_messages(fake_manager, "wg_attach")) == 2
    add_messages = _messages(fake_manager, "wg_add_peer")
    assert len(add_messages) == 2
    assert {
        tuple(item["message"]["params"]["allowed_ips"])
        for item in add_messages
    } == {("10.21.0.10/32",), ("10.22.0.10/32",)}

    for item in _messages(fake_manager, "wg_attach"):
        params = item["message"]["params"]
        assert params["is_gateway"] is False
        assert params["lan_network"] == ""
        assert params["lan_ip"] == ""

    command_types = [item["message"]["type"] for item in fake_manager.sent]
    assert command_types == [
        "wg_remove_peer",
        "wg_attach",
        "wg_add_peer",
        "wg_remove_peer",
        "wg_attach",
        "wg_add_peer",
    ]


async def test_gateway_demotion_clears_lan_egress_and_server_snat_desired_state(
    client,
    db,
    factories,
    fake_manager,
):
    tunnel_client = await factories.make_client(db, is_gateway=True)
    first_server = await factories.make_server(
        db, primary_ip="203.0.113.110", network="10.31.0.0/24"
    )
    second_server = await factories.make_server(
        db, primary_ip="203.0.113.111", network="10.32.0.0/24"
    )
    first_attachment = await factories.make_attachment(
        db,
        client=tunnel_client,
        server=first_server,
        tunnel_ip="10.31.0.10",
    )
    second_attachment = await factories.make_attachment(
        db,
        client=tunnel_client,
        server=second_server,
        tunnel_ip="10.32.0.10",
        wg_interface="wg1",
        route_table_id=101,
    )
    first_primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == first_server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    second_primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == second_server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert first_primary is not None
    assert second_primary is not None
    lan_rows = [
        GatewayLanClient(
            tunnel_client_id=tunnel_client.id,
            lan_ip="192.168.1.70",
            egress_attachment_id=first_attachment.id,
            egress_tunnel_server_ip_id=first_primary.id,
        ),
        GatewayLanClient(
            tunnel_client_id=tunnel_client.id,
            lan_ip="192.168.1.71",
            egress_attachment_id=second_attachment.id,
            egress_tunnel_server_ip_id=second_primary.id,
        ),
    ]
    db.add_all(lan_rows)
    await db.commit()

    response = await client.patch(
        f"/api/tunnel-clients/{tunnel_client.id}",
        json={"is_gateway": False},
    )

    assert response.status_code == 200, response.text
    for row in lan_rows:
        await db.refresh(row)
        assert row.egress_attachment_id is None
        assert row.egress_tunnel_server_ip_id is None
    clears = _messages(fake_manager, "set_lan_egress")
    assert {item["message"]["params"]["lan_ip"] for item in clears} == {
        "192.168.1.70",
        "192.168.1.71",
    }
    assert all(
        item["message"]["params"] == {
            "lan_ip": item["message"]["params"]["lan_ip"],
            "route_table_id": 0,
        }
        for item in clears
    )
    reconciles = _messages(fake_manager, "reconcile_lan_snat")
    assert {item["agent_id"] for item in reconciles} == {
        str(first_server.agent_id),
        str(second_server.agent_id),
    }
    assert all(item["message"]["params"] == {"pins": []} for item in reconciles)

    fake_manager.sent.clear()
    repin = await client.patch(
        f"/api/tunnel-clients/{tunnel_client.id}/lan-clients/{lan_rows[0].id}",
        json={
            "egress_attachment_id": str(first_attachment.id),
            "egress_tunnel_server_ip_id": str(first_primary.id),
        },
    )
    create_pinned = await client.post(
        f"/api/tunnel-clients/{tunnel_client.id}/lan-clients",
        json={
            "lan_ip": "192.168.1.72",
            "egress_attachment_id": str(first_attachment.id),
            "egress_tunnel_server_ip_id": str(first_primary.id),
        },
    )
    assert repin.status_code == 409, repin.text
    assert create_pinned.status_code == 409, create_pinned.text
    assert not fake_manager.sent

    # A stale legacy row must not enter the authoritative server snapshot.
    lan_rows[0].egress_attachment_id = first_attachment.id
    lan_rows[0].egress_tunnel_server_ip_id = first_primary.id
    await db.commit()
    replay = await client.patch(
        f"/api/tunnel-servers/{first_server.id}",
        json={"wg_port": 51901},
    )
    assert replay.status_code == 200, replay.text
    assert _messages(fake_manager, "reconcile_lan_snat")[-1]["message"]["params"] == {
        "pins": []
    }


async def test_gateway_demotion_is_blocked_while_vpn_endpoint_exists(
    client,
    db,
    factories,
    fake_manager,
):
    tunnel_client = await factories.make_client(db, is_gateway=True)
    db.add(
        VpnEndpoint(
            tunnel_client_id=tunnel_client.id,
            wg_interface="wg-vpn0",
            listen_port=51821,
            vpn_network="10.44.0.0/24",
            public_endpoint="vpn.example.test:51821",
            enabled=False,
        )
    )
    await db.commit()

    response = await client.patch(
        f"/api/tunnel-clients/{tunnel_client.id}",
        json={"is_gateway": False},
    )

    assert response.status_code == 409, response.text
    assert "vpn endpoint exists" in response.text.lower()
    await db.refresh(tunnel_client)
    assert tunnel_client.is_gateway is True
    assert not fake_manager.sent


async def test_node_delete_contract_preserves_configured_state(
    client,
    db,
    factories,
):
    server = await factories.make_server(db)
    tunnel_client = await factories.make_client(db)

    server_delete = await client.delete(f"/api/tunnel-servers/{server.id}")
    client_delete = await client.delete(f"/api/tunnel-clients/{tunnel_client.id}")
    server_agent_delete = await client.delete(f"/api/agents/{server.agent_id}")
    client_agent_delete = await client.delete(f"/api/agents/{tunnel_client.agent_id}")

    assert server_delete.status_code == 409
    assert client_delete.status_code == 409
    assert server_agent_delete.status_code == 409
    assert client_agent_delete.status_code == 409
    assert "runtime teardown" in server_delete.text.lower()
    assert "runtime teardown" in client_delete.text.lower()
    assert "runtime teardown" in server_agent_delete.text.lower()

    assert await db.get(TunnelServer, server.id) is not None
    assert await db.get(TunnelClient, tunnel_client.id) is not None
    assert await db.get(Agent, server.agent_id) is not None
    assert await db.get(Agent, tunnel_client.agent_id) is not None

    # A record without runtime config can still be removed.
    orphan = await factories.make_agent(db, type_="client", name="orphan")
    orphan_delete = await client.delete(f"/api/agents/{orphan.id}")
    assert orphan_delete.status_code == 204
    assert await db.scalar(select(Agent).where(Agent.id == orphan.id)) is None


async def test_agent_delete_remains_admin_only(operator_client, db, factories):
    agent = await factories.make_agent(db, type_="server")
    response = await operator_client.delete(f"/api/agents/{agent.id}")
    assert response.status_code == 403
    assert await db.get(Agent, agent.id) is not None

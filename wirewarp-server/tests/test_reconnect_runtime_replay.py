"""Agent auth reconnect replays current runtime desired state over the socket."""

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.auth import create_agent_token
from app.models.gateway_lan_client import GatewayLanClient
from app.models.port_forward import PortForward
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.vpn_endpoint import VpnEndpoint
from app.services import agent_commands
from app.websocket.hub import ConnectionManager


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("role", ["server", "gateway"])
async def test_reconnect_replays_disabled_edge_and_leaves_never_managed_node_untouched(db, session_maker, factories, monkeypatch, role):
    from app.models.edge_node import EdgeNode
    if role == "server":
        node = await factories.make_server(db)
        owner = await db.get(EdgeNode, node.agent_id)
    else:
        node = await factories.make_client(db)
        owner = EdgeNode(agent_id=node.agent_id)
        db.add(owner)
    owner.edge_mode = "security_edge"
    owner.edge_state = "disabled"
    owner.edge_disabled_at = datetime.now(timezone.utc)
    await db.commit()
    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = RecordingWebSocket(create_agent_token(str(node.agent_id)))
    await main_module.agent_websocket(socket)
    commands = [message for message in socket.received if "id" in message]
    disable = [message for message in commands if message["type"] == "edge_disable"]
    assert len(disable) == 1
    assert disable[0]["params"] == {"preserve_state": True}
    assert not any(message["type"] == "edge_desired_state" for message in commands)
    owner.edge_disabled_at = None
    await db.commit()
    socket = RecordingWebSocket(create_agent_token(str(node.agent_id)))
    await main_module.agent_websocket(socket)
    commands = [message for message in socket.received if "id" in message]
    assert not any(message["type"] == "edge_disable" for message in commands)


class RecordingWebSocket:
    def __init__(self, jwt: str):
        self.payloads = [json.dumps({"type": "auth", "jwt": jwt})]
        self.received: list[dict] = []

    async def accept(self):
        return None

    async def receive_text(self):
        if self.payloads:
            return self.payloads.pop(0)
        from fastapi import WebSocketDisconnect

        raise WebSocketDisconnect(code=1000)

    async def send_text(self, message: str):
        self.received.append(json.loads(message))

    async def close(self, code: int = 1000):
        return None

    @property
    def query_params(self):
        return {}


@pytest.mark.parametrize("role", ["server", "gateway"])
@pytest.mark.parametrize("already_released", [False, True])
async def test_teardown_reconnect_keeps_socket_open_without_network_bootstrap(client, db, session_maker, factories, fake_manager, monkeypatch, role, already_released):
    from tests.test_site_link_teardown import empty_applied, reviewed, receipt
    topology, state = await empty_applied(client, db, factories, fake_manager)
    node = topology[0 if role == "server" else 1]
    assert (await client.post("/api/site-links/teardown", json=reviewed(state))).status_code == 200
    if already_released:
        await receipt(db, node.agent_id)
    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = RecordingWebSocket(create_agent_token(str(node.agent_id)))
    socket.payloads.append(json.dumps({"type":"agent_ping", "nonce":"cleanup-wait"}))
    await main_module.agent_websocket(socket)
    commands = [message for message in socket.received if "id" in message]
    assert [message["type"] for message in commands] == ["site_link_teardown"]
    assert {"type":"agent_pong", "nonce":"cleanup-wait"} in socket.received


@pytest.mark.parametrize("role", ["server", "gateway"])
async def test_teardown_last_receipt_resumes_deferred_network_bootstrap(client, db, session_maker, factories, fake_manager, monkeypatch, role):
    from tests.test_site_link_teardown import empty_applied, reviewed, receipt
    topology, state = await empty_applied(client, db, factories, fake_manager)
    node = topology[0 if role == "server" else 1]
    assert (await client.post("/api/site-links/teardown", json=reviewed(state))).status_code == 200
    others = [item["agent_id"] for item in state["states"] if item["agent_id"] != str(node.agent_id)]

    class CompletingSocket(RecordingWebSocket):
        acknowledged = False

        async def receive_text(self):
            if self.payloads:
                return self.payloads.pop(0)
            if not self.acknowledged:
                self.acknowledged = True
                for agent_id in others:
                    await receipt(db, agent_id)
                command = next(message for message in self.received if message.get("type") == "site_link_teardown")
                result = {"released":True, "revision":command["params"]["revision"], "desired_hash":command["params"]["desired_hash"]}
                return json.dumps({"type":"command_result", "command_id":command["id"], "success":True, "output":json.dumps(result)})
            return await super().receive_text()

    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = CompletingSocket(create_agent_token(str(node.agent_id)))
    await main_module.agent_websocket(socket)
    commands = [message["type"] for message in socket.received if "id" in message]
    assert commands[0] == "site_link_teardown"
    assert ("wg_init" if role == "server" else "edge_node_role") in commands[1:]
    assert (await client.get("/api/site-links/retained-state")).json()["states"] == []


def _use_real_socket_manager(monkeypatch, session_maker):
    from app import main as main_module

    runtime_manager = ConnectionManager()
    monkeypatch.setattr(main_module, "SessionLocal", session_maker)
    monkeypatch.setattr(main_module, "manager", runtime_manager)
    monkeypatch.setattr(agent_commands, "manager", runtime_manager)
    return main_module


@pytest.mark.parametrize("role", ["server", "gateway"])
async def test_teardown_started_during_reconnect_defers_bootstrap_without_closing_socket(client, db, session_maker, factories, fake_manager, monkeypatch, role):
    from app.services import agent_replay
    from tests.test_site_link_teardown import empty_applied, reviewed
    topology, state = await empty_applied(client, db, factories, fake_manager)
    node = topology[0 if role == "server" else 1]
    original = agent_replay._replay_normal_runtime

    async def begin_teardown_then_replay(agent_id, replay_db):
        assert (await client.post("/api/site-links/teardown", json=reviewed(state))).status_code == 200
        return await original(agent_id, replay_db)

    monkeypatch.setattr(agent_replay, "_replay_normal_runtime", begin_teardown_then_replay)
    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = RecordingWebSocket(create_agent_token(str(node.agent_id)))
    socket.payloads.append(json.dumps({"type":"agent_ping", "nonce":"race-recovered"}))
    await main_module.agent_websocket(socket)
    commands = [message for message in socket.received if "id" in message]
    assert [message["type"] for message in commands] == ["site_link_teardown", "site_link_teardown"]
    assert commands[0]["params"] == commands[1]["params"]
    assert {"type":"agent_pong", "nonce":"race-recovered"} in socket.received


async def test_related_hub_teardown_defers_noncohort_client_until_release(client, db, session_maker, factories, fake_manager, monkeypatch):
    from tests.test_site_link_teardown import empty_applied, reviewed, receipt
    topology, state = await empty_applied(client, db, factories, fake_manager)
    node = await factories.make_client(db, is_gateway=False)
    await factories.make_attachment(db, client=node, server=topology[0], tunnel_ip="10.21.0.99")
    assert (await client.post("/api/site-links/teardown", json=reviewed(state))).status_code == 200

    class ReleasingSocket(RecordingWebSocket):
        released = False

        async def receive_text(self):
            if self.payloads:
                return self.payloads.pop(0)
            if not self.released:
                assert not any("id" in message for message in self.received)
                self.released = True
                for item in state["states"]:
                    await receipt(db, item["agent_id"])
                return json.dumps({"type":"agent_ping", "nonce":"hub-released"})
            return await super().receive_text()

    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = ReleasingSocket(create_agent_token(str(node.agent_id)))
    await main_module.agent_websocket(socket)
    commands = [message["type"] for message in socket.received if "id" in message]
    assert commands == ["edge_node_role", "wg_attach"]
    assert {"type":"agent_pong", "nonce":"hub-released"} in socket.received


async def test_reconnect_preserves_unrelated_conflict_errors(db, factories, monkeypatch):
    from fastapi import HTTPException
    from app.services import agent_replay
    node = await factories.make_client(db)

    async def conflict(agent_id, replay_db):
        raise HTTPException(409, "Unrelated conflict")

    monkeypatch.setattr(agent_replay, "_replay_normal_runtime", conflict)
    with pytest.raises(HTTPException, match="Unrelated conflict"):
        await agent_replay.replay_agent_runtime(node.agent_id, db)


async def test_server_auth_reconnect_replays_init_before_forwards_peers_and_snat(
    db,
    session_maker,
    factories,
    monkeypatch,
):
    server = await factories.make_server(db, primary_ip="203.0.113.70")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db,
        client=tunnel_client,
        server=server,
        tunnel_ip="10.21.0.10",
    )
    forward = PortForward(
        attachment_id=attachment.id,
        protocol="tcp",
        public_port=8443,
        destination_ip="192.168.1.50",
        destination_port=443,
        service_kind="raw",
        active=True,
    )
    primary = await db.scalar(
        select(TunnelServerIP).where(
            TunnelServerIP.tunnel_server_id == server.id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    assert primary is not None
    lan_client = GatewayLanClient(
        tunnel_client_id=tunnel_client.id,
        lan_ip="192.168.1.50",
        egress_attachment_id=attachment.id,
        egress_tunnel_server_ip_id=primary.id,
    )
    db.add_all([forward, lan_client])
    await db.commit()

    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = RecordingWebSocket(create_agent_token(str(server.agent_id)))
    await main_module.agent_websocket(socket)

    commands = [message for message in socket.received if "id" in message]
    command_types = [message["type"] for message in commands]
    assert command_types == [
        "wg_init",
        "reconcile_lan_snat",
        "iptables_add_forward",
        "wg_add_peer",
    ]
    assert commands[0]["params"]["public_ip"] == "203.0.113.70"
    assert commands[1]["params"] == {
        "pins": [
            {"lan_ip": "192.168.1.50", "public_ip": "203.0.113.70"}
        ]
    }
    assert commands[2]["params"]["public_ip"] == "203.0.113.70"


async def test_server_auth_reconnect_sends_empty_snat_snapshot(
    db,
    session_maker,
    factories,
    monkeypatch,
):
    server = await factories.make_server(db, primary_ip="203.0.113.71")

    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = RecordingWebSocket(create_agent_token(str(server.agent_id)))
    await main_module.agent_websocket(socket)

    commands = [message for message in socket.received if "id" in message]
    assert [message["type"] for message in commands] == [
        "wg_init",
        "reconcile_lan_snat",
    ]
    assert commands[1]["params"] == {"pins": []}


async def test_client_auth_reconnect_replays_attachment_and_lan_egress_pin(
    db,
    session_maker,
    factories,
    monkeypatch,
):
    server = await factories.make_server(db, primary_ip="203.0.113.80")
    tunnel_client = await factories.make_client(db)
    attachment = await factories.make_attachment(
        db,
        client=tunnel_client,
        server=server,
        tunnel_ip="10.21.0.20",
    )
    db.add(
        GatewayLanClient(
            tunnel_client_id=tunnel_client.id,
            lan_ip="192.168.1.60",
            egress_attachment_id=attachment.id,
        )
    )
    db.add(
        GatewayLanClient(
            tunnel_client_id=tunnel_client.id,
            lan_ip="192.168.1.61",
        )
    )
    await db.commit()

    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = RecordingWebSocket(create_agent_token(str(tunnel_client.agent_id)))
    await main_module.agent_websocket(socket)

    commands = [message for message in socket.received if "id" in message]
    assert [message["type"] for message in commands] == [
        "edge_node_role",
        "wg_attach",
        "set_lan_egress",
        "set_lan_egress",
    ]
    assert commands[0]["params"] == {"is_gateway": True, "lan_ip": "192.168.1.110", "lan_network": "192.168.1.0/24"}
    egress_by_ip = {
        message["params"]["lan_ip"]: message["params"]
        for message in commands[2:]
    }
    assert egress_by_ip["192.168.1.60"] == {
        "lan_ip": "192.168.1.60",
        "route_table_id": attachment.route_table_id,
        "wg_interface": attachment.wg_interface,
    }
    assert egress_by_ip["192.168.1.61"] == {
        "lan_ip": "192.168.1.61",
        "route_table_id": 0,
    }


async def test_plain_client_reconnect_clears_stale_lan_egress_pin(
    db,
    session_maker,
    factories,
    monkeypatch,
):
    server = await factories.make_server(db, primary_ip="203.0.113.81")
    tunnel_client = await factories.make_client(db, is_gateway=False)
    attachment = await factories.make_attachment(
        db,
        client=tunnel_client,
        server=server,
        tunnel_ip="10.21.0.21",
    )
    db.add(
        GatewayLanClient(
            tunnel_client_id=tunnel_client.id,
            lan_ip="192.168.1.62",
            egress_attachment_id=attachment.id,
        )
    )
    db.add(
        VpnEndpoint(
            tunnel_client_id=tunnel_client.id,
            wg_interface="wg-vpn0",
            listen_port=51821,
            vpn_network="10.45.0.0/24",
            public_endpoint="vpn.example.test:51821",
            enabled=True,
        )
    )
    await db.commit()

    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = RecordingWebSocket(create_agent_token(str(tunnel_client.agent_id)))
    await main_module.agent_websocket(socket)

    commands = [message for message in socket.received if "id" in message]
    assert [message["type"] for message in commands] == [
        "edge_node_role",
        "wg_attach",
        "set_lan_egress",
    ]
    assert commands[0]["params"]["is_gateway"] is False
    assert commands[2]["params"] == {
        "lan_ip": "192.168.1.62",
        "route_table_id": 0,
    }

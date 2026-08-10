"""Agent auth reconnect replays current runtime desired state over the socket."""

import json

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


def _use_real_socket_manager(monkeypatch, session_maker):
    from app import main as main_module

    runtime_manager = ConnectionManager()
    monkeypatch.setattr(main_module, "SessionLocal", session_maker)
    monkeypatch.setattr(main_module, "manager", runtime_manager)
    monkeypatch.setattr(agent_commands, "manager", runtime_manager)
    return main_module


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
        "wg_attach",
        "set_lan_egress",
        "set_lan_egress",
    ]
    egress_by_ip = {
        message["params"]["lan_ip"]: message["params"]
        for message in commands[1:]
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
        "wg_attach",
        "set_lan_egress",
    ]
    assert commands[1]["params"] == {
        "lan_ip": "192.168.1.62",
        "route_table_id": 0,
    }

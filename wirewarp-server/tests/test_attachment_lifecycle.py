"""End-to-end tests for the /api/tunnel-client-attachments router.

Covers:
- 503 when either agent is offline (rebase-style precheck).
- 201 on success, with auto-allocated wg_interface and tunnel_ip.
- 409 on duplicate (client, server) pair.
- DELETE: 409 when port forwards reference, 204 with cascade=1.
"""
import uuid

import pytest
from sqlalchemy import select

from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment


pytestmark = pytest.mark.asyncio


async def test_create_503_when_client_offline(client, db, factories, fake_manager):
    server_agent = await factories.make_agent(db, type_="server", name="srv-agent")
    server = await factories.make_server(db, agent=server_agent)
    client_agent = await factories.make_agent(db, type_="client", name="cli-agent")
    cli = await factories.make_client(db, agent=client_agent)
    # Server online, client offline
    fake_manager.online.add(str(server_agent.id))

    res = await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(cli.id), "tunnel_server_id": str(server.id)},
    )
    assert res.status_code == 503
    assert "client agent" in res.text


async def test_create_503_when_server_offline(client, db, factories, fake_manager):
    server_agent = await factories.make_agent(db, type_="server")
    server = await factories.make_server(db, agent=server_agent)
    client_agent = await factories.make_agent(db, type_="client")
    cli = await factories.make_client(db, agent=client_agent)
    fake_manager.online.add(str(client_agent.id))

    res = await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(cli.id), "tunnel_server_id": str(server.id)},
    )
    assert res.status_code == 503


async def test_create_success_allocates_ordinal_and_ip(client, db, factories, fake_manager):
    server_agent = await factories.make_agent(db, type_="server")
    server = await factories.make_server(db, agent=server_agent, network="10.21.0.0/24")
    client_agent = await factories.make_agent(db, type_="client")
    cli = await factories.make_client(db, agent=client_agent)
    fake_manager.online.add(str(server_agent.id))
    fake_manager.online.add(str(client_agent.id))

    res = await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(cli.id), "tunnel_server_id": str(server.id)},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["wg_interface"] == "wg0"
    assert body["fwmark"] == 0x101
    assert body["route_table_id"] == 100
    assert body["tunnel_ip"] == "10.21.0.2"  # .1 is server, .2 is first free host

    # Second attachment to a different server should be wg1
    server2 = await factories.make_server(db, network="10.22.0.0/24")
    fake_manager.online.add(str(server2.agent_id))
    res2 = await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(cli.id), "tunnel_server_id": str(server2.id)},
    )
    assert res2.status_code == 201, res2.text
    body2 = res2.json()
    assert body2["wg_interface"] == "wg1"
    assert body2["fwmark"] == 0x102
    assert body2["route_table_id"] == 101

    # The router dispatches wg_attach via send_command; verify our fake
    # manager captured both messages with the right command type.
    attach_msgs = [s for s in fake_manager.sent if s["message"]["type"] == "wg_attach"]
    assert len(attach_msgs) == 2
    # First attach payload
    p0 = attach_msgs[0]["message"]["params"]
    assert p0["wg_interface"] == "wg0"
    assert p0["fwmark"] == 0x101
    assert p0["route_table_id"] == 100


async def test_create_409_on_duplicate_pair(client, db, factories, fake_manager):
    server = await factories.make_server(db)
    cli = await factories.make_client(db)
    fake_manager.online.add(str(server.agent_id))
    fake_manager.online.add(str(cli.agent_id))

    res1 = await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(cli.id), "tunnel_server_id": str(server.id)},
    )
    assert res1.status_code == 201

    res2 = await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(cli.id), "tunnel_server_id": str(server.id)},
    )
    assert res2.status_code == 409


async def test_delete_409_when_port_forward_references(client, db, factories, fake_manager):
    server = await factories.make_server(db)
    cli = await factories.make_client(db)
    fake_manager.online.add(str(server.agent_id))
    fake_manager.online.add(str(cli.agent_id))

    create = await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(cli.id), "tunnel_server_id": str(server.id)},
    )
    assert create.status_code == 201
    att_id = create.json()["id"]

    # Force-create a port forward bound to this attachment
    pf = PortForward(
        id=uuid.uuid4(),
        attachment_id=uuid.UUID(att_id),
        protocol="tcp",
        public_port=8080,
        destination_ip="10.21.0.2",
        destination_port=8080,
    )
    db.add(pf)
    await db.commit()

    res = await client.delete(f"/api/tunnel-client-attachments/{att_id}")
    assert res.status_code == 409
    assert "desired state was preserved" in res.text.lower()


async def test_delete_cascade_is_blocked_and_preserves_forwards(
    client, db, factories, fake_manager
):
    server = await factories.make_server(db)
    cli = await factories.make_client(db)
    fake_manager.online.add(str(server.agent_id))
    fake_manager.online.add(str(cli.agent_id))

    create = await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(cli.id), "tunnel_server_id": str(server.id)},
    )
    att_id = create.json()["id"]

    pf = PortForward(
        id=uuid.uuid4(),
        attachment_id=uuid.UUID(att_id),
        protocol="tcp",
        public_port=8080,
        destination_ip="10.21.0.2",
        destination_port=8080,
    )
    db.add(pf)
    await db.commit()
    pf_id = pf.id

    res = await client.delete(f"/api/tunnel-client-attachments/{att_id}?cascade=1")
    assert res.status_code == 409
    assert "desired state was preserved" in res.text.lower()

    remaining_att = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == uuid.UUID(att_id))
    )
    assert remaining_att is not None

    remaining_pf = await db.scalar(
        select(PortForward).where(PortForward.id == pf_id)
    )
    assert remaining_pf is not None


async def test_list_filters_by_client(client, db, factories, fake_manager):
    server = await factories.make_server(db)
    c1 = await factories.make_client(db)
    c2 = await factories.make_client(db)
    fake_manager.online.add(str(server.agent_id))
    fake_manager.online.add(str(c1.agent_id))
    fake_manager.online.add(str(c2.agent_id))

    server2 = await factories.make_server(db, network="10.22.0.0/24")
    fake_manager.online.add(str(server2.agent_id))

    await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(c1.id), "tunnel_server_id": str(server.id)},
    )
    await client.post(
        "/api/tunnel-client-attachments",
        json={"tunnel_client_id": str(c2.id), "tunnel_server_id": str(server.id)},
    )

    res = await client.get(f"/api/tunnel-client-attachments?tunnel_client_id={c1.id}")
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["tunnel_client_id"] == str(c1.id)

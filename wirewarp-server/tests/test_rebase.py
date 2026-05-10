"""Rebase walks attachments (not the legacy direct FK) and renumbers per-
attachment tunnel_ips + forward destinations atomically. Verify the network
allocator's exclude-self path and the precheck pivots through attachments.
"""
import pytest
from sqlalchemy import select

from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment


pytestmark = pytest.mark.asyncio


async def test_rebase_renumbers_attachments_and_forwards(client, db, session_maker, factories, fake_manager):
    server = await factories.make_server(db, network="10.21.0.0/24")
    cli = await factories.make_client(db)
    att = await factories.make_attachment(
        db, client=cli, server=server, tunnel_ip="10.21.0.10", wg_interface="wg0"
    )
    pf = PortForward(
        attachment_id=att.id,
        protocol="tcp",
        public_port=8080,
        destination_ip="10.21.0.10",
        destination_port=8080,
    )
    db.add(pf)
    await db.commit()
    # Close the txn entirely so the API's rebase commit is visible to the
    # next session we open. SQLite's read snapshot is per-connection.
    await db.close()

    fake_manager.online.add(str(server.agent_id))
    fake_manager.online.add(str(cli.agent_id))

    res = await client.post(
        f"/api/tunnel-servers/{server.id}/rebase",
        json={"tunnel_network": "10.30.0.0/24"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["tunnel_network"] == "10.30.0.0/24"

    async with session_maker() as fresh:
        fresh_att = await fresh.scalar(
            select(TunnelClientAttachment).where(TunnelClientAttachment.id == att.id)
        )
        assert fresh_att.tunnel_ip == "10.30.0.10"
        fresh_pf = await fresh.scalar(select(PortForward).where(PortForward.id == pf.id))
        assert fresh_pf.destination_ip == "10.30.0.10"

    # Dispatch sequence: wg_init → wg_attach → iptables_remove_forward → iptables_add_forward
    types = [s["message"]["type"] for s in fake_manager.sent]
    assert types[0] == "wg_init"
    assert "wg_attach" in types
    assert "iptables_remove_forward" in types
    assert "iptables_add_forward" in types


async def test_rebase_precheck_503_when_attached_client_offline(client, db, factories, fake_manager):
    server = await factories.make_server(db, network="10.21.0.0/24")
    cli = await factories.make_client(db)
    await factories.make_attachment(db, client=cli, server=server)

    # Server agent is online but the attached client agent is offline.
    fake_manager.online.add(str(server.agent_id))

    res = await client.post(
        f"/api/tunnel-servers/{server.id}/rebase",
        json={"tunnel_network": "10.30.0.0/24"},
    )
    assert res.status_code == 503
    assert "client agent" in res.text


async def test_rebase_no_op_returns_200(client, db, factories, fake_manager):
    server = await factories.make_server(db, network="10.21.0.0/24")
    fake_manager.online.add(str(server.agent_id))
    res = await client.post(
        f"/api/tunnel-servers/{server.id}/rebase",
        json={"tunnel_network": "10.21.0.0/24"},
    )
    assert res.status_code == 200

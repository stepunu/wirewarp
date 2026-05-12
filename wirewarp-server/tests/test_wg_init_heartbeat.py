"""Regression test for the first-connect race where dispatch_wg_init fired
before the heartbeat had populated tunnel_server_ips, leaving
wg_public_key empty until an operator triggered a PATCH.
"""
import uuid

import pytest
from sqlalchemy import select

from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.services.tunnel_server_ops import dispatch_wg_init
from app.websocket.handlers import handle_heartbeat


pytestmark = pytest.mark.asyncio


async def _bare_server(db, agent):
    """A tunnel server with NO IPs and an empty wg_public_key — the state
    a freshly registered server sits in until its first heartbeat lands.
    """
    s = TunnelServer(
        id=uuid.uuid4(),
        agent_id=agent.id,
        wg_port=51820,
        wg_interface="wg0",
        public_iface="eth0",
        wg_public_key="",
        tunnel_network="10.21.0.0/24",
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def test_dispatch_wg_init_skips_when_no_primary_ip(db, factories, fake_manager):
    agent = await factories.make_agent(db, type_="server", name="srv-no-ip")
    server = await _bare_server(db, agent)
    fake_manager.online.add(str(agent.id))

    sent, cmd_id = await dispatch_wg_init(server, db)

    assert sent is False
    assert cmd_id == ""
    assert fake_manager.sent == []


async def test_heartbeat_fires_wg_init_when_first_ip_lands(db, factories, fake_manager):
    agent = await factories.make_agent(db, type_="server", name="srv-race")
    server = await _bare_server(db, agent)
    fake_manager.online.add(str(agent.id))

    await handle_heartbeat(
        str(agent.id),
        {"public_ip": "203.0.113.7", "public_ips": ["203.0.113.7"]},
        db,
    )

    ip_rows = (
        await db.execute(
            select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id)
        )
    ).scalars().all()
    assert len(ip_rows) == 1
    assert ip_rows[0].address == "203.0.113.7"
    assert ip_rows[0].is_primary is True

    wg_inits = [s for s in fake_manager.sent if s["message"]["type"] == "wg_init"]
    assert len(wg_inits) == 1, fake_manager.sent
    assert wg_inits[0]["message"]["params"]["public_ip"] == "203.0.113.7"


async def test_heartbeat_does_not_refire_when_wg_public_key_present(db, factories, fake_manager):
    agent = await factories.make_agent(db, type_="server", name="srv-already-init")
    server = TunnelServer(
        id=uuid.uuid4(),
        agent_id=agent.id,
        wg_port=51820,
        wg_interface="wg0",
        public_iface="eth0",
        wg_public_key="x" * 44,
        tunnel_network="10.21.0.0/24",
    )
    db.add(server)
    await db.commit()
    fake_manager.online.add(str(agent.id))

    await handle_heartbeat(
        str(agent.id),
        {"public_ip": "203.0.113.8", "public_ips": ["203.0.113.8"]},
        db,
    )

    wg_inits = [s for s in fake_manager.sent if s["message"]["type"] == "wg_init"]
    assert wg_inits == []


async def test_heartbeat_auto_detects_public_iface(db, factories, fake_manager):
    """Agent reports public_iface=ens18; column default eth0 is treated as
    a placeholder, so server adopts the reported iface and re-fires wg_init
    with the corrected value."""
    agent = await factories.make_agent(db, type_="server", name="srv-iface")
    server = TunnelServer(
        id=uuid.uuid4(),
        agent_id=agent.id,
        wg_port=51820,
        wg_interface="wg0",
        public_iface="eth0",
        wg_public_key="x" * 44,
        tunnel_network="10.21.0.0/24",
    )
    db.add(server)
    db.add(
        TunnelServerIP(
            tunnel_server_id=server.id,
            address="203.0.113.20",
            is_primary=True,
        )
    )
    await db.commit()
    fake_manager.online.add(str(agent.id))

    await handle_heartbeat(
        str(agent.id),
        {"public_ip": "203.0.113.20", "public_ips": ["203.0.113.20"], "public_iface": "ens18"},
        db,
    )

    await db.refresh(server)
    assert server.public_iface == "ens18"
    wg_inits = [s for s in fake_manager.sent if s["message"]["type"] == "wg_init"]
    assert len(wg_inits) == 1
    assert wg_inits[0]["message"]["params"]["public_iface"] == "ens18"


async def test_heartbeat_does_not_override_operator_set_iface(db, factories, fake_manager):
    """Once public_iface is set to a non-default value (operator PATCH),
    the agent's reported iface must not override it."""
    agent = await factories.make_agent(db, type_="server", name="srv-iface-override")
    server = TunnelServer(
        id=uuid.uuid4(),
        agent_id=agent.id,
        wg_port=51820,
        wg_interface="wg0",
        public_iface="enp0s3",
        wg_public_key="x" * 44,
        tunnel_network="10.21.0.0/24",
    )
    db.add(server)
    db.add(
        TunnelServerIP(
            tunnel_server_id=server.id,
            address="203.0.113.21",
            is_primary=True,
        )
    )
    await db.commit()
    fake_manager.online.add(str(agent.id))

    await handle_heartbeat(
        str(agent.id),
        {"public_ip": "203.0.113.21", "public_ips": ["203.0.113.21"], "public_iface": "ens18"},
        db,
    )

    await db.refresh(server)
    assert server.public_iface == "enp0s3"
    wg_inits = [s for s in fake_manager.sent if s["message"]["type"] == "wg_init"]
    assert wg_inits == []


async def test_heartbeat_does_not_refire_on_secondary_ip(db, factories, fake_manager):
    agent = await factories.make_agent(db, type_="server", name="srv-second-ip")
    server = await _bare_server(db, agent)
    db.add(
        TunnelServerIP(
            tunnel_server_id=server.id,
            address="203.0.113.9",
            is_primary=True,
        )
    )
    await db.commit()
    fake_manager.online.add(str(agent.id))

    await handle_heartbeat(
        str(agent.id),
        {"public_ip": "203.0.113.9", "public_ips": ["203.0.113.9", "203.0.113.10"]},
        db,
    )

    wg_inits = [s for s in fake_manager.sent if s["message"]["type"] == "wg_init"]
    assert wg_inits == []

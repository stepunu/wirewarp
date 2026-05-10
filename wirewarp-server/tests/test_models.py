"""Model-level tests for TunnelClientAttachment.

Cover the unique constraints from migration 0009 (uq_tca_client_server,
uq_tca_server_ip), the cascade-on-parent-delete relationship, and the
attachment ↔ port_forward FK pivot.
"""
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.port_forward import PortForward
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment


pytestmark = pytest.mark.asyncio


async def test_unique_client_server_pair(db, factories):
    server = await factories.make_server(db)
    client = await factories.make_client(db)
    await factories.make_attachment(
        db, client=client, server=server, tunnel_ip="10.21.0.10", wg_interface="wg0"
    )

    dup = TunnelClientAttachment(
        tunnel_client_id=client.id,
        tunnel_server_id=server.id,
        tunnel_ip="10.21.0.11",
        wg_interface="wg1",
        fwmark=0x102,
        route_table_id=101,
    )
    db.add(dup)
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_unique_server_tunnel_ip(db, factories):
    server = await factories.make_server(db)
    c1 = await factories.make_client(db)
    c2 = await factories.make_client(db)
    await factories.make_attachment(
        db, client=c1, server=server, tunnel_ip="10.21.0.10", wg_interface="wg0"
    )

    dup_ip = TunnelClientAttachment(
        tunnel_client_id=c2.id,
        tunnel_server_id=server.id,
        tunnel_ip="10.21.0.10",
        wg_interface="wg0",
        fwmark=0x101,
        route_table_id=100,
    )
    db.add(dup_ip)
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_attachment_cascades_on_client_delete(db, factories):
    server = await factories.make_server(db)
    client = await factories.make_client(db)
    att = await factories.make_attachment(db, client=client, server=server)
    att_id = att.id

    await db.delete(client)
    await db.commit()

    remaining = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == att_id)
    )
    assert remaining is None


async def test_port_forward_blocks_attachment_delete(db, factories):
    """ON DELETE RESTRICT on port_forwards.attachment_id means deleting an
    attachment with active forwards must fail at the DB level.
    """
    server = await factories.make_server(db)
    client = await factories.make_client(db)
    att = await factories.make_attachment(db, client=client, server=server)
    pf = PortForward(
        id=uuid.uuid4(),
        attachment_id=att.id,
        protocol="tcp",
        public_port=8080,
        destination_ip=att.tunnel_ip,
        destination_port=8080,
    )
    db.add(pf)
    await db.commit()

    await db.delete(att)
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_port_forward_unique_per_attachment(db, factories):
    """Spec unique key: (attachment_id, tunnel_server_ip_id, protocol, public_port).
    Two attachments bound to the same server-IP can each take port 8080; one
    attachment cannot bind 8080 twice on the same server-IP.

    The NULL-ip case is covered by a partial index in alembic migration 0012;
    we exercise the explicit-ip path here so the regular UNIQUE constraint
    fires (NULLs are distinct under regular UNIQUE).
    """
    from app.models.tunnel_server_ip import TunnelServerIP
    from sqlalchemy import select

    server = await factories.make_server(db)
    c1 = await factories.make_client(db)
    c2 = await factories.make_client(db)
    a1 = await factories.make_attachment(db, client=c1, server=server, tunnel_ip="10.21.0.10", wg_interface="wg0")
    a2 = await factories.make_attachment(db, client=c2, server=server, tunnel_ip="10.21.0.11", wg_interface="wg0")

    server_ip = await db.scalar(
        select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id)
    )
    assert server_ip is not None

    db.add(
        PortForward(
            id=uuid.uuid4(), attachment_id=a1.id, tunnel_server_ip_id=server_ip.id,
            protocol="tcp", public_port=8080,
            destination_ip=a1.tunnel_ip, destination_port=8080,
        )
    )
    db.add(
        PortForward(
            id=uuid.uuid4(), attachment_id=a2.id, tunnel_server_ip_id=server_ip.id,
            protocol="tcp", public_port=8080,
            destination_ip=a2.tunnel_ip, destination_port=8080,
        )
    )
    await db.commit()  # both succeed — different attachment_id, same (ip, port)

    db.add(
        PortForward(
            id=uuid.uuid4(), attachment_id=a1.id, tunnel_server_ip_id=server_ip.id,
            protocol="tcp", public_port=8080,
            destination_ip=a1.tunnel_ip, destination_port=8081,
        )
    )
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_client_eager_loads_attachments(db, factories):
    server = await factories.make_server(db)
    client = await factories.make_client(db)
    await factories.make_attachment(db, client=client, server=server, wg_interface="wg0")
    await factories.make_attachment(
        db, client=client, server=await factories.make_server(db, network="10.22.0.0/24"),
        tunnel_ip="10.22.0.10", wg_interface="wg1", fwmark=0x102, route_table_id=101,
    )

    from sqlalchemy.orm import selectinload

    fresh = await db.scalar(
        select(TunnelClient)
        .options(selectinload(TunnelClient.attachments))
        .where(TunnelClient.id == client.id)
    )
    assert fresh is not None
    assert len(fresh.attachments) == 2
    interfaces = sorted(a.wg_interface for a in fresh.attachments)
    assert interfaces == ["wg0", "wg1"]

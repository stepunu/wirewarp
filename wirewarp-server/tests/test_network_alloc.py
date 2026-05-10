"""Network/IP allocator tests.

Spec-relevant invariants:
- Ordinal allocator picks the *lowest unused* slot per client, so detach +
  reattach reuses the freed slot (no integer drift).
- IP allocator skips `.1` (server itself) and any host already held by an
  existing attachment for that server.
"""
import pytest

from app.services.network_alloc import (
    allocate_attachment_ip,
    allocate_attachment_ordinal,
    allocate_tunnel_network,
    renumber_host,
    server_tunnel_ip,
)


pytestmark = pytest.mark.asyncio


async def test_ordinal_starts_at_zero(db, factories):
    client = await factories.make_client(db)
    n = await allocate_attachment_ordinal(client.id, db)
    assert n == 0


async def test_ordinal_grows_then_reuses_freed_slot(db, factories):
    server_a = await factories.make_server(db, network="10.21.0.0/24")
    server_b = await factories.make_server(db, network="10.22.0.0/24")
    server_c = await factories.make_server(db, network="10.23.0.0/24")
    client = await factories.make_client(db)

    a0 = await factories.make_attachment(
        db, client=client, server=server_a, tunnel_ip="10.21.0.10", wg_interface="wg0"
    )
    await factories.make_attachment(
        db, client=client, server=server_b, tunnel_ip="10.22.0.10",
        wg_interface="wg1", fwmark=0x102, route_table_id=101,
    )

    # Next allocation should be 2 (lowest unused).
    n = await allocate_attachment_ordinal(client.id, db)
    assert n == 2

    # Detach wg0 → next allocation should reuse 0, not 2.
    await db.delete(a0)
    await db.commit()
    n = await allocate_attachment_ordinal(client.id, db)
    assert n == 0

    # After re-attaching at 0, should jump to 2 again (1 still in use).
    await factories.make_attachment(
        db, client=client, server=server_c, tunnel_ip="10.23.0.10",
        wg_interface=f"wg{n}", fwmark=0x101 + n, route_table_id=100 + n,
    )
    n2 = await allocate_attachment_ordinal(client.id, db)
    assert n2 == 2


async def test_ordinal_is_per_client(db, factories):
    server = await factories.make_server(db)
    c1 = await factories.make_client(db)
    c2 = await factories.make_client(db)

    await factories.make_attachment(db, client=c1, server=server, wg_interface="wg0")

    # c2 starts fresh, should be wg0.
    assert await allocate_attachment_ordinal(c2.id, db) == 0


async def test_ip_allocator_skips_server_ip_and_used_hosts(db, factories):
    server = await factories.make_server(db, network="10.21.0.0/24")
    client = await factories.make_client(db)
    # Pin some attachments
    await factories.make_attachment(
        db, client=client, server=server, tunnel_ip="10.21.0.2", wg_interface="wg0"
    )
    other = await factories.make_client(db)
    await factories.make_attachment(
        db, client=other, server=server, tunnel_ip="10.21.0.3",
        wg_interface="wg0", fwmark=0x101, route_table_id=100,
    )

    ip = await allocate_attachment_ip(server.id, db)
    # First free host past .1 (server) and skipping .2 / .3
    assert ip == "10.21.0.4"


async def test_ip_allocator_starts_after_server_ip_when_empty(db, factories):
    server = await factories.make_server(db, network="10.21.0.0/24")
    ip = await allocate_attachment_ip(server.id, db)
    assert ip == "10.21.0.2"


async def test_renumber_host_preserves_octet():
    assert renumber_host("10.0.0.3", "10.22.0.0/24") == "10.22.0.3"


async def test_server_tunnel_ip_is_dot_one():
    assert server_tunnel_ip("10.21.0.0/24") == "10.21.0.1"


async def test_tunnel_network_allocator_skips_used(db, factories):
    await factories.make_server(db, network="10.21.0.0/24")
    n = await allocate_tunnel_network(db)
    assert n == "10.22.0.0/24"

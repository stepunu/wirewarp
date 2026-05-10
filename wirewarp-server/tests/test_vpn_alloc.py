"""VPN /24 + /32 allocation: doesn't collide with tunnel servers, walks pool."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tunnel_client import TunnelClient
from app.models.tunnel_server import TunnelServer
from app.models.vpn_endpoint import VpnEndpoint
from app.models.vpn_profile import VpnProfile
from app.services.network_alloc import allocate_vpn_network, allocate_vpn_peer_ip


@pytest.mark.asyncio
async def test_allocate_vpn_network_first_call_picks_first_pool_slot(db: AsyncSession):
    net = await allocate_vpn_network(db)
    assert net == "10.21.0.0/24"


@pytest.mark.asyncio
async def test_allocate_vpn_network_skips_existing_tunnel_servers(
    db: AsyncSession, factories
):
    await factories.make_server(db, network="10.21.0.0/24")
    await factories.make_server(db, network="10.22.0.0/24")
    net = await allocate_vpn_network(db)
    assert net == "10.23.0.0/24"


@pytest.mark.asyncio
async def test_allocate_vpn_network_skips_existing_vpn_endpoints(
    db: AsyncSession, factories
):
    client = await factories.make_client(db)
    db.add(
        VpnEndpoint(
            tunnel_client_id=client.id,
            wg_interface="wg-vpn0",
            listen_port=51821,
            vpn_network="10.21.0.0/24",
            public_endpoint="vpn.example:51821",
        )
    )
    await db.commit()

    net = await allocate_vpn_network(db)
    assert net == "10.22.0.0/24"


@pytest.mark.asyncio
async def test_allocate_vpn_peer_ip_skips_server_ip_and_used(
    db: AsyncSession, factories
):
    client = await factories.make_client(db)
    endpoint = VpnEndpoint(
        tunnel_client_id=client.id,
        wg_interface="wg-vpn0",
        listen_port=51821,
        vpn_network="10.30.0.0/24",
        public_endpoint="vpn.example:51821",
    )
    db.add(endpoint)
    await db.commit()
    await db.refresh(endpoint)

    # First peer skips .1 (gateway itself) and gets .2.
    ip1 = await allocate_vpn_peer_ip(endpoint.id, db)
    assert ip1 == "10.30.0.2"

    # Seed a user first so the profile FK is satisfied.
    from app.models.user import User

    user = User(
        id=uuid.uuid4(),
        username="alice-alloc",
        email="alice-alloc@stub",
        password_hash=None,
        role="viewer",
        auth_provider="local",
    )
    db.add(user)
    await db.commit()

    db.add(
        VpnProfile(
            user_id=user.id,
            vpn_endpoint_id=endpoint.id,
            label="phone",
            tunnel_ip=ip1,
            wg_public_key="PUBKEY1",
            wg_psk="PSK1",
            tunnel_mode="split",
        )
    )
    await db.commit()

    ip2 = await allocate_vpn_peer_ip(endpoint.id, db)
    assert ip2 == "10.30.0.3"

"""Tunnel network allocation.

Each tunnel server gets a unique /24 so cross-server routing, log
attribution, and client rehoming are unambiguous. We carve /24s out of
the 10.0.0.0/8 space, incrementing the second octet starting at 21:
10.21.0.0/24, 10.22.0.0/24, ..., 10.255.0.0/24. That gives 235 servers,
which is plenty for any realistic deployment.
"""

import ipaddress
import re
import uuid
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer


POOL_START_OCTET = 21
POOL_END_OCTET = 255  # inclusive


def _candidate_networks() -> Iterable[str]:
    for octet in range(POOL_START_OCTET, POOL_END_OCTET + 1):
        yield f"10.{octet}.0.0/24"


def _is_overlapping(candidate: str, used: set[str]) -> bool:
    """Two /24s overlap if their network addresses are equal. Anything else
    we treat conservatively: parse and compare."""
    if candidate in used:
        return True
    try:
        cand_net = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return True  # malformed candidate; never use it
    for u in used:
        try:
            other = ipaddress.ip_network(u, strict=False)
        except ValueError:
            continue
        if cand_net.overlaps(other):
            return True
    return False


async def allocate_tunnel_network(
    db: AsyncSession,
    exclude_server_id: str | None = None,
) -> str:
    """Pick the next free /24 from the pool.

    `exclude_server_id`: optional server whose current network is excluded
    from the "used" set (useful when rebasing — the server's own old network
    shouldn't block the search).

    Raises RuntimeError if the pool is exhausted.
    """
    q = select(TunnelServer.id, TunnelServer.tunnel_network)
    rows = (await db.execute(q)).all()
    used = {
        net for sid, net in rows if net and (exclude_server_id is None or str(sid) != str(exclude_server_id))
    }
    for cand in _candidate_networks():
        if not _is_overlapping(cand, used):
            return cand
    raise RuntimeError(
        f"Tunnel network pool exhausted (all /24s in 10.{POOL_START_OCTET}.0.0 — 10.{POOL_END_OCTET}.0.0 are in use)"
    )


def renumber_host(old_ip: str, new_network: str) -> str:
    """Map an IP from one /24 to another, preserving the host octet.

    e.g. renumber_host("10.0.0.3", "10.22.0.0/24") -> "10.22.0.3".
    Caller is responsible for ensuring old_ip lives in a /24.
    """
    new = ipaddress.ip_network(new_network, strict=False)
    host_octet = old_ip.rsplit(".", 1)[1]
    prefix = str(new.network_address).rsplit(".", 1)[0]
    return f"{prefix}.{host_octet}"


def server_tunnel_ip(network: str) -> str:
    """The tunnel-side IP of the server itself: first usable host (.1)."""
    n = ipaddress.ip_network(network, strict=False)
    prefix = str(n.network_address).rsplit(".", 1)[0]
    return f"{prefix}.1"


_WG_IFACE_RE = re.compile(r"^wg(\d+)$")


async def allocate_attachment_ordinal(client_id: uuid.UUID, db: AsyncSession) -> int:
    """Lowest unused N for a new wgN interface on this client.

    Detach+reattach reuses the freed slot, so kernel state on the gateway
    stays compact and there's no integer drift over time.
    """
    rows = await db.execute(
        select(TunnelClientAttachment.wg_interface).where(
            TunnelClientAttachment.tunnel_client_id == client_id
        )
    )
    used: set[int] = set()
    for (iface,) in rows.all():
        m = _WG_IFACE_RE.match(iface or "")
        if m:
            used.add(int(m.group(1)))
    n = 0
    while n in used:
        n += 1
    return n


async def allocate_attachment_ip(server_id: uuid.UUID, db: AsyncSession) -> str:
    """Next free host in the server's /24, skipping `.1` (server itself) and
    any host already held by an existing attachment for this server.
    """
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))
    if server is None:
        raise ValueError(f"tunnel server {server_id} not found")
    network = ipaddress.ip_network(server.tunnel_network, strict=False)
    server_ip = server_tunnel_ip(server.tunnel_network)

    rows = await db.execute(
        select(TunnelClientAttachment.tunnel_ip).where(
            TunnelClientAttachment.tunnel_server_id == server_id
        )
    )
    used = {ip for (ip,) in rows.all() if ip}
    used.add(server_ip)

    for host in network.hosts():
        cand = str(host)
        if cand not in used:
            return cand
    raise RuntimeError(f"tunnel network {server.tunnel_network} exhausted")


# ---- VPN endpoint allocation -------------------------------------------
#
# VPN endpoints share the same `10.X.0.0/24` pool as tunnel servers — the
# allocator unions both tables so an operator can't accidentally pick a
# /24 that's already taken by a tunnel server (or vice-versa). Each VPN
# endpoint owns its full /24; peers (one per device) get a /32 inside it.


async def allocate_vpn_network(
    db: AsyncSession,
    exclude_endpoint_id: uuid.UUID | str | None = None,
) -> str:
    """Pick the next free /24 not in use by any tunnel server or VPN endpoint."""
    from app.models.vpn_endpoint import VpnEndpoint

    ts_rows = await db.execute(select(TunnelServer.tunnel_network))
    used: set[str] = {n for (n,) in ts_rows.all() if n}

    vpn_rows = await db.execute(select(VpnEndpoint.id, VpnEndpoint.vpn_network))
    used.update(
        n
        for eid, n in vpn_rows.all()
        if n
        and (exclude_endpoint_id is None or str(eid) != str(exclude_endpoint_id))
    )

    for cand in _candidate_networks():
        if not _is_overlapping(cand, used):
            return cand
    raise RuntimeError(
        f"VPN network pool exhausted (all /24s in 10.{POOL_START_OCTET}.0.0 — 10.{POOL_END_OCTET}.0.0 are in use)"
    )


async def allocate_vpn_peer_ip(endpoint_id: uuid.UUID, db: AsyncSession) -> str:
    """Next free /32 inside the endpoint's /24, skipping `.1` (the gateway's
    own address on the VPN interface) and any IP already held by an
    existing profile for this endpoint."""
    from app.models.vpn_endpoint import VpnEndpoint
    from app.models.vpn_profile import VpnProfile

    endpoint = await db.scalar(select(VpnEndpoint).where(VpnEndpoint.id == endpoint_id))
    if endpoint is None:
        raise ValueError(f"VPN endpoint {endpoint_id} not found")
    network = ipaddress.ip_network(endpoint.vpn_network, strict=False)
    server_ip = server_tunnel_ip(endpoint.vpn_network)

    rows = await db.execute(
        select(VpnProfile.tunnel_ip).where(VpnProfile.vpn_endpoint_id == endpoint_id)
    )
    used = {ip for (ip,) in rows.all() if ip}
    used.add(server_ip)

    for host in network.hosts():
        cand = str(host)
        if cand not in used:
            return cand
    raise RuntimeError(f"VPN network {endpoint.vpn_network} exhausted")

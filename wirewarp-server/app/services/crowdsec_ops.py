"""CrowdSec install + auto-whitelist plumbing.

The whitelist computation is centralised here so that:
  - the install command and the periodic sync command share the exact
    same payload-construction code,
  - tests can hit a single pure function with fixtures.

Whitelist scope (matches operator confirmation):

  * Every OTHER agent's `agent.public_ip` (so one VPS doesn't ban
    another VPS's outbound checks).
  * Every `tunnel_server_ips.address` (additional public IPs).
  * Every tunnel mesh `/24` from `tunnel_servers.tunnel_network`
    (peers reach the VPS with these as source).
  * Every VPN endpoint's `vpn_network` (road-warrior peers).
  * Every gateway client's `vm_network` (the LAN subnet itself, broad).
  * Every discovered `gateway_lan_clients.lan_ip` (per-host precision).

Payload shape sent to the agent:

  {
    "ips":   ["1.2.3.4", "10.0.0.5", ...],   # sorted, deduped
    "cidrs": ["10.21.0.0/24", "192.168.40.0/24", ...]
  }

The agent writes a CrowdSec parser at
  /etc/crowdsec/parsers/s02-enrich/99-wirewarp-whitelist.yaml
with this content.
"""
from __future__ import annotations

import hashlib
import json
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.gateway_lan_client import GatewayLanClient
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.vpn_endpoint import VpnEndpoint


async def build_whitelist(
    target_agent_id: uuid.UUID | str, db: AsyncSession
) -> dict:
    """Compute the auto-whitelist payload for the given crowdsec host.

    Excludes the target agent's own public IPs from the `ips` list —
    no point in whitelisting yourself, and it would just bloat the
    payload + hash churn on routine IP changes.
    """
    target_id = str(target_agent_id)

    ips: set[str] = set()
    cidrs: set[str] = set()

    # Every other agent's public_ip.
    rows = (await db.execute(select(Agent.id, Agent.public_ip))).all()
    self_agent_ids: set[str] = set()
    for row in rows:
        ag_id, pub_ip = row
        if str(ag_id) == target_id:
            self_agent_ids.add(str(ag_id))
            continue
        if pub_ip:
            ips.add(pub_ip)

    # Every additional tunnel-server IP (excluding the target's own).
    rows = (
        await db.execute(
            select(TunnelServerIP.address, TunnelServer.agent_id)
            .join(TunnelServer, TunnelServer.id == TunnelServerIP.tunnel_server_id)
        )
    ).all()
    for address, ag_id in rows:
        if str(ag_id) == target_id:
            continue
        if address:
            ips.add(address)

    # Every tunnel mesh subnet — peers reach the VPS with these as source.
    networks = (
        await db.execute(select(TunnelServer.tunnel_network))
    ).scalars().all()
    for n in networks:
        if n:
            cidrs.add(n)

    # Every VPN endpoint subnet.
    vpn_networks = (
        await db.execute(select(VpnEndpoint.vpn_network))
    ).scalars().all()
    for n in vpn_networks:
        if n:
            cidrs.add(n)

    # Every gateway client's vm_network (broad LAN allow).
    vm_networks = (
        await db.execute(select(TunnelClient.vm_network).where(TunnelClient.is_gateway.is_(True)))
    ).scalars().all()
    for n in vm_networks:
        if n:
            cidrs.add(n)

    # Every discovered LAN client (precise per-host allow).
    lan_ips = (
        await db.execute(select(GatewayLanClient.lan_ip))
    ).scalars().all()
    for ip in lan_ips:
        if ip:
            ips.add(ip)

    return {
        "ips": sorted(ips),
        "cidrs": sorted(cidrs),
    }


def whitelist_hash(payload: dict) -> str:
    """Stable hex SHA-256 of the canonical JSON form of the payload.

    Used as the dispatch trigger: when the freshly-built whitelist hash
    differs from the snapshot's `whitelist_hash` column, dispatch a sync
    command and update the column. JSON with sort_keys=True is the
    canonical form so reordered DB rows can't flap the hash.
    """
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()

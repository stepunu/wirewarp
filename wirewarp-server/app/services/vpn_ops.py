"""Dispatch helpers + .conf rendering + key generation for VPN endpoints.

Mirrors the shape of `app/services/tunnel_server_ops.py` — every state
change on a VpnEndpoint or VpnProfile that needs to land on the gateway
agent goes through one of these helpers.

Private keys: generated server-side with `wg genkey | wg pubkey` (or in
pure Python via cryptography), returned ONCE to the API caller via the
rendered .conf, and immediately discarded. The DB only ever holds the
public key + PSK + peer metadata.
"""
from __future__ import annotations

import base64
import logging
import secrets
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tunnel_client import TunnelClient
from app.models.vpn_endpoint import VpnEndpoint
from app.models.vpn_permission import VpnPermission
from app.models.vpn_profile import VpnProfile
from app.services.agent_commands import send_command
from app.services.network_alloc import server_tunnel_ip


logger = logging.getLogger(__name__)


# ---- key + PSK generation ---------------------------------------------


@dataclass
class WgKeypair:
    private_key: str  # base64
    public_key: str   # base64


def generate_keypair() -> WgKeypair:
    """Generate a Curve25519 keypair in the WireGuard wire format.

    WireGuard keys are raw 32-byte X25519 keys, base64-encoded. We use
    `cryptography` (already a dep) rather than shelling out to `wg
    genkey` — the control server has no `wg` binary inside the Docker
    image and we don't want to add one just for this."""
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return WgKeypair(
        private_key=base64.b64encode(priv_bytes).decode("ascii"),
        public_key=base64.b64encode(pub_bytes).decode("ascii"),
    )


def generate_psk() -> str:
    """32 random bytes, base64-encoded — wireguard preshared-key wire format."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


# ---- .conf rendering --------------------------------------------------


def _format_port_range(start: int | None, end: int | None) -> str | None:
    if start is None:
        return None
    if end is None or end == start:
        return str(start)
    return f"{start}:{end}"  # iptables-style; .conf side never sees this


def compute_allowed_ips(
    endpoint: VpnEndpoint,
    profile: VpnProfile,
    permissions: list[VpnPermission],
) -> list[str]:
    """Compute AllowedIPs for the .conf based on tunnel mode + permissions."""
    if profile.tunnel_mode == "full":
        return ["0.0.0.0/0", "::/0"]
    out: list[str] = []
    seen: set[str] = set()
    for p in permissions:
        if p.destination not in seen:
            out.append(p.destination)
            seen.add(p.destination)
    return out or [endpoint.vpn_network]


def _ensure_endpoint_has_port(public_endpoint: str, listen_port: int) -> str:
    """Append the configured listen port if the operator didn't include one
    in the public_endpoint field. Handles bare hostnames, IPv4, and the
    [v6]:port form."""
    if not public_endpoint:
        return public_endpoint
    if public_endpoint.startswith("["):
        # bracketed IPv6 form already includes its own port discriminator
        if "]:" in public_endpoint:
            return public_endpoint
        return f"{public_endpoint}:{listen_port}"
    if ":" in public_endpoint:
        return public_endpoint
    return f"{public_endpoint}:{listen_port}"


def render_conf(
    *,
    endpoint: VpnEndpoint,
    profile: VpnProfile,
    permissions: list[VpnPermission],
    private_key: str,
) -> str:
    """Build the WireGuard client `.conf` text for this profile."""
    address = f"{profile.tunnel_ip}/32"
    allowed = ", ".join(compute_allowed_ips(endpoint, profile, permissions))
    endpoint_str = _ensure_endpoint_has_port(endpoint.public_endpoint, endpoint.listen_port)
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
    ]
    if endpoint.dns_servers:
        lines.append("DNS = " + ", ".join(endpoint.dns_servers))
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {endpoint.wg_public_key or 'PENDING_ENDPOINT_INIT'}",
        f"PresharedKey = {profile.wg_psk}",
        f"AllowedIPs = {allowed}",
        f"Endpoint = {endpoint_str}",
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(lines)


# ---- dispatch helpers -------------------------------------------------


async def _gateway_agent_id(endpoint: VpnEndpoint, db: AsyncSession) -> str | None:
    client = await db.scalar(
        select(TunnelClient).where(TunnelClient.id == endpoint.tunnel_client_id)
    )
    if client is None or client.agent_id is None:
        return None
    return str(client.agent_id)


async def load_user_endpoint_permissions(
    user_id, vpn_endpoint_id, db: AsyncSession
) -> list[VpnPermission]:
    """Return every permission rule the user has on the given endpoint.

    Profiles inherit this set — when a permission row changes, the agent's
    iptables for every profile of that user on that endpoint is reapplied
    via dispatch_vpn_peer_update_rules.
    """
    rows = await db.execute(
        select(VpnPermission).where(
            VpnPermission.user_id == user_id,
            VpnPermission.vpn_endpoint_id == vpn_endpoint_id,
        )
    )
    return list(rows.scalars().all())


def _peer_rule_payload(perm: VpnPermission) -> dict:
    return {
        "destination": perm.destination,
        "protocol": perm.protocol,
        "port_range_start": perm.port_range_start,
        "port_range_end": perm.port_range_end,
    }


async def dispatch_vpn_endpoint_up(
    endpoint: VpnEndpoint,
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str]:
    agent_id = await _gateway_agent_id(endpoint, db)
    if agent_id is None:
        return False, ""
    return await send_command(
        agent_id=agent_id,
        command_type="vpn_endpoint_up",
        params={
            "interface": endpoint.wg_interface,
            "listen_port": endpoint.listen_port,
            "vpn_network": endpoint.vpn_network,
            "vpn_server_ip": server_tunnel_ip(endpoint.vpn_network),
            "endpoint_id": str(endpoint.id),
            "dns_servers": endpoint.dns_servers or [],
        },
        db=db,
        actor_user_id=actor_user_id,
    )


async def dispatch_vpn_endpoint_down(
    endpoint: VpnEndpoint,
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str]:
    agent_id = await _gateway_agent_id(endpoint, db)
    if agent_id is None:
        return False, ""
    return await send_command(
        agent_id=agent_id,
        command_type="vpn_endpoint_down",
        params={"interface": endpoint.wg_interface},
        db=db,
        actor_user_id=actor_user_id,
    )


async def dispatch_vpn_peer_add(
    profile: VpnProfile,
    endpoint: VpnEndpoint,
    permissions: list[VpnPermission],
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str]:
    agent_id = await _gateway_agent_id(endpoint, db)
    if agent_id is None:
        return False, ""
    full_tunnel = profile.tunnel_mode == "full"
    return await send_command(
        agent_id=agent_id,
        command_type="vpn_peer_add",
        params={
            "interface": endpoint.wg_interface,
            "vpn_network": endpoint.vpn_network,
            "public_key": profile.wg_public_key,
            "psk": profile.wg_psk,
            "tunnel_ip": profile.tunnel_ip,
            "full_tunnel": full_tunnel,
            "rules": [_peer_rule_payload(p) for p in permissions],
        },
        db=db,
        actor_user_id=actor_user_id,
    )


async def dispatch_vpn_peer_remove(
    profile: VpnProfile,
    endpoint: VpnEndpoint,
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str]:
    agent_id = await _gateway_agent_id(endpoint, db)
    if agent_id is None:
        return False, ""
    return await send_command(
        agent_id=agent_id,
        command_type="vpn_peer_remove",
        params={
            "interface": endpoint.wg_interface,
            "public_key": profile.wg_public_key,
            "tunnel_ip": profile.tunnel_ip,
        },
        db=db,
        actor_user_id=actor_user_id,
    )


async def dispatch_vpn_peer_update_rules(
    profile: VpnProfile,
    endpoint: VpnEndpoint,
    permissions: list[VpnPermission],
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str]:
    """Reapply iptables rules for one peer after the admin edits the
    permission list (or toggles tunnel_mode)."""
    agent_id = await _gateway_agent_id(endpoint, db)
    if agent_id is None:
        return False, ""
    return await send_command(
        agent_id=agent_id,
        command_type="vpn_peer_update_rules",
        params={
            "interface": endpoint.wg_interface,
            "vpn_network": endpoint.vpn_network,
            "tunnel_ip": profile.tunnel_ip,
            "full_tunnel": profile.tunnel_mode == "full",
            "rules": [_peer_rule_payload(p) for p in permissions],
        },
        db=db,
        actor_user_id=actor_user_id,
    )

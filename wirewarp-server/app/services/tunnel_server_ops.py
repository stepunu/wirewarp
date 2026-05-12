"""Shared dispatch helpers for tunnel-server operations.

These build the right command payload from the DB state and send it to the
agent. Used by:
  - PATCH /tunnel-servers/{id}      (config edit)
  - WS register handler             (auto wg_init on first connection)
  - POST /tunnel-servers/{id}/rebase (network renumber, walks attachments)
  - POST /tunnel-client-attachments (attach + detach lifecycle)
"""

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.services.agent_commands import send_command
from app.services.network_alloc import server_tunnel_ip
from app.services.primary_ip import get_primary_ip

logger = logging.getLogger(__name__)


async def dispatch_wg_init(server: TunnelServer, db: AsyncSession) -> tuple[bool, str]:
    """Send wg_init to the server agent so it (re)builds the WireGuard interface.

    Skips dispatch when no primary IP is known yet: the agent validates
    `public_ip` as an IPv4 and would reject an empty string. The heartbeat
    handler re-dispatches once an IP lands in `tunnel_server_ips`.
    """
    primary = await get_primary_ip(server.id, db)
    if not primary:
        logger.warning(
            "Skipping wg_init for server %s: no primary IP yet — will retry once heartbeat reports one",
            server.id,
        )
        return False, ""
    sent, cmd_id = await send_command(
        agent_id=str(server.agent_id),
        command_type="wg_init",
        params={
            "wg_interface": server.wg_interface,
            "wg_port": server.wg_port,
            "tunnel_network": server.tunnel_network,
            "tunnel_ip": server_tunnel_ip(server.tunnel_network),
            "public_iface": server.public_iface,
            "public_ip": primary,
        },
        db=db,
    )
    if sent:
        logger.info("Sent wg_init to server agent %s (cmd=%s)", server.agent_id, cmd_id)
    else:
        logger.warning("Server agent %s not connected — wg_init queued (cmd=%s)", server.agent_id, cmd_id)

    # wg_init rebuilds wg0 from scratch on the agent, wiping any existing
    # peers. Re-fire wg_add_peer for every attachment that has reported a
    # public key so the peer list converges back. Commands queue FIFO per
    # agent so the adds run after wg_init.
    attachments = (await db.scalars(
        select(TunnelClientAttachment).where(
            TunnelClientAttachment.tunnel_server_id == server.id,
            TunnelClientAttachment.wg_public_key.isnot(None),
        )
    )).all()
    for att in attachments:
        await dispatch_add_peer_for_attachment(att, db)

    return sent, cmd_id


async def _load_attachment_context(
    attachment_id: uuid.UUID, db: AsyncSession
) -> tuple[TunnelClientAttachment, TunnelClient, TunnelServer]:
    att = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == attachment_id)
    )
    if att is None:
        raise ValueError(f"attachment {attachment_id} not found")
    client = await db.scalar(select(TunnelClient).where(TunnelClient.id == att.tunnel_client_id))
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == att.tunnel_server_id))
    if client is None or server is None:
        raise ValueError(f"attachment {attachment_id} has dangling client or server")
    return att, client, server


async def dispatch_wg_attach(
    attachment: TunnelClientAttachment, db: AsyncSession
) -> tuple[bool, str]:
    """Provision one attachment on the client agent: bring up wgN, install
    per-attachment routing rules, return the agent's public key (which the
    WS result handler stores on the attachment row and uses to fire
    wg_add_peer at the matching server agent).
    """
    client = await db.scalar(
        select(TunnelClient).where(TunnelClient.id == attachment.tunnel_client_id)
    )
    server = await db.scalar(
        select(TunnelServer).where(TunnelServer.id == attachment.tunnel_server_id)
    )
    if client is None or server is None:
        raise ValueError(f"attachment {attachment.id} has dangling client or server")

    primary_ip = await get_primary_ip(server.id, db)
    server_endpoint = f"{primary_ip}:{server.wg_port}" if primary_ip else ""

    sent, cmd_id = await send_command(
        agent_id=str(client.agent_id),
        command_type="wg_attach",
        params={
            "attachment_id": str(attachment.id),
            "wg_interface": attachment.wg_interface,
            "tunnel_ip": attachment.tunnel_ip,
            "fwmark": attachment.fwmark,
            "route_table_id": attachment.route_table_id,
            "server_endpoint": server_endpoint,
            "server_public_key": server.wg_public_key or "",
            "server_tunnel_network": server.tunnel_network,
            "vps_tunnel_ip": server_tunnel_ip(server.tunnel_network),
            "lan_iface": "eth0",
            "lan_network": client.vm_network or "",
            "lan_ip": client.lan_ip or "",
            "is_gateway": client.is_gateway,
        },
        db=db,
    )
    if sent:
        logger.info(
            "Sent wg_attach to client agent %s for attachment %s (cmd=%s)",
            client.agent_id, attachment.id, cmd_id,
        )
    else:
        logger.warning(
            "Client agent %s not connected — wg_attach queued (cmd=%s)",
            client.agent_id, cmd_id,
        )
    return sent, cmd_id


async def dispatch_wg_detach(
    attachment: TunnelClientAttachment, db: AsyncSession
) -> tuple[bool, str]:
    """Tear down one attachment on the client agent."""
    client = await db.scalar(
        select(TunnelClient).where(TunnelClient.id == attachment.tunnel_client_id)
    )
    if client is None:
        raise ValueError(f"attachment {attachment.id} has dangling client")

    sent, cmd_id = await send_command(
        agent_id=str(client.agent_id),
        command_type="wg_detach",
        params={
            "attachment_id": str(attachment.id),
            "wg_interface": attachment.wg_interface,
            "fwmark": attachment.fwmark,
            "route_table_id": attachment.route_table_id,
            "lan_iface": "eth0",
        },
        db=db,
    )
    if sent:
        logger.info(
            "Sent wg_detach to client agent %s for attachment %s (cmd=%s)",
            client.agent_id, attachment.id, cmd_id,
        )
    else:
        logger.warning(
            "Client agent %s not connected — wg_detach queued (cmd=%s)",
            client.agent_id, cmd_id,
        )
    return sent, cmd_id


async def dispatch_add_peer_for_attachment(
    attachment: TunnelClientAttachment, db: AsyncSession
) -> tuple[bool, str] | None:
    """Tell the tunnel-server agent to add this attachment as a peer. Skips
    silently if the attachment hasn't reported its public key yet.
    """
    if not attachment.wg_public_key:
        return None
    server = await db.scalar(
        select(TunnelServer).where(TunnelServer.id == attachment.tunnel_server_id)
    )
    client = await db.scalar(
        select(TunnelClient).where(TunnelClient.id == attachment.tunnel_client_id)
    )
    if server is None or client is None:
        return None
    allowed_ips = [attachment.tunnel_ip + "/32"]
    if client.is_gateway and client.vm_network:
        allowed_ips.append(client.vm_network)
    sent, cmd_id = await send_command(
        agent_id=str(server.agent_id),
        command_type="wg_add_peer",
        params={
            "peer_name": f"client-{attachment.tunnel_ip}",
            "public_key": attachment.wg_public_key,
            "tunnel_ip": attachment.tunnel_ip,
            "allowed_ips": allowed_ips,
        },
        db=db,
    )
    if sent:
        logger.info(
            "Sent wg_add_peer to server agent %s for attachment %s (cmd=%s)",
            server.agent_id, attachment.id, cmd_id,
        )
    else:
        logger.warning(
            "Server agent %s not connected — wg_add_peer for attachment %s queued",
            server.agent_id, attachment.id,
        )
    return sent, cmd_id


async def dispatch_remove_peer_for_attachment(
    attachment: TunnelClientAttachment, db: AsyncSession
) -> tuple[bool, str] | None:
    """Tell the tunnel-server agent to remove this attachment's peer."""
    if not attachment.wg_public_key:
        return None
    server = await db.scalar(
        select(TunnelServer).where(TunnelServer.id == attachment.tunnel_server_id)
    )
    if server is None:
        return None
    sent, cmd_id = await send_command(
        agent_id=str(server.agent_id),
        command_type="wg_remove_peer",
        params={
            "public_key": attachment.wg_public_key,
        },
        db=db,
    )
    return sent, cmd_id


async def dispatch_set_lan_snat(
    server: TunnelServer,
    lan_ip: str,
    public_ip: str | None,
    db: AsyncSession,
) -> tuple[bool, str]:
    """Tell the tunnel-server agent to install (or clear) a per-LAN-host
    SNAT rule on its public interface. public_ip=None clears any rule
    matching `-s <lan_ip>` in nat POSTROUTING.
    """
    sent, cmd_id = await send_command(
        agent_id=str(server.agent_id),
        command_type="set_lan_snat",
        params={
            "lan_ip": lan_ip,
            "public_ip": public_ip or "",
            "action": "set" if public_ip else "clear",
        },
        db=db,
    )
    if sent:
        if public_ip:
            logger.info(
                "Sent set_lan_snat to server agent %s: %s -> %s (cmd=%s)",
                server.agent_id, lan_ip, public_ip, cmd_id,
            )
        else:
            logger.info(
                "Sent set_lan_snat to server agent %s: %s -> clear (cmd=%s)",
                server.agent_id, lan_ip, cmd_id,
            )
    else:
        logger.warning(
            "Server agent %s not connected — set_lan_snat for %s queued (cmd=%s)",
            server.agent_id, lan_ip, cmd_id,
        )
    return sent, cmd_id


async def dispatch_set_lan_egress(
    client: TunnelClient,
    lan_ip: str,
    attachment: TunnelClientAttachment | None,
    db: AsyncSession,
) -> tuple[bool, str]:
    """Tell the gateway agent to install (or clear) an egress-pin ip rule
    for one LAN host. attachment=None clears the pin.
    """
    params: dict = {"lan_ip": lan_ip}
    if attachment is not None:
        params["route_table_id"] = attachment.route_table_id
        params["wg_interface"] = attachment.wg_interface
    else:
        params["route_table_id"] = 0  # 0 = clear
    sent, cmd_id = await send_command(
        agent_id=str(client.agent_id),
        command_type="set_lan_egress",
        params=params,
        db=db,
    )
    if sent:
        if attachment is not None:
            logger.info(
                "Sent set_lan_egress to gateway agent %s: %s -> %s (cmd=%s)",
                client.agent_id, lan_ip, attachment.wg_interface, cmd_id,
            )
        else:
            logger.info(
                "Sent set_lan_egress to gateway agent %s: %s -> clear (cmd=%s)",
                client.agent_id, lan_ip, cmd_id,
            )
    else:
        logger.warning(
            "Gateway agent %s not connected — set_lan_egress for %s queued (cmd=%s)",
            client.agent_id, lan_ip, cmd_id,
        )
    return sent, cmd_id

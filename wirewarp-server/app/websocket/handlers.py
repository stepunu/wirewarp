import logging
import re
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.models.metric import Metric
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_client import TunnelClient
from app.services.agent_commands import send_command

logger = logging.getLogger(__name__)


async def handle_heartbeat(agent_id: str, msg: dict, db: AsyncSession) -> None:
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        return

    agent.last_seen = datetime.now(timezone.utc)

    if version := msg.get("version"):
        agent.version = version

    public_ip = msg.get("public_ip")
    if public_ip and public_ip != agent.public_ip:
        agent.public_ip = public_ip
        # For server agents, also propagate to tunnel_server.public_ip so the
        # WireGuard endpoint is always current without manual configuration.
        if agent.type == "server":
            srv_result = await db.execute(
                select(TunnelServer).where(TunnelServer.agent_id == agent_id)
            )
            server = srv_result.scalar_one_or_none()
            if server and server.public_ip != public_ip:
                server.public_ip = public_ip
                logger.info("Auto-updated tunnel server public IP to %s for agent %s", public_ip, agent_id)

    await db.commit()


async def handle_command_result(agent_id: str, msg: dict, db: AsyncSession) -> None:
    """Update the command_log entry, extract public keys, and trigger follow-up commands."""
    command_id = msg.get("command_id")
    success = msg.get("success", False)
    output = msg.get("output", "")

    command_type = None
    if command_id:
        result = await db.execute(select(CommandLog).where(CommandLog.id == command_id))
        log = result.scalar_one_or_none()
        if log:
            log.success = success
            log.output = output
            command_type = log.command_type
            await db.commit()

    # Always update last_seen
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)
        await db.commit()

    if not success:
        return

    # Extract and store public keys from wg_init / wg_configure results
    public_key = _extract_public_key(output)

    if command_type == "wg_init" and public_key:
        result = await db.execute(
            select(TunnelServer).where(TunnelServer.agent_id == agent_id)
        )
        server = result.scalar_one_or_none()
        if server:
            server.wg_public_key = public_key
            await db.commit()
            logger.info("Stored server public key for agent %s", agent_id)

    elif command_type == "wg_configure" and public_key:
        result = await db.execute(
            select(TunnelClient).where(TunnelClient.agent_id == agent_id)
        )
        client = result.scalar_one_or_none()
        if client:
            client.wg_public_key = public_key
            client.status = "connected"
            await db.commit()
            logger.info("Stored client public key for agent %s", agent_id)

            # Now that we have the client's public key, add it as a peer on the server
            if client.tunnel_server_id:
                await _add_peer_to_server(client, db)


async def _add_peer_to_server(client: TunnelClient, db: AsyncSession) -> None:
    """Send wg_add_peer to the tunnel server agent with the client's public key."""
    result = await db.execute(
        select(TunnelServer).where(TunnelServer.id == client.tunnel_server_id)
    )
    server = result.scalar_one_or_none()
    if not server:
        return

    allowed_ips = [client.tunnel_ip + "/32"]
    if client.is_gateway and client.vm_network:
        allowed_ips.append(client.vm_network)

    sent, cmd_id = await send_command(
        agent_id=str(server.agent_id),
        command_type="wg_add_peer",
        params={
            "peer_name": f"client-{client.tunnel_ip}",
            "public_key": client.wg_public_key,
            "tunnel_ip": client.tunnel_ip,
            "allowed_ips": allowed_ips,
        },
        db=db,
    )
    if sent:
        logger.info("Sent wg_add_peer to server agent %s for client %s (cmd=%s)",
                     server.agent_id, client.tunnel_ip, cmd_id)
    else:
        logger.warning("Server agent %s not connected — wg_add_peer not delivered", server.agent_id)


def _extract_public_key(output: str) -> str | None:
    """Extract a WireGuard public key from command output like 'public key: abc123...'"""
    match = re.search(r"public key:\s*(\S+)", output, re.IGNORECASE)
    return match.group(1) if match else None


async def handle_metrics(agent_id: str, msg: dict, db: AsyncSession) -> None:
    timestamp_raw = msg.get("timestamp")
    try:
        timestamp = datetime.fromisoformat(timestamp_raw) if timestamp_raw else datetime.now(timezone.utc)
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    metric = Metric(
        agent_id=agent_id,
        timestamp=timestamp,
        data={k: v for k, v in msg.items() if k not in ("type", "timestamp")},
    )
    db.add(metric)

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)

    await db.commit()


async def dispatch(agent_id: str, msg: dict, db: AsyncSession) -> None:
    msg_type = msg.get("type")
    if msg_type == "heartbeat":
        await handle_heartbeat(agent_id, msg, db)
    elif msg_type == "command_result":
        await handle_command_result(agent_id, msg, db)
    elif msg_type == "metrics":
        await handle_metrics(agent_id, msg, db)
    # Unknown message types are silently ignored

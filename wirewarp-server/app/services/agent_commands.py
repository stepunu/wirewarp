import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.command_log import CommandLog
from app.websocket.hub import manager


VALID_COMMAND_TYPES = {
    "wg_init",
    "wg_attach",
    "wg_detach",
    "wg_add_peer",
    "wg_remove_peer",
    "wg_update_endpoint",
    "iptables_add_forward",
    "iptables_remove_forward",
    "set_lan_egress",
    "set_lan_snat",
    "gateway_up",
    "gateway_down",
    "agent_update",
    "vpn_endpoint_up",
    "vpn_endpoint_down",
    "vpn_peer_add",
    "vpn_peer_remove",
    "vpn_peer_update_rules",
    "crowdsec_install",
    "crowdsec_sync_whitelist",
    "traefik_install",
    "traefik_sync_config",
    "crowdsec_appsec_enable",
    "edge_desired_state",
}


async def send_command(
    agent_id: str,
    command_type: str,
    params: dict[str, Any],
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[bool, str]:
    """
    Build a command message, log it, and send it to the agent.

    `actor_user_id` is the user who triggered the command via HTTP. WS
    handlers (replays, agent-initiated flows) pass None.

    Returns (sent: bool, command_id: str).
    sent=False means the agent is not currently connected.
    """
    if command_type not in VALID_COMMAND_TYPES:
        raise ValueError(f"Unknown command type: {command_type}")

    command_uuid = uuid.uuid4()
    command_id = str(command_uuid)
    message = {
        "id": command_id,
        "type": command_type,
        "params": params,
    }

    try:
        agent_uuid = uuid.UUID(agent_id) if isinstance(agent_id, str) else agent_id
    except (TypeError, ValueError):
        agent_uuid = None

    # Log before sending — success/output filled in when command_result arrives
    log = CommandLog(
        id=command_uuid,
        agent_id=agent_uuid,
        actor_user_id=actor_user_id,
        command_type=command_type,
        params=params,
        success=None,
        output=None,
    )
    db.add(log)
    await db.commit()

    sent = await manager.send(agent_id, message)
    return sent, command_id

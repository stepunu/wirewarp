import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.command_log import CommandLog
from app.websocket.hub import manager


VALID_COMMAND_TYPES = {
    "wg_init",
    "wg_configure",
    "wg_add_peer",
    "wg_remove_peer",
    "wg_update_endpoint",
    "wg_down",
    "iptables_add_forward",
    "iptables_remove_forward",
    "gateway_up",
    "gateway_down",
    "agent_update",
}


async def send_command(
    agent_id: str,
    command_type: str,
    params: dict[str, Any],
    db: AsyncSession,
) -> tuple[bool, str]:
    """
    Build a command message, log it, and send it to the agent.

    Returns (sent: bool, command_id: str).
    sent=False means the agent is not currently connected.
    """
    if command_type not in VALID_COMMAND_TYPES:
        raise ValueError(f"Unknown command type: {command_type}")

    command_id = str(uuid.uuid4())
    message = {
        "id": command_id,
        "type": command_type,
        "params": params,
    }

    # Log before sending — success/output filled in when command_result arrives
    log = CommandLog(
        id=command_id,
        agent_id=agent_id,
        command_type=command_type,
        params=params,
        success=None,
        output=None,
    )
    db.add(log)
    await db.commit()

    sent = await manager.send(agent_id, message)
    return sent, command_id

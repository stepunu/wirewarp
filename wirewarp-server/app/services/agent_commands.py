import asyncio
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import select
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
    "reconcile_lan_snat",
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
    "edge_disable",
    "edge_cache_purge",
    "edge_cache_test",
    "edge_route_test",
    "acme_dns_test",
    "edge_node_role",
    "site_link_desired_state",
    "site_link_test",
    "site_link_teardown",
}


class CommandResultState(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    DISCONNECTED = "disconnected"
    MISSING = "missing"


async def wait_for_command_result(
    command_id: str,
    agent_id: str,
    db: AsyncSession,
    *,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.05,
) -> CommandResultState:
    """Wait for one agent-owned CommandLog result without blocking the loop.

    The caller must invoke this only after `send_command` commits the log.
    End each read transaction so results committed by the WebSocket handler
    become visible on PostgreSQL and SQLite.
    """
    try:
        command_uuid = uuid.UUID(command_id)
        agent_uuid = uuid.UUID(agent_id)
    except (TypeError, ValueError):
        return CommandResultState.MISSING

    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(timeout_seconds, 0.0)
    while True:
        await db.commit()
        log = await db.scalar(
            select(CommandLog)
            .where(
                CommandLog.id == command_uuid,
                CommandLog.agent_id == agent_uuid,
            )
            .execution_options(populate_existing=True)
        )
        if log is None:
            return CommandResultState.MISSING
        if log.success is True:
            return CommandResultState.SUCCESS
        if log.success is False:
            return CommandResultState.FAILURE
        if not manager.is_connected(agent_id):
            return CommandResultState.DISCONNECTED

        remaining = deadline - loop.time()
        if remaining <= 0:
            return CommandResultState.TIMEOUT
        await asyncio.sleep(min(poll_interval_seconds, remaining))


async def send_command(
    agent_id: str,
    command_type: str,
    params: dict[str, Any],
    db: AsyncSession,
    actor_user_id: uuid.UUID | None = None,
    log_params: dict[str, Any] | None = None,
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

    try:
        agent_uuid = uuid.UUID(agent_id) if isinstance(agent_id, str) else agent_id
    except (TypeError, ValueError):
        agent_uuid = None
    if command_type in {"wg_init", "wg_attach", "wg_detach", "wg_add_peer", "wg_remove_peer", "wg_update_endpoint", "gateway_up", "gateway_down", "edge_node_role", "vpn_endpoint_up", "vpn_endpoint_down"} and agent_uuid is not None:
        from app.services.site_link_ops import lock_site_links, ensure_no_site_link_teardown
        from app.models.tunnel_client_attachment import TunnelClientAttachment
        from app.models.tunnel_server import TunnelServer
        scope = {agent_uuid}
        if command_type in {"wg_attach", "wg_detach", "wg_update_endpoint"} and params.get("attachment_id"):
            try:
                attachment_id = uuid.UUID(str(params["attachment_id"]))
            except (ValueError, TypeError):
                attachment_id = None
            related_hub = await db.scalar(select(TunnelServer.agent_id).join(TunnelClientAttachment, TunnelClientAttachment.tunnel_server_id == TunnelServer.id).where(TunnelClientAttachment.id == attachment_id)) if attachment_id else None
            if related_hub:
                scope.add(related_hub)
        await lock_site_links(db)
        await ensure_no_site_link_teardown(db, agent_ids=scope)
    if command_type == "wg_add_peer" and agent_uuid is not None:
        from app.models.site_link import SiteLinkAgentState
        from app.models.tunnel_client import TunnelClient
        from app.models.tunnel_client_attachment import TunnelClientAttachment
        from app.models.tunnel_server import TunnelServer
        if await db.get(SiteLinkAgentState, agent_uuid) is not None:
            gateway_peer = await db.scalar(select(TunnelClientAttachment.id).join(
                TunnelClient, TunnelClient.id == TunnelClientAttachment.tunnel_client_id,
            ).join(TunnelServer, TunnelServer.id == TunnelClientAttachment.tunnel_server_id).where(
                TunnelServer.agent_id == agent_uuid, TunnelClient.is_gateway.is_(True),
                TunnelClientAttachment.wg_public_key == params.get("public_key"),
            ).limit(1))
            if gateway_peer is not None:
                params = dict(params, site_link_guard_required=True)

    command_uuid = uuid.uuid4()
    command_id = str(command_uuid)
    message = {
        "id": command_id,
        "type": command_type,
        "params": params,
    }

    # Log before sending — success/output filled in when command_result arrives
    log = CommandLog(
        id=command_uuid,
        agent_id=agent_uuid,
        actor_user_id=actor_user_id,
        command_type=command_type,
        params=log_params if log_params is not None else params,
        success=None,
        output=None,
        executed_at=datetime.now(timezone.utc),
    )
    db.add(log)
    await db.commit()

    sent = await manager.send(agent_id, message)
    return sent, command_id

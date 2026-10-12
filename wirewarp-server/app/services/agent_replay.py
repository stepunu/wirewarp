"""Replay current runtime state without interrupting a pending Site Links teardown."""
import logging

from fastapi import HTTPException
from sqlalchemy import or_, select

from app.models.site_link import SiteLinkAgentState
from app.services.agent_commands import send_command
from app.services.site_link_ops import TEARDOWN_PHASES, dispatch_site_links_for_agent

logger = logging.getLogger(__name__)


async def site_link_teardown_pending(agent_id, db):
    from app.models.tunnel_client import TunnelClient
    from app.models.tunnel_client_attachment import TunnelClientAttachment
    from app.models.tunnel_server import TunnelServer

    related_hubs = select(TunnelServer.agent_id).join(
        TunnelClientAttachment, TunnelClientAttachment.tunnel_server_id == TunnelServer.id,
    ).join(TunnelClient, TunnelClient.id == TunnelClientAttachment.tunnel_client_id).where(
        TunnelClient.agent_id == agent_id,
    )
    return await db.scalar(select(SiteLinkAgentState.agent_id).where(
        SiteLinkAgentState.phase.in_(TEARDOWN_PHASES),
        or_(SiteLinkAgentState.agent_id == agent_id, SiteLinkAgentState.agent_id.in_(related_hubs)),
    ).limit(1)) is not None


async def _replay_teardown(agent_id, db):
    phase = await db.scalar(select(SiteLinkAgentState.phase).where(SiteLinkAgentState.agent_id == agent_id))
    if phase in TEARDOWN_PHASES:
        await dispatch_site_links_for_agent(agent_id, db)


async def replay_agent_runtime(agent_id, db):
    if await site_link_teardown_pending(agent_id, db):
        await _replay_teardown(agent_id, db)
        return False
    try:
        return await _replay_normal_runtime(agent_id, db)
    except HTTPException as exc:
        if exc.status_code != 409 or not await site_link_teardown_pending(agent_id, db):
            raise
        await db.rollback()
        await _replay_teardown(agent_id, db)
        return False


async def _replay_normal_runtime(agent_id, db):
    from app.models.tunnel_server import TunnelServer
    from app.models.tunnel_client import TunnelClient
    from app.models.tunnel_client_attachment import TunnelClientAttachment
    from app.models.gateway_lan_client import GatewayLanClient
    from app.models.port_forward import PortForward
    result = await db.execute(
        select(TunnelServer).where(TunnelServer.agent_id == agent_id)
    )
    server = result.scalar_one_or_none()
    if server:
        from app.models.tunnel_server_ip import TunnelServerIP
        from app.services.primary_ip import get_primary_ip
        from app.services.port_forward_ops import dispatch_raw_forward
        from app.services.tunnel_server_ops import (
            dispatch_reconcile_lan_snat,
            dispatch_wg_init,
        )

        # Rebuild the server interface on every auth reconnect. This
        # must precede forward and peer replay because wg_init replaces
        # the live WireGuard configuration.
        await dispatch_wg_init(server, db, replay_peers=False)
        await dispatch_reconcile_lan_snat(server, db)

        # All attachments peering with this server.
        att_rows = (
            await db.execute(
                select(TunnelClientAttachment).where(
                    TunnelClientAttachment.tunnel_server_id == server.id
                )
            )
        ).scalars().all()
        attachment_ids = [att.id for att in att_rows]

        if attachment_ids:
            pf_result = await db.execute(
                select(PortForward).where(
                    PortForward.attachment_id.in_(attachment_ids),
                    PortForward.service_kind == "raw",
                    PortForward.active == True,  # noqa: E712
                )
            )
            active_forwards = pf_result.scalars().all()
        else:
            active_forwards = []

        ip_rows = await db.execute(
            select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id)
        )
        ip_map = {ip.id: ip.address for ip in ip_rows.scalars().all()}
        primary_ip = await get_primary_ip(server.id, db)

        for pf in active_forwards:
            public_ip = ip_map.get(pf.tunnel_server_ip_id) if pf.tunnel_server_ip_id else None
            if not public_ip:
                public_ip = primary_ip or ""
            await dispatch_raw_forward(
                pf,
                "iptables_add_forward",
                db,
                public_ip_override=public_ip,
            )
        logger.info(
            "Replayed %d active port forward(s) to server agent %s",
            len(active_forwards), agent_id,
        )

        # Replay wg_add_peer for every attachment that already has a
        # public key (i.e. wg_attach has completed at some point).
        await dispatch_site_links_for_agent(agent_id, db)
        replayed_peers = 0
        for att in att_rows:
            if not att.wg_public_key or not att.tunnel_ip:
                continue
            client = await db.scalar(
                select(TunnelClient).where(TunnelClient.id == att.tunnel_client_id)
            )
            if client is None:
                continue
            allowed_ips = [att.tunnel_ip + "/32"]
            if client.is_gateway and client.vm_network:
                allowed_ips.append(client.vm_network)
            await send_command(
                agent_id=agent_id,
                command_type="wg_add_peer",
                params={
                    "peer_name": f"client-{att.tunnel_ip}",
                    "public_key": att.wg_public_key,
                    "tunnel_ip": att.tunnel_ip,
                    "allowed_ips": allowed_ips,
                },
                db=db,
            )
            replayed_peers += 1
        logger.info(
            "Replayed %d peer(s) to server agent %s",
            replayed_peers, agent_id,
        )

        from app.services.edge_ops import replay_edge_lifecycle

        await replay_edge_lifecycle(agent_id, db)

    # Client-side replay: on (re)connect, dispatch wg_attach for every
    # attachment of this client. Overwrites stale on-disk values from
    # the legacy `client:` → `attachments:` migration (which copied
    # pre-rebase tunnel IPs verbatim) and reconciles any attachments
    # added while the agent was offline. The agent's handleWGAttach
    # is idempotent (flushes + re-applies routing).
    client_row = await db.scalar(
        select(TunnelClient).where(TunnelClient.agent_id == agent_id)
    )
    if client_row is not None:
        await send_command(
            agent_id=agent_id, command_type="edge_node_role",
            params={"is_gateway": bool(client_row.is_gateway), "lan_ip": client_row.lan_ip, "lan_network": client_row.vm_network}, db=db,
        )
        from app.services.tunnel_server_ops import (
            dispatch_set_lan_egress,
            dispatch_wg_attach,
        )
        client_atts = (
            await db.execute(
                select(TunnelClientAttachment).where(
                    TunnelClientAttachment.tunnel_client_id == client_row.id
                )
            )
        ).scalars().all()
        for att in client_atts:
            await dispatch_wg_attach(att, db)
        if client_atts:
            logger.info(
                "Replayed %d wg_attach(es) to client agent %s",
                len(client_atts), agent_id,
            )

        attachment_map = {att.id: att for att in client_atts}
        lan_clients = (
            await db.execute(
                select(GatewayLanClient).where(
                    GatewayLanClient.tunnel_client_id == client_row.id
                )
            )
        ).scalars().all()
        for lan_client in lan_clients:
            attachment = (
                attachment_map.get(lan_client.egress_attachment_id)
                if client_row.is_gateway
                else None
            )
            await dispatch_set_lan_egress(
                client_row,
                lan_client.lan_ip,
                attachment,
                db,
            )
        if lan_clients:
            logger.info(
                "Replayed %d LAN egress desired state row(s) to client agent %s",
                len(lan_clients),
                agent_id,
            )

        # VPN endpoint replay: gateway clients may host a wg-vpn0
        # interface for road warriors. Reissue endpoint_up + a
        # peer_add per profile so the gateway's iptables rules and
        # peer list match the DB after a restart.
        from app.models.vpn_endpoint import VpnEndpoint
        from app.models.vpn_profile import VpnProfile
        from app.services.vpn_ops import (
            dispatch_vpn_endpoint_up,
            dispatch_vpn_peer_add,
            load_user_endpoint_permissions,
        )

        vpn_endpoint = (
            await db.scalar(
                select(VpnEndpoint).where(
                    VpnEndpoint.tunnel_client_id == client_row.id,
                    VpnEndpoint.enabled == True,  # noqa: E712
                )
            )
            if client_row.is_gateway
            else None
        )
        if vpn_endpoint is not None:
            await dispatch_vpn_endpoint_up(vpn_endpoint, db)
            profiles = (
                await db.execute(
                    select(VpnProfile).where(
                        VpnProfile.vpn_endpoint_id == vpn_endpoint.id
                    )
                )
            ).scalars().all()
            for profile in profiles:
                perms = await load_user_endpoint_permissions(
                    profile.user_id, vpn_endpoint.id, db
                )
                await dispatch_vpn_peer_add(
                    profile=profile,
                    endpoint=vpn_endpoint,
                    permissions=perms,
                    db=db,
                )
            if profiles:
                logger.info(
                    "Replayed VPN endpoint + %d peer(s) to gateway agent %s",
                    len(profiles), agent_id,
                )

        if client_row.is_gateway:
            from app.services.edge_ops import replay_edge_lifecycle
            await replay_edge_lifecycle(agent_id, db)

        await dispatch_site_links_for_agent(agent_id, db)
    return True

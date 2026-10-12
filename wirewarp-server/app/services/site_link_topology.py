"""Keep accepted links intact while tunnel topology changes."""
import uuid
import ipaddress

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.models.site_link import SiteLink, SiteLinkAgentState
from app.models.tunnel_client_attachment import TunnelClientAttachment


async def validate_managed_hub_peer(db: AsyncSession, server, client, tunnel_ip: str, *, exclude_attachment_id: uuid.UUID | None = None) -> None:
    """WireGuard must own each advertised source network through one peer."""
    from app.models.tunnel_client import TunnelClient
    from app.services.site_link_ops import lock_site_links, ensure_no_site_link_teardown
    await lock_site_links(db)
    await ensure_no_site_link_teardown(db, agent_ids={server.agent_id, client.agent_id})
    if await db.get(SiteLinkAgentState, server.agent_id) is None:
        return
    advertised = [ipaddress.IPv4Network(tunnel_ip + "/32")]
    if client.is_gateway and client.vm_network:
        advertised.append(ipaddress.IPv4Network(client.vm_network))
    peers = (await db.execute(select(TunnelClientAttachment, TunnelClient).join(TunnelClient, TunnelClient.id == TunnelClientAttachment.tunnel_client_id).where(TunnelClientAttachment.tunnel_server_id == server.id))).all()
    for attachment, peer in peers:
        if attachment.id == exclude_attachment_id:
            continue
        networks = [ipaddress.IPv4Network(attachment.tunnel_ip + "/32")]
        if peer.is_gateway and peer.vm_network:
            networks.append(ipaddress.IPv4Network(peer.vm_network))
        if any(a.overlaps(b) for a in advertised for b in networks):
            raise HTTPException(409, "The managed hub already has a peer that owns an overlapping network")
    if client.is_gateway and client.vm_network and ipaddress.IPv4Network(client.vm_network).overlaps(ipaddress.IPv4Network(server.tunnel_network)):
        raise HTTPException(409, "The advertised LAN overlaps the managed hub tunnel network")


async def require_unlinked_agent(db: AsyncSession, agent_id: uuid.UUID) -> None:
    from app.services.site_link_ops import lock_site_links, ensure_no_site_link_teardown
    await lock_site_links(db)
    await ensure_no_site_link_teardown(db, agent_ids={agent_id})
    if await db.get(SiteLinkAgentState, agent_id):
        raise HTTPException(409, "This node retains Site Links ownership. Finish managed teardown before changing its network or role")
    query = select(SiteLink.id).where(
        (SiteLink.site_a_gateway_id == agent_id) | (SiteLink.site_b_gateway_id == agent_id) | (SiteLink.hub_agent_id == agent_id),
    )
    if await db.scalar(query.limit(1)):
        raise HTTPException(409, "Remove this node's Site Links before changing its network or gateway role")


async def require_unlinked_client_hubs(db: AsyncSession, client_id: uuid.UUID) -> None:
    from app.models.tunnel_server import TunnelServer
    from app.services.site_link_ops import lock_site_links, ensure_no_site_link_teardown
    await lock_site_links(db)
    hubs = select(TunnelServer.agent_id).join(TunnelClientAttachment, TunnelClientAttachment.tunnel_server_id == TunnelServer.id).where(TunnelClientAttachment.tunnel_client_id == client_id)
    await ensure_no_site_link_teardown(db, agent_ids=set((await db.scalars(hubs)).all()))
    if await db.scalar(select(SiteLinkAgentState.agent_id).where(SiteLinkAgentState.agent_id.in_(hubs)).limit(1)):
        raise HTTPException(409, "Remove Site Links on this client's hubs before changing its advertised LAN or gateway role")


async def require_unpublished_attachment(db: AsyncSession, attachment_id: uuid.UUID) -> None:
    from app.models.tunnel_client import TunnelClient
    from app.models.tunnel_server import TunnelServer
    from app.services.site_link_ops import lock_site_links, ensure_no_site_link_teardown
    await lock_site_links(db)
    owners = (await db.execute(select(TunnelClient.agent_id, TunnelServer.agent_id).join(TunnelClientAttachment, TunnelClientAttachment.tunnel_client_id == TunnelClient.id).join(TunnelServer, TunnelServer.id == TunnelClientAttachment.tunnel_server_id).where(TunnelClientAttachment.id == attachment_id))).first()
    await ensure_no_site_link_teardown(db, agent_ids=set(owners) if owners else set())
    link = await db.scalar(select(SiteLink.id).where((SiteLink.site_a_attachment_id == attachment_id) | (SiteLink.site_b_attachment_id == attachment_id)).limit(1))
    publication = await db.scalar(select(HTTPPublicIngress.route_id).join(HTTPRoute, HTTPRoute.id == HTTPPublicIngress.route_id).join(TunnelClient, TunnelClient.agent_id == HTTPRoute.agent_id).where(HTTPPublicIngress.attachment_id == attachment_id, TunnelClient.is_gateway.is_(True)).limit(1))
    if link or publication:
        raise HTTPException(409, "Remove this attachment's Site Links and HTTP publications before changing its tunnel address")


async def require_unpublished_server(db: AsyncSession, server_id: uuid.UUID) -> None:
    from app.models.tunnel_server import TunnelServer
    from app.services.site_link_ops import lock_site_links, ensure_no_site_link_teardown
    await lock_site_links(db)
    agent_id = await db.scalar(select(TunnelServer.agent_id).where(TunnelServer.id == server_id))
    await ensure_no_site_link_teardown(db, agent_ids={agent_id} if agent_id else set())
    attachments = (await db.scalars(select(TunnelClientAttachment.id).where(TunnelClientAttachment.tunnel_server_id == server_id))).all()
    for attachment_id in attachments:
        await require_unpublished_attachment(db, attachment_id)


async def refresh_site_link_topology(db: AsyncSession) -> None:
    from app.services.site_link_ops import lock_site_links, prepare_snapshots, send_snapshots, TEARDOWN_PHASES
    await lock_site_links(db)
    if await db.scalar(select(SiteLinkAgentState.agent_id).where(SiteLinkAgentState.phase.in_(TEARDOWN_PHASES)).limit(1)):
        return
    managed = set((await db.scalars(select(SiteLinkAgentState.agent_id))).all())
    if managed:
        await send_snapshots(await prepare_snapshots(managed, db), db)

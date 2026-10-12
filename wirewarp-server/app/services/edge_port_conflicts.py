from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.http_route import HTTPRoute
from app.models.edge_node import EdgeNode


EDGE_ENTRYPOINT_PORTS = (80, 443)


def uses_edge_entrypoint(protocol: str, public_port: int, public_port_end: int | None = None) -> bool:
    if protocol != "tcp":
        return False
    end = public_port_end or public_port
    return any(public_port <= port <= end for port in EDGE_ENTRYPOINT_PORTS)


async def server_id_for_attachment(
    db: AsyncSession,
    attachment_id: uuid.UUID,
) -> uuid.UUID | None:
    return await db.scalar(
        select(TunnelClientAttachment.tunnel_server_id).where(
            TunnelClientAttachment.id == attachment_id
        )
    )


async def find_active_http_site_on_server(
    db: AsyncSession,
    server_id: uuid.UUID,
    *,
    exclude_port_forward_id: uuid.UUID | None = None,
) -> HTTPRoute | None:
    # Disabled HTTP routes do not reserve ports. Active gateway relays do.
    server = await db.get(TunnelServer, server_id)
    if server:
        from app.services.edge_relay_ops import load_relay_routes
        relays = await load_relay_routes(db, server.agent_id)
        for route, _ in relays:
            if route.id != exclude_port_forward_id:
                return route
    owner_ids = (
        select(TunnelServer.agent_id)
        .join(EdgeNode, EdgeNode.agent_id == TunnelServer.agent_id)
        .where(
            TunnelServer.id == server_id,
            EdgeNode.edge_state == "enabled",
        )
    )
    q = select(HTTPRoute).where(
        HTTPRoute.agent_id.in_(owner_ids),
        HTTPRoute.active.is_(True),
    )
    if exclude_port_forward_id is not None:
        q = q.where(HTTPRoute.id != exclude_port_forward_id)
    return await db.scalar(q.limit(1))


async def find_active_raw_edge_forward_on_server(
    db: AsyncSession,
    server_id: uuid.UUID,
    *,
    exclude_port_forward_id: uuid.UUID | None = None,
) -> PortForward | None:
    attachment_ids = select(TunnelClientAttachment.id).where(
        TunnelClientAttachment.tunnel_server_id == server_id
    )
    q = select(PortForward).where(
        PortForward.attachment_id.in_(attachment_ids),
        PortForward.service_kind == "raw",
        PortForward.protocol == "tcp",
        PortForward.active == True,  # noqa: E712
    )
    if exclude_port_forward_id is not None:
        q = q.where(PortForward.id != exclude_port_forward_id)
    rows = (await db.execute(q)).scalars().all()
    for pf in rows:
        if uses_edge_entrypoint(pf.protocol, pf.public_port, pf.public_port_end):
            return pf
    return None

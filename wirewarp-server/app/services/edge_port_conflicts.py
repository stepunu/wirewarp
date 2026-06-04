from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer


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
) -> PortForward | None:
    # An http edge site only counts as a conflict when edge is actually
    # running on the server. `disable_node_edge` flips
    # tunnel_servers.edge_state to 'disabled' and stops Traefik on the
    # agent, but leaves per-row `active=true` on service_kind='http'
    # forwards — without the edge_state filter, raw 80/443 forwards
    # would be forever blocked by stale-active sites on a node where
    # edge is off.
    attachment_ids = (
        select(TunnelClientAttachment.id)
        .join(TunnelServer, TunnelServer.id == TunnelClientAttachment.tunnel_server_id)
        .where(
            TunnelClientAttachment.tunnel_server_id == server_id,
            TunnelServer.edge_state == "enabled",
        )
    )
    q = select(PortForward).where(
        PortForward.attachment_id.in_(attachment_ids),
        PortForward.service_kind == "http",
        PortForward.active == True,  # noqa: E712
    )
    if exclude_port_forward_id is not None:
        q = q.where(PortForward.id != exclude_port_forward_id)
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

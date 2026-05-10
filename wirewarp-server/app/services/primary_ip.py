import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server_ip import TunnelServerIP


async def get_primary_ip(tunnel_server_id: uuid.UUID, db: AsyncSession) -> str | None:
    """Return the primary public IP address for a tunnel server, or None if none configured."""
    result = await db.execute(
        select(TunnelServerIP.address).where(
            TunnelServerIP.tunnel_server_id == tunnel_server_id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    return result.scalar_one_or_none()


async def resolve_public_ip(pf: PortForward, db: AsyncSession) -> str:
    """Resolve the public IP a port forward should bind to.

    If the forward has an explicit tunnel_server_ip_id, use that row's address.
    Otherwise fall back to the tunnel server's primary IP (resolved via the
    attachment), or empty string if neither is set (the agent will then use
    its locally cached PublicIP).
    """
    if pf.tunnel_server_ip_id is not None:
        result = await db.execute(
            select(TunnelServerIP.address).where(TunnelServerIP.id == pf.tunnel_server_ip_id)
        )
        addr = result.scalar_one_or_none()
        if addr:
            return addr
    server_id = await db.scalar(
        select(TunnelClientAttachment.tunnel_server_id).where(
            TunnelClientAttachment.id == pf.attachment_id
        )
    )
    if server_id is None:
        return ""
    primary = await get_primary_ip(server_id, db)
    return primary or ""

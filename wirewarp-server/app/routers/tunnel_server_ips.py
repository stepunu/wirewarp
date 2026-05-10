import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_role
from app.database import get_db
from app.realtime.events import emit_tunnel_server_changed
from app.models.port_forward import PortForward
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.tunnel_client import TunnelClient
from app.models.user import User
from app.schemas.tunnel_server_ip import (
    TunnelServerIPCreate,
    TunnelServerIPRead,
    TunnelServerIPUpdate,
)
from app.services.agent_commands import send_command
from app.services.primary_ip import get_primary_ip

logger = logging.getLogger(__name__)
router = APIRouter()


async def _serialize(ip: TunnelServerIP, db: AsyncSession) -> TunnelServerIPRead:
    """Build a TunnelServerIPRead with the live port_forward_count."""
    count = await db.scalar(
        select(func.count(PortForward.id)).where(PortForward.tunnel_server_ip_id == ip.id)
    )
    return TunnelServerIPRead(
        id=ip.id,
        tunnel_server_id=ip.tunnel_server_id,
        address=ip.address,
        label=ip.label,
        is_primary=ip.is_primary,
        port_forward_count=int(count or 0),
        created_at=ip.created_at,
    )


async def _broadcast_endpoint_change(server: TunnelServer, db: AsyncSession) -> None:
    """When the primary IP changes, push wg_update_endpoint to dependent client agents."""
    new_primary = await get_primary_ip(server.id, db)
    if not new_primary:
        return
    new_endpoint = f"{new_primary}:{server.wg_port}"
    clients_result = await db.execute(
        select(TunnelClient).where(TunnelClient.tunnel_server_id == server.id)
    )
    for client in clients_result.scalars().all():
        await send_command(
            agent_id=str(client.agent_id),
            command_type="wg_update_endpoint",
            params={"endpoint": new_endpoint},
            db=db,
        )


async def _demote_other_primaries(
    server_id: uuid.UUID, except_ip_id: uuid.UUID | None, db: AsyncSession
) -> None:
    stmt = (
        update(TunnelServerIP)
        .where(TunnelServerIP.tunnel_server_id == server_id, TunnelServerIP.is_primary.is_(True))
        .values(is_primary=False)
    )
    if except_ip_id is not None:
        stmt = stmt.where(TunnelServerIP.id != except_ip_id)
    await db.execute(stmt)


@router.get("", response_model=list[TunnelServerIPRead])
async def list_ips(
    tunnel_server_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = select(TunnelServerIP).order_by(TunnelServerIP.is_primary.desc(), TunnelServerIP.created_at)
    if tunnel_server_id:
        q = q.where(TunnelServerIP.tunnel_server_id == tunnel_server_id)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [await _serialize(ip, db) for ip in rows]


@router.post("", response_model=TunnelServerIPRead, status_code=201)
async def create_ip(
    body: TunnelServerIPCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == body.tunnel_server_id))
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")

    # First IP for a server auto-promotes to primary regardless of the request.
    existing_count = await db.scalar(
        select(func.count(TunnelServerIP.id)).where(
            TunnelServerIP.tunnel_server_id == body.tunnel_server_id
        )
    )
    is_primary = body.is_primary or existing_count == 0

    ip = TunnelServerIP(
        tunnel_server_id=body.tunnel_server_id,
        address=body.address,
        label=body.label,
        is_primary=False,  # write false first to avoid the partial unique index conflict
    )
    db.add(ip)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409, detail=f"Address {body.address} already exists on this tunnel server"
        )

    if is_primary:
        await _demote_other_primaries(body.tunnel_server_id, ip.id, db)
        ip.is_primary = True

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Conflict creating IP — another primary may have been set concurrently")

    await db.refresh(ip)

    if is_primary:
        await _broadcast_endpoint_change(server, db)

    emit_tunnel_server_changed()
    return await _serialize(ip, db)


@router.patch("/{ip_id}", response_model=TunnelServerIPRead)
async def update_ip(
    ip_id: str,
    body: TunnelServerIPUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.id == ip_id))
    if not ip:
        raise HTTPException(status_code=404, detail="IP not found")
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == ip.tunnel_server_id))

    promoting = body.is_primary is True and not ip.is_primary
    demoting = body.is_primary is False and ip.is_primary

    changes = body.model_dump(exclude_unset=True)
    if "is_primary" in changes:
        # Handle primary flips below; don't apply via setattr.
        changes.pop("is_primary")

    for field, value in changes.items():
        setattr(ip, field, value)

    if promoting:
        await _demote_other_primaries(ip.tunnel_server_id, ip.id, db)
        ip.is_primary = True
    elif demoting:
        ip.is_primary = False

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail=str(exc.orig))

    await db.refresh(ip)
    if promoting and server:
        await _broadcast_endpoint_change(server, db)

    emit_tunnel_server_changed()
    return await _serialize(ip, db)


@router.delete("/{ip_id}", status_code=204)
async def delete_ip(
    ip_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.id == ip_id))
    if not ip:
        raise HTTPException(status_code=404, detail="IP not found")

    bound = await db.scalar(
        select(func.count(PortForward.id)).where(PortForward.tunnel_server_ip_id == ip.id)
    )
    if bound and bound > 0:
        raise HTTPException(
            status_code=409,
            detail=f"{bound} port forward(s) bound to this IP — re-bind or delete them first",
        )

    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == ip.tunnel_server_id))
    was_primary = ip.is_primary

    await db.delete(ip)
    await db.commit()

    if was_primary and server:
        # Don't auto-promote — admin chooses. But notify clients if any other primary now exists
        # (none should, immediately after deleting the primary).
        await _broadcast_endpoint_change(server, db)

    emit_tunnel_server_changed()

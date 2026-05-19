import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.heal_event import AgentHealEvent
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.user import User
from app.models.wg_peer_snapshot import WgPeerSnapshot
from app.schemas.tunnel_client import (
    TunnelClientAttachmentHealth,
    TunnelClientRead,
    TunnelClientSummary,
    TunnelClientUpdate,
)
from app.schemas.wg_peer import WgPeerSnapshotRead
from app.auth import require_ops_role, require_role
from app.realtime.events import emit_port_forward_changed, emit_tunnel_client_changed

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("", response_model=list[TunnelClientRead])
async def list_tunnel_clients(db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    result = await db.execute(
        select(TunnelClient)
        .options(selectinload(TunnelClient.attachments))
        .order_by(TunnelClient.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{client_id}", response_model=TunnelClientRead)
async def get_tunnel_client(client_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    result = await db.execute(
        select(TunnelClient)
        .options(selectinload(TunnelClient.attachments))
        .where(TunnelClient.id == client_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    return client


@router.get("/{client_id}/wg-peers", response_model=list[WgPeerSnapshotRead])
async def list_tunnel_client_wg_peers(
    client_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    client = await db.scalar(select(TunnelClient).where(TunnelClient.id == client_id))
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    result = await db.execute(
        select(WgPeerSnapshot)
        .where(WgPeerSnapshot.agent_id == client.agent_id)
        .where(WgPeerSnapshot.kind == "mesh")
        .order_by(WgPeerSnapshot.interface.asc(), WgPeerSnapshot.last_handshake_unix.desc())
    )
    return result.scalars().all()


@router.get("/{client_id}/summary", response_model=TunnelClientSummary)
async def get_tunnel_client_summary(
    client_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func as sa_func

    client = (
        await db.execute(
            select(TunnelClient)
            .options(selectinload(TunnelClient.attachments))
            .where(TunnelClient.id == client_id)
        )
    ).scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")

    agg = (
        await db.execute(
            select(
                sa_func.coalesce(sa_func.sum(WgPeerSnapshot.rx_bytes), 0),
                sa_func.coalesce(sa_func.sum(WgPeerSnapshot.tx_bytes), 0),
            )
            .where(WgPeerSnapshot.agent_id == client.agent_id)
            .where(WgPeerSnapshot.kind == "mesh")
        )
    ).first()
    total_rx, total_tx = (agg or (0, 0))

    # Per-attachment health rows. The schema is small enough that we
    # gather + count in Python rather than running N+1 SQL — N here is
    # the attachment count on one gateway client, typically 1-3.
    snapshots = (
        (
            await db.execute(
                select(WgPeerSnapshot)
                .where(WgPeerSnapshot.agent_id == client.agent_id)
                .where(WgPeerSnapshot.kind == "mesh")
            )
        )
        .scalars()
        .all()
    )
    by_iface: dict[str, list[WgPeerSnapshot]] = {}
    for s in snapshots:
        by_iface.setdefault(s.interface, []).append(s)

    attachment_health: list[TunnelClientAttachmentHealth] = []
    for att in client.attachments:
        rows = by_iface.get(att.wg_interface, [])
        last_handshake = None
        for r in rows:
            if r.last_handshake_unix and (
                last_handshake is None or r.last_handshake_unix > last_handshake
            ):
                last_handshake = r.last_handshake_unix
        attachment_health.append(
            TunnelClientAttachmentHealth(
                attachment_id=att.id,
                wg_interface=att.wg_interface,
                peer_count=len(rows),
                last_handshake_unix=last_handshake,
            )
        )

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    heal_count = (
        await db.scalar(
            select(sa_func.count(AgentHealEvent.id))
            .where(AgentHealEvent.agent_id == client.agent_id)
            .where(AgentHealEvent.occurred_at >= cutoff)
        )
    ) or 0

    base = TunnelClientRead.model_validate(client)
    return TunnelClientSummary(
        **base.model_dump(),
        total_rx_bytes=int(total_rx),
        total_tx_bytes=int(total_tx),
        recent_heal_count=int(heal_count),
        attachment_health=attachment_health,
    )


@router.patch("/{client_id}", response_model=TunnelClientRead)
async def update_tunnel_client(
    client_id: str,
    body: TunnelClientUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    result = await db.execute(
        select(TunnelClient)
        .options(selectinload(TunnelClient.attachments))
        .where(TunnelClient.id == client_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(client, field, value)
    await db.commit()
    await db.refresh(client, attribute_names=["attachments"])
    emit_tunnel_client_changed()
    return client


@router.delete("/{client_id}", status_code=204)
async def delete_tunnel_client(
    client_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    result = await db.execute(select(TunnelClient).where(TunnelClient.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    await db.delete(client)
    await db.commit()
    emit_tunnel_client_changed()
    emit_port_forward_changed()  # cascade may have removed forwards

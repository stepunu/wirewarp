"""Tunnel client attachments — peerings between a homelab gateway client and a tunnel server.

Each attachment owns one wgN interface on the gateway agent, plus its own
fwmark / route_table_id for reply-path routing. Multiple attachments per
client let one homelab front services across regional VPSes simultaneously.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.gateway_lan_client import GatewayLanClient
from app.models.port_forward import PortForward
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.schemas.tunnel_client_attachment import (
    TunnelClientAttachmentCreate,
    TunnelClientAttachmentRead,
    TunnelClientAttachmentUpdate,
)
from app.auth import get_current_user, require_role, require_ops_role
from app.realtime.events import (
    emit_lan_client_changed,
    emit_port_forward_changed,
    emit_tunnel_client_changed,
)
from app.services.network_alloc import (
    allocate_attachment_ip,
    allocate_attachment_ordinal,
)
from app.services.tunnel_server_ops import (
    dispatch_remove_peer_for_attachment,
    dispatch_set_lan_egress,
    dispatch_wg_attach,
    dispatch_wg_detach,
)
from app.websocket.hub import manager

logger = logging.getLogger(__name__)

router = APIRouter()


# fwmark layout per spec: 0x101, 0x102, ... — leaves 0x1 for the legacy
# single-attachment reply mark. Route tables: 100, 101, 102, ...
def _fwmark_for_ordinal(n: int) -> int:
    return 0x101 + n


def _route_table_for_ordinal(n: int) -> int:
    return 100 + n


def _ordinal_from_iface(iface: str) -> int:
    if not iface.startswith("wg"):
        raise ValueError(f"unexpected wg interface name: {iface}")
    return int(iface[2:])


@router.get("", response_model=list[TunnelClientAttachmentRead])
async def list_attachments(
    tunnel_client_id: uuid.UUID | None = Query(None),
    tunnel_server_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    q = select(TunnelClientAttachment).order_by(TunnelClientAttachment.created_at.desc())
    if tunnel_client_id is not None:
        q = q.where(TunnelClientAttachment.tunnel_client_id == tunnel_client_id)
    if tunnel_server_id is not None:
        q = q.where(TunnelClientAttachment.tunnel_server_id == tunnel_server_id)
    return (await db.execute(q)).scalars().all()


@router.get("/{attachment_id}", response_model=TunnelClientAttachmentRead)
async def get_attachment(
    attachment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    att = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == attachment_id)
    )
    if att is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    return att


@router.post("", response_model=TunnelClientAttachmentRead, status_code=201)
async def create_attachment(
    body: TunnelClientAttachmentCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    client = await db.scalar(
        select(TunnelClient).where(TunnelClient.id == body.tunnel_client_id)
    )
    if client is None:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    server = await db.scalar(
        select(TunnelServer).where(TunnelServer.id == body.tunnel_server_id)
    )
    if server is None:
        raise HTTPException(status_code=404, detail="Tunnel server not found")

    # Both agents must be online so the attach handshake (wg_attach → result →
    # wg_add_peer) can complete in one shot. Same precheck the rebase
    # endpoint uses for symmetry.
    offline: list[str] = []
    if not manager.is_connected(str(client.agent_id)):
        offline.append(f"client agent (id={client.agent_id})")
    if not manager.is_connected(str(server.agent_id)):
        offline.append(f"server agent (id={server.agent_id})")
    if offline:
        raise HTTPException(
            status_code=503,
            detail=(
                "Cannot attach: " + ", ".join(offline)
                + " — bring them back online and retry."
            ),
        )

    ordinal = await allocate_attachment_ordinal(client.id, db)
    tunnel_ip = body.tunnel_ip or await allocate_attachment_ip(server.id, db)

    att = TunnelClientAttachment(
        tunnel_client_id=client.id,
        tunnel_server_id=server.id,
        tunnel_ip=tunnel_ip,
        wg_interface=f"wg{ordinal}",
        fwmark=_fwmark_for_ordinal(ordinal),
        route_table_id=_route_table_for_ordinal(ordinal),
    )
    db.add(att)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                f"Attachment for this (client, server) pair already exists, "
                f"or tunnel_ip {tunnel_ip} is already taken on this server."
            ),
        )
    await db.refresh(att)

    await dispatch_wg_attach(att, db)
    emit_tunnel_client_changed()
    return att


@router.patch("/{attachment_id}", response_model=TunnelClientAttachmentRead)
async def update_attachment(
    attachment_id: uuid.UUID,
    body: TunnelClientAttachmentUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    att = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == attachment_id)
    )
    if att is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    changes = body.model_dump(exclude_none=True)
    if not changes:
        return att

    client = await db.scalar(select(TunnelClient).where(TunnelClient.id == att.tunnel_client_id))
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == att.tunnel_server_id))
    if client is None or server is None:
        raise HTTPException(status_code=409, detail="Attachment has dangling client or server")
    if not manager.is_connected(str(client.agent_id)) or not manager.is_connected(
        str(server.agent_id)
    ):
        raise HTTPException(
            status_code=503,
            detail="Both client and server agents must be online to update an attachment",
        )

    for field, value in changes.items():
        setattr(att, field, value)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"tunnel_ip already in use on server {server.id}",
        )
    await db.refresh(att)

    await dispatch_wg_attach(att, db)
    emit_tunnel_client_changed()
    return att


@router.delete("/{attachment_id}", status_code=204)
async def delete_attachment(
    attachment_id: uuid.UUID,
    cascade: int = Query(0, ge=0, le=1),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    att = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == attachment_id)
    )
    if att is None:
        raise HTTPException(status_code=404, detail="Attachment not found")

    pf_count = (
        await db.scalar(
            select(PortForward).where(PortForward.attachment_id == attachment_id).limit(1)
        )
    )
    if pf_count is not None and not cascade:
        raise HTTPException(
            status_code=409,
            detail=(
                "Cannot detach: port forwards reference this attachment. "
                "Delete them first or pass ?cascade=1 to remove them with the attachment."
            ),
        )

    if cascade:
        forwards = (
            await db.execute(
                select(PortForward).where(PortForward.attachment_id == attachment_id)
            )
        ).scalars().all()
        for pf in forwards:
            await db.delete(pf)
        await db.commit()

    # Clear any LAN-host egress pins that referenced this attachment, both
    # in the DB and on the agent. The FK has ON DELETE SET NULL so the row
    # would survive the attachment delete, but the agent's `ip rule from
    # <lan_ip> table <route_table_id>` would point at a now-stale table —
    # ask the agent to remove each one before we delete the attachment.
    pinned = (
        await db.execute(
            select(GatewayLanClient).where(GatewayLanClient.egress_attachment_id == attachment_id)
        )
    ).scalars().all()
    if pinned:
        client = await db.scalar(
            select(TunnelClient).where(TunnelClient.id == att.tunnel_client_id)
        )
        if client is not None:
            for lc in pinned:
                await dispatch_set_lan_egress(client, lc.lan_ip, None, db)

    # Try to gracefully tear down on both ends. If agents are offline we
    # still drop the DB row — the attachment slot will reconcile when the
    # agents reconnect (server agent's stale peer is harmless; client
    # agent's stale wgN gets reclaimed by the next attach since ordinal
    # allocation picks the lowest free slot).
    await dispatch_remove_peer_for_attachment(att, db)
    await dispatch_wg_detach(att, db)

    await db.delete(att)
    await db.commit()
    emit_tunnel_client_changed()
    if cascade:
        emit_port_forward_changed()
    if pinned:
        emit_lan_client_changed()

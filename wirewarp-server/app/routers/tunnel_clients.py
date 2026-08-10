import ipaddress
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.gateway_lan_client import GatewayLanClient
from app.models.heal_event import AgentHealEvent
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.models.vpn_endpoint import VpnEndpoint
from app.models.wg_peer_snapshot import WgPeerSnapshot
from app.schemas.tunnel_client import (
    TunnelClientAttachmentHealth,
    TunnelClientRead,
    TunnelClientSummary,
    TunnelClientUpdate,
)
from app.schemas.wg_peer import WgPeerSnapshotRead
from app.auth import require_ops_role, require_role
from app.realtime.events import emit_tunnel_client_changed
from app.services.tunnel_server_ops import (
    dispatch_reconcile_lan_snat,
    dispatch_set_lan_egress,
    reconcile_client_attachments,
)
from app.services.port_forward_ops import serialize_server_runtime_mutation

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
    current_is_gateway = await db.scalar(
        select(TunnelClient.is_gateway).where(TunnelClient.id == client_id)
    )
    if current_is_gateway is None:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    requested = body.model_dump(exclude_unset=True)
    if current_is_gateway and requested.get("is_gateway") is False:
        async with serialize_server_runtime_mutation(uuid.UUID(int=0), db):
            return await _update_tunnel_client_locked(client_id, body, db)
    return await _update_tunnel_client_locked(client_id, body, db)


async def _update_tunnel_client_locked(
    client_id: str,
    body: TunnelClientUpdate,
    db: AsyncSession,
):
    result = await db.execute(
        select(TunnelClient)
        .options(selectinload(TunnelClient.attachments))
        .where(TunnelClient.id == client_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    requested = body.model_dump(exclude_unset=True)
    if requested.get("is_gateway", False) is None:
        requested.pop("is_gateway")
    changes = {
        field: value
        for field, value in requested.items()
        if getattr(client, field) != value
    }
    resulting_vm_network = changes.get("vm_network", client.vm_network)
    resulting_lan_ip = changes.get("lan_ip", client.lan_ip)
    resulting_is_gateway = changes.get("is_gateway", client.is_gateway)
    network = None
    if resulting_vm_network is not None:
        try:
            network = ipaddress.ip_network(resulting_vm_network, strict=True)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="vm_network must be a canonical IPv4 CIDR",
            ) from exc
        if network.version != 4:
            raise HTTPException(
                status_code=422,
                detail="vm_network must be a canonical IPv4 CIDR",
            )
    lan_address = None
    if resulting_lan_ip is not None:
        try:
            lan_address = ipaddress.ip_address(resulting_lan_ip)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="lan_ip must be an IPv4 address",
            ) from exc
        if lan_address.version != 4:
            raise HTTPException(
                status_code=422,
                detail="lan_ip must be an IPv4 address",
            )
    if resulting_is_gateway:
        if network is None or lan_address is None:
            raise HTTPException(
                status_code=422,
                detail="Gateway clients require vm_network and lan_ip",
            )
        if (
            lan_address not in network
            or lan_address == network.network_address
            or lan_address == network.broadcast_address
        ):
            raise HTTPException(
                status_code=422,
                detail="lan_ip must be a usable host address inside vm_network",
            )
    gateway_disabled = client.is_gateway and changes.get("is_gateway") is False
    if gateway_disabled:
        vpn_endpoint_id = await db.scalar(
            select(VpnEndpoint.id).where(VpnEndpoint.tunnel_client_id == client.id)
        )
        if vpn_endpoint_id is not None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Cannot disable gateway mode while a VPN endpoint exists. "
                    "Preserve gateway mode until VPN endpoint teardown is available."
                ),
            )
    lan_rows: list[GatewayLanClient] = []
    affected_server_ids = set()
    if gateway_disabled:
        lan_rows = (
            await db.scalars(
                select(GatewayLanClient).where(
                    GatewayLanClient.tunnel_client_id == client.id
                )
            )
        ).all()
        attachment_ids = {
            row.egress_attachment_id
            for row in lan_rows
            if row.egress_attachment_id is not None
        }
        if attachment_ids:
            affected_server_ids = set(
                await db.scalars(
                    select(TunnelClientAttachment.tunnel_server_id).where(
                        TunnelClientAttachment.id.in_(attachment_ids)
                    )
                )
            )
        for row in lan_rows:
            row.egress_attachment_id = None
            row.egress_tunnel_server_ip_id = None
    for field, value in changes.items():
        setattr(client, field, value)
    if not changes:
        return client
    await db.commit()
    await db.refresh(client, attribute_names=["attachments"])

    try:
        if gateway_disabled:
            for row in lan_rows:
                await dispatch_set_lan_egress(client, row.lan_ip, None, db)
            for server_id in affected_server_ids:
                server = await db.get(TunnelServer, server_id)
                if server is not None:
                    await dispatch_reconcile_lan_snat(server, db)
        await reconcile_client_attachments(client.id, db)
    except Exception:
        await db.rollback()
        logger.exception(
            "Immediate tunnel client reconcile failed for %s; desired state "
            "will replay on reconnect",
            client_id,
        )
    client = (
        await db.execute(
            select(TunnelClient)
            .options(selectinload(TunnelClient.attachments))
            .where(TunnelClient.id == client_id)
        )
    ).scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="Tunnel client not found after update")
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
    raise HTTPException(
        status_code=409,
        detail=(
            "Tunnel client configuration cannot be deleted separately from its agent. "
            "Runtime teardown is not available, so the desired state was preserved."
        ),
    )

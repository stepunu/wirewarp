import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.heal_event import AgentHealEvent
from app.models.port_forward import PortForward
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.models.wg_peer_snapshot import WgPeerSnapshot
from app.schemas.crowdsec import CrowdSecSnapshotRead
from app.schemas.tunnel_server import TunnelServerRead, TunnelServerSummary, TunnelServerUpdate
from app.schemas.tunnel_server_ip import TunnelServerIPRead
from app.schemas.wg_peer import WgPeerSnapshotRead
from app.auth import require_ops_role, require_role
from app.realtime.events import (
    emit_port_forward_changed,
    emit_tunnel_client_changed,
    emit_tunnel_server_changed,
)
from app.services.agent_commands import send_command
from app.services.crowdsec_ops import build_whitelist
from app.services.network_alloc import allocate_tunnel_network, renumber_host
from app.services.primary_ip import resolve_public_ip
from app.services.tunnel_server_ops import dispatch_wg_attach, dispatch_wg_init
from app.websocket.hub import manager

logger = logging.getLogger(__name__)

router = APIRouter()


def _to_read(server: TunnelServer) -> TunnelServerRead:
    primary_addr: str | None = None
    ips_read: list[TunnelServerIPRead] = []
    for ip in server.ips:
        ips_read.append(
            TunnelServerIPRead(
                id=ip.id,
                tunnel_server_id=ip.tunnel_server_id,
                address=ip.address,
                label=ip.label,
                is_primary=ip.is_primary,
                port_forward_count=0,
                created_at=ip.created_at,
            )
        )
        if ip.is_primary:
            primary_addr = ip.address
    return TunnelServerRead(
        id=server.id,
        agent_id=server.agent_id,
        wg_port=server.wg_port,
        wg_interface=server.wg_interface,
        primary_ip=primary_addr,
        public_iface=server.public_iface,
        wg_public_key=server.wg_public_key,
        tunnel_network=server.tunnel_network,
        created_at=server.created_at,
        ips=ips_read,
    )


@router.get("", response_model=list[TunnelServerRead])
async def list_tunnel_servers(db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    result = await db.execute(
        select(TunnelServer)
        .options(selectinload(TunnelServer.ips))
        .order_by(TunnelServer.created_at.desc())
    )
    return [_to_read(s) for s in result.scalars().all()]


@router.get("/{server_id}", response_model=TunnelServerRead)
async def get_tunnel_server(server_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    result = await db.execute(
        select(TunnelServer).options(selectinload(TunnelServer.ips)).where(TunnelServer.id == server_id)
    )
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    return _to_read(server)


@router.get("/{server_id}/wg-peers", response_model=list[WgPeerSnapshotRead])
async def list_tunnel_server_wg_peers(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """All `kind=mesh` peers seen on this server agent's wg interfaces.

    Returns every row that the agent's last heartbeat reconciled. No
    filtering by interface (the server may grow more than one wg port
    in future) — sorted by interface, then handshake recency.
    """
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    result = await db.execute(
        select(WgPeerSnapshot)
        .where(WgPeerSnapshot.agent_id == server.agent_id)
        .where(WgPeerSnapshot.kind == "mesh")
        .order_by(WgPeerSnapshot.interface.asc(), WgPeerSnapshot.last_handshake_unix.desc())
    )
    return result.scalars().all()


@router.post("/{server_id}/crowdsec/install", status_code=202)
async def install_crowdsec_on_tunnel_server(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    """Install CrowdSec on a tunnel server's host via the agent.

    Admin-only because this runs apt as root on a remote host. Dispatches
    a `crowdsec_install` command with the auto-built whitelist payload
    so the agent applies the WireWarp-managed allowlist as part of the
    initial install — no second command needed.
    """
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    whitelist = await build_whitelist(server.agent_id, db)
    sent, command_id = await send_command(
        agent_id=str(server.agent_id),
        command_type="crowdsec_install",
        params=whitelist,
        db=db,
        actor_user_id=user.id,
    )
    if not sent:
        raise HTTPException(
            status_code=409,
            detail="Agent is not currently connected. Reconnect the agent, then retry.",
        )
    return {"command_id": command_id, "sent": True}


@router.get("/{server_id}/crowdsec", response_model=CrowdSecSnapshotRead)
async def get_tunnel_server_crowdsec(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """Return the latest CrowdSec snapshot for this server's agent.

    Always returns 200 — when the agent hasn't reported yet (or cscli
    is missing on the host), we send `{running: false}` so the UI can
    render its "not detected" card without special-casing 404.
    """
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    snap = await db.scalar(
        select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == server.agent_id)
    )
    if snap is None:
        return CrowdSecSnapshotRead(running=False)
    return snap


@router.get("/{server_id}/summary", response_model=TunnelServerSummary)
async def get_tunnel_server_summary(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """Aggregated dashboard payload for the per-server detail page."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func as sa_func

    server = (
        await db.execute(
            select(TunnelServer)
            .options(selectinload(TunnelServer.ips))
            .where(TunnelServer.id == server_id)
        )
    ).scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")

    # Per-peer aggregates, scoped to mesh peers on this agent.
    agg = (
        await db.execute(
            select(
                sa_func.count(WgPeerSnapshot.id),
                sa_func.coalesce(sa_func.sum(WgPeerSnapshot.rx_bytes), 0),
                sa_func.coalesce(sa_func.sum(WgPeerSnapshot.tx_bytes), 0),
            )
            .where(WgPeerSnapshot.agent_id == server.agent_id)
            .where(WgPeerSnapshot.kind == "mesh")
        )
    ).first()
    peer_count, total_rx, total_tx = (agg or (0, 0, 0))

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    heal_count = (
        await db.scalar(
            select(sa_func.count(AgentHealEvent.id))
            .where(AgentHealEvent.agent_id == server.agent_id)
            .where(AgentHealEvent.occurred_at >= cutoff)
        )
    ) or 0

    forward_count = (
        await db.scalar(
            select(sa_func.count(PortForward.id))
            .join(TunnelClientAttachment, PortForward.attachment_id == TunnelClientAttachment.id)
            .where(TunnelClientAttachment.tunnel_server_id == server.id)
        )
    ) or 0

    base = _to_read(server)
    return TunnelServerSummary(
        **base.model_dump(),
        peer_count=int(peer_count),
        total_rx_bytes=int(total_rx),
        total_tx_bytes=int(total_tx),
        recent_heal_count=int(heal_count),
        forward_count=int(forward_count),
    )


@router.patch("/{server_id}", response_model=TunnelServerRead)
async def update_tunnel_server(
    server_id: str,
    body: TunnelServerUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    result = await db.execute(
        select(TunnelServer).options(selectinload(TunnelServer.ips)).where(TunnelServer.id == server_id)
    )
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(server, field, value)
    await db.commit()
    await db.refresh(server, attribute_names=["ips"])

    await dispatch_wg_init(server, db)
    emit_tunnel_server_changed()

    return _to_read(server)


@router.delete("/{server_id}", status_code=204)
async def delete_tunnel_server(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    result = await db.execute(select(TunnelServer).where(TunnelServer.id == server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    await db.delete(server)
    await db.commit()
    emit_tunnel_server_changed()
    emit_tunnel_client_changed()  # cascade may have removed attachments
    emit_port_forward_changed()


class RebaseRequest(BaseModel):
    tunnel_network: str

    @field_validator("tunnel_network")
    @classmethod
    def _validate_24(cls, v: str) -> str:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"'{v}' is not a valid network") from exc
        if net.version != 4 or net.prefixlen != 24:
            raise ValueError("tunnel_network must be an IPv4 /24")
        return str(ipaddress.ip_network(f"{net.network_address}/24", strict=False))


class RebaseSuggestion(BaseModel):
    tunnel_network: str


@router.get("/{server_id}/rebase-suggestion", response_model=RebaseSuggestion)
async def suggest_rebase_network(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    network = await allocate_tunnel_network(db, exclude_server_id=server_id)
    return RebaseSuggestion(tunnel_network=network)


@router.post("/{server_id}/rebase", response_model=TunnelServerRead)
async def rebase_tunnel_network(
    server_id: str,
    body: RebaseRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    """Move a tunnel server to a new /24, renumbering all of its attachments
    (preserving host octets) and reissuing wg_init / wg_attach / iptables
    commands. Disruptive: every attachment on this server briefly loses its
    handshake while reconfiguring.
    """
    result = await db.execute(
        select(TunnelServer).options(selectinload(TunnelServer.ips)).where(TunnelServer.id == server_id)
    )
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")

    new_network = body.tunnel_network
    if new_network == server.tunnel_network:
        return _to_read(server)

    # Connectivity precheck: every agent that needs to receive a reconfig
    # command must be currently connected. Walks attachments now (one row
    # per (client, server) peering) instead of the legacy direct FK.
    offline: list[str] = []
    if not manager.is_connected(str(server.agent_id)):
        offline.append(f"server agent (id={server.agent_id})")
    attachment_rows = (
        await db.execute(
            select(
                TunnelClientAttachment.id,
                TunnelClientAttachment.tunnel_ip,
                TunnelClient.agent_id,
            )
            .join(TunnelClient, TunnelClient.id == TunnelClientAttachment.tunnel_client_id)
            .where(TunnelClientAttachment.tunnel_server_id == server.id)
        )
    ).all()
    for att_id, att_ip, client_agent_id in attachment_rows:
        if not manager.is_connected(str(client_agent_id)):
            offline.append(f"client agent (id={client_agent_id}, ip={att_ip})")
    if offline:
        raise HTTPException(
            status_code=503,
            detail=(
                "Cannot rebase: " + ", ".join(offline)
                + " — bring them back online and retry."
            ),
        )

    # Conflict check
    others = (
        await db.execute(
            select(TunnelServer.id, TunnelServer.tunnel_network).where(TunnelServer.id != server.id)
        )
    ).all()
    new_net = ipaddress.ip_network(new_network, strict=False)
    for other_id, other_net in others:
        try:
            o = ipaddress.ip_network(other_net, strict=False)
        except ValueError:
            continue
        if o.overlaps(new_net):
            raise HTTPException(
                status_code=409,
                detail=f"Network {new_network} overlaps with server {other_id} ({other_net})",
            )

    old_network = server.tunnel_network

    # Walk attachments — one row per peering with this server.
    attachments = (
        await db.execute(
            select(TunnelClientAttachment).where(
                TunnelClientAttachment.tunnel_server_id == server.id
            )
        )
    ).scalars().all()

    ip_map: dict[str, str] = {}
    for att in attachments:
        if not att.tunnel_ip:
            continue
        ip_map[att.tunnel_ip] = renumber_host(att.tunnel_ip, new_network)

    # Renumber forwards whose destination_ip references an attachment IP we
    # just renumbered.
    attachment_ids = [att.id for att in attachments]
    forwards = []
    if attachment_ids:
        forwards = (
            await db.execute(
                select(PortForward).where(PortForward.attachment_id.in_(attachment_ids))
            )
        ).scalars().all()

    forward_old_dest: dict[str, str] = {str(pf.id): pf.destination_ip for pf in forwards}

    # Apply DB changes in one transaction.
    server.tunnel_network = new_network
    for att in attachments:
        if att.tunnel_ip and att.tunnel_ip in ip_map:
            att.tunnel_ip = ip_map[att.tunnel_ip]
    for pf in forwards:
        if pf.destination_ip in ip_map:
            pf.destination_ip = ip_map[pf.destination_ip]
    await db.commit()
    await db.refresh(server, attribute_names=["ips"])

    # Dispatch commands. Order matters:
    #   1. server: wg_init (rebuilds wg0 on the new network).
    #   2. each attachment: wg_attach (new tunnel_ip + new vps_tunnel_ip).
    #   3. each active forward: remove (old) + add (new).
    await dispatch_wg_init(server, db)

    for att in attachments:
        await dispatch_wg_attach(att, db)

    for pf in forwards:
        if not pf.active:
            continue
        old_dest = forward_old_dest.get(str(pf.id))
        public_ip = await resolve_public_ip(pf, db)
        common = {
            "protocol": pf.protocol,
            "public_port": pf.public_port,
            "destination_port": pf.destination_port,
            "public_ip": public_ip,
        }
        if pf.public_port_end is not None:
            common["public_port_end"] = pf.public_port_end
        if pf.destination_port_end is not None:
            common["destination_port_end"] = pf.destination_port_end
        if old_dest:
            await send_command(
                agent_id=str(server.agent_id),
                command_type="iptables_remove_forward",
                params={**common, "destination_ip": old_dest},
                db=db,
            )
        await send_command(
            agent_id=str(server.agent_id),
            command_type="iptables_add_forward",
            params={**common, "destination_ip": pf.destination_ip},
            db=db,
        )

    logger.info(
        "Rebased server %s: %s -> %s (%d attachment(s), %d forward(s))",
        server.id, old_network, new_network, len(attachments), len(forwards),
    )
    emit_tunnel_server_changed()
    emit_tunnel_client_changed()
    emit_port_forward_changed()
    return _to_read(server)

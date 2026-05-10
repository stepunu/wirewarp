import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.port_forward import PortForward
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.schemas.tunnel_server import TunnelServerRead, TunnelServerUpdate
from app.schemas.tunnel_server_ip import TunnelServerIPRead
from app.auth import require_ops_role, require_role
from app.realtime.events import (
    emit_port_forward_changed,
    emit_tunnel_client_changed,
    emit_tunnel_server_changed,
)
from app.services.agent_commands import send_command
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

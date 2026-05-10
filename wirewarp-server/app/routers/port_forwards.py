import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.schemas.port_forward import PortForwardCreate, PortForwardRead, PortForwardUpdate
from app.auth import get_current_user, require_role
from app.realtime.events import emit_port_forward_changed, emit_tunnel_server_changed
from app.services.agent_commands import send_command
from app.services.primary_ip import resolve_public_ip

router = APIRouter()
logger = logging.getLogger(__name__)


async def _server_for_attachment(
    attachment_id: uuid.UUID, db: AsyncSession
) -> TunnelServer | None:
    """Resolve the tunnel server for an attachment_id (one indirect lookup)."""
    server_id = await db.scalar(
        select(TunnelClientAttachment.tunnel_server_id).where(
            TunnelClientAttachment.id == attachment_id
        )
    )
    if server_id is None:
        return None
    return await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))


async def _push_forward(pf: PortForward, command_type: str, db: AsyncSession) -> None:
    """Send iptables_add_forward or iptables_remove_forward to the tunnel server agent."""
    server = await _server_for_attachment(pf.attachment_id, db)
    if server is None:
        return
    resolved_ip = await resolve_public_ip(pf, db)
    params: dict = {
        "protocol": pf.protocol,
        "public_port": pf.public_port,
        "destination_ip": pf.destination_ip,
        "destination_port": pf.destination_port,
        "public_ip": resolved_ip,
    }
    if pf.public_port_end is not None:
        params["public_port_end"] = pf.public_port_end
    if pf.destination_port_end is not None:
        params["destination_port_end"] = pf.destination_port_end
    sent, _ = await send_command(
        agent_id=str(server.agent_id),
        command_type=command_type,
        params=params,
        db=db,
    )
    if not sent:
        port_str = f"{pf.public_port}-{pf.public_port_end}" if pf.public_port_end else str(pf.public_port)
        logger.warning(
            "Server agent %s not connected — %s not delivered for port %s",
            server.agent_id, command_type, port_str,
        )


async def migrate_port_forwards_to_pin(
    lan_ip: str,
    new_attachment_id: uuid.UUID,
    new_tunnel_server_ip_id: uuid.UUID | None,
    db: AsyncSession,
) -> int:
    """Move every active port forward whose destination_ip == lan_ip onto
    the given (attachment, tunnel-server-ip). Used by the LAN-client
    egress pin so inbound and outbound stay symmetric the moment the
    operator changes their mind about which VPS fronts a host.

    Returns the count of forwards actually migrated. Forwards already on
    the target are skipped silently. A unique-constraint conflict (the
    target already has a forward on the same port) leaves that one
    forward where it was — operator can resolve manually.

    Failure is best-effort by design: if the new VPS agent is offline,
    the new DNAT rule queues for replay on reconnect; if the old VPS
    agent is offline, the stale rule remains until that agent reconnects
    and reconciles via the active-forward replay loop in main.py. This
    matches the project's offline-resilience principle (Architecture
    Rule 3).
    """
    result = await db.execute(
        select(PortForward).where(PortForward.destination_ip == lan_ip)
    )
    forwards = result.scalars().all()

    migrated = 0
    for pf in forwards:
        if (
            pf.attachment_id == new_attachment_id
            and pf.tunnel_server_ip_id == new_tunnel_server_ip_id
        ):
            continue

        # Pre-check uniqueness against the target slot. Postgres NULLs in
        # tunnel_server_ip_id are *distinct* under the UNIQUE constraint
        # (default NULL semantics), so a NULL target can never conflict
        # — skip the query in that case. Doing the check up front avoids
        # the integrity-error-then-rollback path that would otherwise
        # corrupt the async session and bubble up as MissingGreenlet at
        # the request boundary.
        if new_tunnel_server_ip_id is not None:
            conflict_id = await db.scalar(
                select(PortForward.id).where(
                    PortForward.attachment_id == new_attachment_id,
                    PortForward.tunnel_server_ip_id == new_tunnel_server_ip_id,
                    PortForward.protocol == pf.protocol,
                    PortForward.public_port == pf.public_port,
                    PortForward.id != pf.id,
                )
            )
            if conflict_id is not None:
                logger.warning(
                    "Skipped migrating forward %s for %s — target attachment "
                    "already has a forward on %s/%s",
                    pf.id, lan_ip, pf.protocol, pf.public_port,
                )
                continue

        old_snapshot = PortForward(
            attachment_id=pf.attachment_id,
            tunnel_server_ip_id=pf.tunnel_server_ip_id,
            protocol=pf.protocol,
            public_port=pf.public_port,
            public_port_end=pf.public_port_end,
            destination_ip=pf.destination_ip,
            destination_port=pf.destination_port,
            destination_port_end=pf.destination_port_end,
        )
        was_active = pf.active

        pf.attachment_id = new_attachment_id
        pf.tunnel_server_ip_id = new_tunnel_server_ip_id
        await db.commit()
        await db.refresh(pf)

        if was_active:
            await _push_forward(old_snapshot, "iptables_remove_forward", db)
            await _push_forward(pf, "iptables_add_forward", db)
        migrated += 1

    return migrated


@router.get("", response_model=list[PortForwardRead])
async def list_port_forwards(
    attachment_id: uuid.UUID | None = None,
    tunnel_server_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = select(PortForward).order_by(PortForward.created_at.desc())
    if attachment_id is not None:
        q = q.where(PortForward.attachment_id == attachment_id)
    if tunnel_server_id is not None:
        # convenience: filter via attachment join
        sub = select(TunnelClientAttachment.id).where(
            TunnelClientAttachment.tunnel_server_id == tunnel_server_id
        )
        q = q.where(PortForward.attachment_id.in_(sub))
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=PortForwardRead, status_code=201)
async def create_port_forward(
    body: PortForwardCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    att = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == body.attachment_id)
    )
    if att is None:
        raise HTTPException(status_code=404, detail="Attachment not found")

    pf = PortForward(**body.model_dump())
    db.add(pf)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Port {body.public_port}/{body.protocol} is already forwarded on this IP",
        )
    await db.refresh(pf)
    if pf.active:
        await _push_forward(pf, "iptables_add_forward", db)
    emit_port_forward_changed()
    emit_tunnel_server_changed()  # port_forward_count on tunnel_server_ips moved
    return pf


@router.patch("/{pf_id}", response_model=PortForwardRead)
async def update_port_forward(
    pf_id: str,
    body: PortForwardUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    result = await db.execute(select(PortForward).where(PortForward.id == pf_id))
    pf = result.scalar_one_or_none()
    if not pf:
        raise HTTPException(status_code=404, detail="Port forward not found")

    # Snapshot old rule before applying changes (needed to remove the old iptables rule)
    old_active = pf.active
    old_pf_snapshot = PortForward(
        attachment_id=pf.attachment_id,
        tunnel_server_ip_id=pf.tunnel_server_ip_id,
        protocol=pf.protocol,
        public_port=pf.public_port,
        public_port_end=pf.public_port_end,
        destination_ip=pf.destination_ip,
        destination_port=pf.destination_port,
        destination_port_end=pf.destination_port_end,
    )

    rule_fields = {
        "attachment_id",
        "tunnel_server_ip_id",
        "protocol",
        "public_port",
        "public_port_end",
        "destination_ip",
        "destination_port",
        "destination_port_end",
    }
    changes = body.model_dump(exclude_unset=True)
    rule_changed = bool(rule_fields & changes.keys())

    for field, value in changes.items():
        setattr(pf, field, value)

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        port = changes.get("public_port", pf.public_port)
        proto = changes.get("protocol", pf.protocol)
        raise HTTPException(
            status_code=409, detail=f"Port {port}/{proto} is already forwarded on this IP"
        )

    await db.refresh(pf)

    if rule_changed and old_active:
        await _push_forward(old_pf_snapshot, "iptables_remove_forward", db)
        if pf.active:
            await _push_forward(pf, "iptables_add_forward", db)
    elif not old_active and pf.active:
        await _push_forward(pf, "iptables_add_forward", db)
    elif old_active and not pf.active:
        await _push_forward(pf, "iptables_remove_forward", db)

    emit_port_forward_changed()
    emit_tunnel_server_changed()
    return pf


@router.delete("/{pf_id}", status_code=204)
async def delete_port_forward(
    pf_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    result = await db.execute(select(PortForward).where(PortForward.id == pf_id))
    pf = result.scalar_one_or_none()
    if not pf:
        raise HTTPException(status_code=404, detail="Port forward not found")
    if pf.active:
        await _push_forward(pf, "iptables_remove_forward", db)
    await db.delete(pf)
    await db.commit()
    emit_port_forward_changed()
    emit_tunnel_server_changed()

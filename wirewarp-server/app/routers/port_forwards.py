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
from app.schemas.port_forward import (
    ClassifyResponse,
    PortForwardCreate,
    PortForwardRead,
    PortForwardUpdate,
    SensitiveServiceTipRead,
)
from app.auth import get_current_user, require_role, require_ops_role
from app.realtime.events import emit_port_forward_changed, emit_tunnel_server_changed
from app.services.agent_commands import send_command
from app.services.edge_port_conflicts import (
    find_active_http_site_on_server,
    uses_edge_entrypoint,
)
from app.services.port_security import classify_forward
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


async def _ensure_raw_forward_does_not_shadow_edge(
    *,
    db: AsyncSession,
    attachment: TunnelClientAttachment,
    protocol: str,
    public_port: int,
    public_port_end: int | None,
    active: bool,
    exclude_port_forward_id: uuid.UUID | None = None,
) -> None:
    if not active or not uses_edge_entrypoint(protocol, public_port, public_port_end):
        return
    conflict = await find_active_http_site_on_server(
        db,
        attachment.tunnel_server_id,
        exclude_port_forward_id=exclude_port_forward_id,
    )
    if conflict is None:
        return
    raise HTTPException(
        status_code=409,
        detail=(
            "Raw TCP forwards on 80/443 cannot be active while Security Edge "
            "sites exist on the same server. Use a Security Edge site instead, "
            "or disable the existing site first."
        ),
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


@router.get("/classify", response_model=ClassifyResponse)
async def classify_port_forward(
    protocol: str,
    port: int,
    port_end: int | None = None,
    _: User = Depends(require_ops_role),
):
    """Classify a (protocol, port[, port_end]) tuple against the
    sensitive-service catalogue.

    Used by the New Port Forward dialog to show the advisory tip
    *before* the operator clicks submit. Same classifier as the
    read-time computed field on PortForwardRead.sensitive_service, so
    there is no chance of the pre-create advice disagreeing with the
    post-create badge.

    Registered before the `/{pf_id}` route so FastAPI doesn't try to
    parse "classify" as a UUID path parameter.
    """
    if protocol not in ("tcp", "udp"):
        raise HTTPException(status_code=400, detail="protocol must be tcp or udp")
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="port out of range")
    if port_end is not None and (port_end < port or port_end > 65535):
        raise HTTPException(status_code=400, detail="port_end out of range")
    tip = classify_forward(protocol, port, port_end)
    if tip is None:
        return ClassifyResponse(tip=None)
    return ClassifyResponse(
        tip=SensitiveServiceTipRead(
            key=tip.key,
            label=tip.label,
            severity=tip.severity,
            message=tip.message,
        )
    )


@router.get("", response_model=list[PortForwardRead])
async def list_port_forwards(
    attachment_id: uuid.UUID | None = None,
    tunnel_server_id: uuid.UUID | None = None,
    service_kind: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    q = select(PortForward).order_by(PortForward.created_at.desc())
    if service_kind is not None:
        if service_kind not in ("raw", "http"):
            raise HTTPException(status_code=400, detail="service_kind must be raw or http")
        q = q.where(PortForward.service_kind == service_kind)
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
    await _ensure_raw_forward_does_not_shadow_edge(
        db=db,
        attachment=att,
        protocol=body.protocol,
        public_port=body.public_port,
        public_port_end=body.public_port_end,
        active=True,
    )

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

    next_attachment_id = changes.get("attachment_id", pf.attachment_id)
    next_attachment = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == next_attachment_id)
    )
    if next_attachment is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    await _ensure_raw_forward_does_not_shadow_edge(
        db=db,
        attachment=next_attachment,
        protocol=changes.get("protocol", pf.protocol),
        public_port=changes.get("public_port", pf.public_port),
        public_port_end=changes.get("public_port_end", pf.public_port_end),
        active=changes.get("active", pf.active),
        exclude_port_forward_id=pf.id,
    )

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

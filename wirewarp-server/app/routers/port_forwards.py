import ipaddress
import logging
import uuid
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server_ip import TunnelServerIP
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
from app.services.edge_port_conflicts import (
    find_active_http_site_on_server,
    uses_edge_entrypoint,
)
from app.services.port_security import classify_forward
from app.services.port_forward_ops import (
    RawForwardRemovalError,
    RawForwardRule,
    dispatch_raw_forward,
    remove_raw_forward_rules_confirmed,
    restore_raw_forward_rules,
    serialize_server_runtime_mutation,
    serialize_server_runtime_mutations,
    snapshot_raw_forward,
)
from app.services.primary_ip import get_primary_ip, resolve_public_ip

router = APIRouter()
logger = logging.getLogger(__name__)


def _validate_raw_rule_values(
    *,
    protocol: str,
    public_port: int,
    public_port_end: int | None,
    destination_ip: str,
    destination_port: int,
    destination_port_end: int | None,
) -> None:
    if protocol not in {"tcp", "udp"}:
        raise HTTPException(status_code=422, detail="protocol must be tcp or udp")
    ports = [public_port, destination_port]
    if public_port_end is not None:
        ports.append(public_port_end)
    if destination_port_end is not None:
        ports.append(destination_port_end)
    if any(port < 1 or port > 65535 for port in ports):
        raise HTTPException(status_code=422, detail="ports must be between 1 and 65535")
    if (public_port_end is None) != (destination_port_end is None):
        raise HTTPException(
            status_code=422,
            detail="public and destination range ends must both be set",
        )
    if public_port_end is not None and destination_port_end is not None:
        if public_port_end < public_port or destination_port_end < destination_port:
            raise HTTPException(status_code=422, detail="port range end must be at least its start")
        if public_port_end - public_port != destination_port_end - destination_port:
            raise HTTPException(status_code=422, detail="public and destination port ranges must have equal size")
    try:
        address = ipaddress.ip_address(destination_ip)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="destination_ip must be a canonical IPv4 address") from exc
    if address.version != 4 or str(address) != destination_ip:
        raise HTTPException(status_code=422, detail="destination_ip must be a canonical IPv4 address")


async def _validate_raw_forward_target(
    attachment: TunnelClientAttachment,
    tunnel_server_ip_id: uuid.UUID | None,
    active: bool,
    db: AsyncSession,
) -> None:
    if tunnel_server_ip_id is not None:
        ip_server_id = await db.scalar(
            select(TunnelServerIP.tunnel_server_id).where(
                TunnelServerIP.id == tunnel_server_ip_id
            )
        )
        if ip_server_id != attachment.tunnel_server_id:
            raise HTTPException(
                status_code=422,
                detail="tunnel_server_ip_id must belong to the attachment tunnel server",
            )
    elif active and await get_primary_ip(attachment.tunnel_server_id, db) is None:
        raise HTTPException(
            status_code=409,
            detail="Active raw forwards require an explicit IP or a server primary IP",
        )


@dataclass
class PortForwardMigration:
    forward_ids: list[uuid.UUID]
    confirmed_removals: list[RawForwardRule]
    guard: AbstractAsyncContextManager

    @property
    def count(self) -> int:
        return len(self.forward_ids)

    async def complete(self, db: AsyncSession) -> None:
        try:
            for forward_id in self.forward_ids:
                try:
                    pf = await db.get(PortForward, forward_id)
                    if pf is None or not pf.active or pf.service_kind != "raw":
                        continue
                    await dispatch_raw_forward(pf, "iptables_add_forward", db)
                except Exception:
                    await db.rollback()
                    logger.exception(
                        "Immediate migrated forward replay failed for %s; desired "
                        "state will replay on reconnect",
                        forward_id,
                    )
        finally:
            await self.guard.__aexit__(None, None, None)

    async def abort(self, db: AsyncSession) -> None:
        try:
            await db.rollback()
            await restore_raw_forward_rules(self.confirmed_removals, db)
        finally:
            await self.guard.__aexit__(None, None, None)


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
    *,
    runtime_lock_held: bool = False,
) -> PortForwardMigration:
    """Prepare an atomic LAN-pin forward move after confirmed old cleanup.

    The caller commits these in-session mutations with the LAN pin and then
    calls ``complete``. It calls ``abort`` on any desired-state write failure.
    """
    target_attachment = await db.get(TunnelClientAttachment, new_attachment_id)
    if target_attachment is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    server_ids = set(
        await db.scalars(
            select(TunnelClientAttachment.tunnel_server_id)
            .join(PortForward, PortForward.attachment_id == TunnelClientAttachment.id)
            .where(PortForward.destination_ip == lan_ip)
        )
    )
    server_ids.add(target_attachment.tunnel_server_id)
    @asynccontextmanager
    async def no_runtime_lock():
        yield

    guard = (
        no_runtime_lock()
        if runtime_lock_held
        else serialize_server_runtime_mutations(server_ids, db)
    )
    await guard.__aenter__()
    confirmed: list[RawForwardRule] = []
    try:
        forwards = (
            await db.scalars(
                select(PortForward).where(PortForward.destination_ip == lan_ip)
            )
        ).all()
        migrating: list[PortForward] = []
        old_rules: list[RawForwardRule] = []
        for pf in forwards:
            if (
                pf.attachment_id == new_attachment_id
                and pf.tunnel_server_ip_id == new_tunnel_server_ip_id
            ):
                continue
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
                        "Skipped migrating forward %s for %s because the target "
                        "attachment already uses %s/%s",
                        pf.id,
                        lan_ip,
                        pf.protocol,
                        pf.public_port,
                    )
                    continue
            migrating.append(pf)
            if pf.active and pf.service_kind == "raw":
                snapshot = snapshot_raw_forward(pf)
                old_rules.append(
                    RawForwardRule(snapshot, await resolve_public_ip(snapshot, db))
                )
        try:
            confirmed = await remove_raw_forward_rules_confirmed(old_rules, db)
        except RawForwardRemovalError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "The old tunnel server did not confirm raw forward removal "
                    f"({exc.state.value}). The egress pin was not changed."
                ),
            ) from exc
        for pf in migrating:
            pf.attachment_id = new_attachment_id
            pf.tunnel_server_ip_id = new_tunnel_server_ip_id
        return PortForwardMigration(
            [pf.id for pf in migrating],
            confirmed,
            guard,
        )
    except Exception:
        if confirmed:
            await restore_raw_forward_rules(confirmed, db)
        await guard.__aexit__(None, None, None)
        raise


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
    server_id = await db.scalar(
        select(TunnelClientAttachment.tunnel_server_id).where(
            TunnelClientAttachment.id == body.attachment_id
        )
    )
    if server_id is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    async with serialize_server_runtime_mutation(server_id, db):
        return await _create_port_forward_locked(body, db)


async def _create_port_forward_locked(
    body: PortForwardCreate,
    db: AsyncSession,
):
    att = await db.scalar(
        select(TunnelClientAttachment).where(TunnelClientAttachment.id == body.attachment_id)
    )
    if att is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    _validate_raw_rule_values(
        protocol=body.protocol,
        public_port=body.public_port,
        public_port_end=body.public_port_end,
        destination_ip=body.destination_ip,
        destination_port=body.destination_port,
        destination_port_end=body.destination_port_end,
    )
    await _validate_raw_forward_target(
        att,
        body.tunnel_server_ip_id,
        True,
        db,
    )
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
        try:
            await dispatch_raw_forward(pf, "iptables_add_forward", db)
        except Exception:
            await db.rollback()
            logger.exception(
                "Immediate raw forward create replay failed for %s; desired "
                "state will replay on reconnect",
                pf.id,
            )
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
    pf = await db.scalar(select(PortForward).where(PortForward.id == pf_id))
    if pf is None:
        raise HTTPException(status_code=404, detail="Port forward not found")
    if pf.service_kind != "raw":
        raise HTTPException(
            status_code=409,
            detail="HTTP edge routes cannot be changed through the raw forward endpoint",
        )
    current_server_id = await db.scalar(
        select(TunnelClientAttachment.tunnel_server_id).where(
            TunnelClientAttachment.id == pf.attachment_id
        )
    )
    changes = body.model_dump(exclude_unset=True)
    next_attachment_id = changes.get("attachment_id", pf.attachment_id)
    next_server_id = await db.scalar(
        select(TunnelClientAttachment.tunnel_server_id).where(
            TunnelClientAttachment.id == next_attachment_id
        )
    )
    server_ids = {
        server_id
        for server_id in (current_server_id, next_server_id)
        if server_id is not None
    }
    async with serialize_server_runtime_mutations(server_ids, db):
        return await _update_port_forward_locked(pf_id, body, db)


async def _update_port_forward_locked(
    pf_id: str,
    body: PortForwardUpdate,
    db: AsyncSession,
):
    result = await db.execute(select(PortForward).where(PortForward.id == pf_id))
    pf = result.scalar_one_or_none()
    if not pf:
        raise HTTPException(status_code=404, detail="Port forward not found")
    if pf.service_kind != "raw":
        raise HTTPException(
            status_code=409,
            detail="HTTP edge routes cannot be changed through the raw forward endpoint",
        )

    # Snapshot old rule before applying changes (needed to remove the old iptables rule)
    old_active = pf.active
    old_pf_snapshot = snapshot_raw_forward(pf)

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
    _validate_raw_rule_values(
        protocol=changes.get("protocol", pf.protocol),
        public_port=changes.get("public_port", pf.public_port),
        public_port_end=changes.get("public_port_end", pf.public_port_end),
        destination_ip=changes.get("destination_ip", pf.destination_ip),
        destination_port=changes.get("destination_port", pf.destination_port),
        destination_port_end=changes.get(
            "destination_port_end", pf.destination_port_end
        ),
    )
    await _validate_raw_forward_target(
        next_attachment,
        changes.get("tunnel_server_ip_id", pf.tunnel_server_ip_id),
        changes.get("active", pf.active),
        db,
    )
    await _ensure_raw_forward_does_not_shadow_edge(
        db=db,
        attachment=next_attachment,
        protocol=changes.get("protocol", pf.protocol),
        public_port=changes.get("public_port", pf.public_port),
        public_port_end=changes.get("public_port_end", pf.public_port_end),
        active=changes.get("active", pf.active),
        exclude_port_forward_id=pf.id,
    )

    remove_old_rule = (
        pf.service_kind == "raw"
        and old_active
        and (rule_changed or changes.get("active") is False)
    )
    confirmed_removals: list[RawForwardRule] = []
    if remove_old_rule:
        old_public_ip = await resolve_public_ip(old_pf_snapshot, db)
        try:
            confirmed_removals = await remove_raw_forward_rules_confirmed(
                [RawForwardRule(old_pf_snapshot, old_public_ip)],
                db,
            )
        except RawForwardRemovalError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "The tunnel server did not confirm removal of the old raw "
                    f"forward rule ({exc.state.value}). The change was not saved."
                ),
            ) from exc

    for field, value in changes.items():
        setattr(pf, field, value)

    try:
        await db.commit()
    except IntegrityError:
        port = changes.get("public_port", pf.public_port)
        proto = changes.get("protocol", pf.protocol)
        await db.rollback()
        await restore_raw_forward_rules(confirmed_removals, db)
        raise HTTPException(
            status_code=409, detail=f"Port {port}/{proto} is already forwarded on this IP"
        )
    except Exception:
        await db.rollback()
        await restore_raw_forward_rules(confirmed_removals, db)
        raise

    await db.refresh(pf)

    try:
        if pf.service_kind == "raw" and pf.active and (
            rule_changed or not old_active
        ):
            await dispatch_raw_forward(pf, "iptables_add_forward", db)
    except Exception:
        await db.rollback()
        logger.exception(
            "Immediate raw forward replay failed for %s; desired state will "
            "replay on reconnect",
            pf.id,
        )

    emit_port_forward_changed()
    emit_tunnel_server_changed()
    return pf


@router.delete("/{pf_id}", status_code=204)
async def delete_port_forward(
    pf_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    pf = await db.scalar(select(PortForward).where(PortForward.id == pf_id))
    if pf is None:
        raise HTTPException(status_code=404, detail="Port forward not found")
    if pf.service_kind != "raw":
        raise HTTPException(
            status_code=409,
            detail="HTTP edge routes cannot be deleted through the raw forward endpoint",
        )
    server_id = await db.scalar(
        select(TunnelClientAttachment.tunnel_server_id).where(
            TunnelClientAttachment.id == pf.attachment_id
        )
    )
    if server_id is None:
        raise HTTPException(status_code=409, detail="Port forward attachment is missing")
    async with serialize_server_runtime_mutation(server_id, db):
        return await _delete_port_forward_locked(pf_id, db)


async def _delete_port_forward_locked(
    pf_id: str,
    db: AsyncSession,
):
    result = await db.execute(select(PortForward).where(PortForward.id == pf_id))
    pf = result.scalar_one_or_none()
    if not pf:
        raise HTTPException(status_code=404, detail="Port forward not found")
    if pf.service_kind != "raw":
        raise HTTPException(
            status_code=409,
            detail="HTTP edge routes cannot be deleted through the raw forward endpoint",
        )
    confirmed_removals: list[RawForwardRule] = []
    if pf.service_kind == "raw" and pf.active:
        snapshot = snapshot_raw_forward(pf)
        old_public_ip = await resolve_public_ip(snapshot, db)
        try:
            confirmed_removals = await remove_raw_forward_rules_confirmed(
                [RawForwardRule(snapshot, old_public_ip)],
                db,
            )
        except RawForwardRemovalError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "The tunnel server did not confirm removal of the raw "
                    f"forward rule ({exc.state.value}). The forward was preserved."
                ),
            ) from exc
    await db.delete(pf)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        await restore_raw_forward_rules(confirmed_removals, db)
        raise
    emit_port_forward_changed()
    emit_tunnel_server_changed()

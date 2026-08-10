import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_role, require_ops_role
from app.database import get_db
from app.realtime.events import emit_port_forward_changed, emit_tunnel_server_changed
from app.models.port_forward import PortForward
from app.models.gateway_lan_client import GatewayLanClient
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.user import User
from app.schemas.tunnel_server_ip import (
    TunnelServerIPCreate,
    TunnelServerIPRead,
    TunnelServerIPUpdate,
)
from app.services.tunnel_server_ops import (
    dispatch_reconcile_lan_snat,
    dispatch_wg_init,
    reconcile_server_attachments,
)
from app.services.port_forward_ops import (
    RawForwardRemovalError,
    RawForwardRule,
    dispatch_raw_forward,
    remove_raw_forward_rules_confirmed,
    restore_raw_forward_rules,
    serialize_server_runtime_mutation,
    snapshot_raw_forward,
)

logger = logging.getLogger(__name__)
router = APIRouter()

FORWARD_REMOVE_RESULT_TIMEOUT_SECONDS = 5.0


async def _serialize(ip: TunnelServerIP, db: AsyncSession) -> TunnelServerIPRead:
    """Build a TunnelServerIPRead with the live port_forward_count."""
    count = await db.scalar(
        select(func.count(PortForward.id)).where(PortForward.tunnel_server_ip_id == ip.id)
    )
    lan_pin_count = await db.scalar(
        select(func.count(GatewayLanClient.id)).where(
            GatewayLanClient.egress_tunnel_server_ip_id == ip.id
        )
    )
    return TunnelServerIPRead(
        id=ip.id,
        tunnel_server_id=ip.tunnel_server_id,
        address=ip.address,
        label=ip.label,
        is_primary=ip.is_primary,
        port_forward_count=int(count or 0),
        lan_egress_pin_count=int(lan_pin_count or 0),
        created_at=ip.created_at,
    )


async def _reconcile_endpoint_change(server_id: uuid.UUID, db: AsyncSession) -> None:
    """Best-effort immediate replay after committed endpoint changes."""
    try:
        server = await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))
        if server is None:
            return
        await dispatch_wg_init(server, db, replay_peers=False)
        await dispatch_reconcile_lan_snat(server, db)
        await reconcile_server_attachments(server.id, db)
    except Exception:
        await db.rollback()
        logger.exception(
            "Immediate endpoint reconcile failed for tunnel server %s; "
            "desired state will replay on reconnect",
            server_id,
        )


async def _has_attachments(server_id: uuid.UUID, db: AsyncSession) -> bool:
    count = await db.scalar(
        select(func.count(TunnelClientAttachment.id)).where(
            TunnelClientAttachment.tunnel_server_id == server_id
        )
    )
    return bool(count)


async def _reconcile_lan_snat(server_id: uuid.UUID, db: AsyncSession) -> None:
    """Best-effort full SNAT replay after a committed IP change."""
    try:
        server = await db.scalar(
            select(TunnelServer).where(TunnelServer.id == server_id)
        )
        if server is not None:
            await dispatch_reconcile_lan_snat(server, db)
    except Exception:
        await db.rollback()
        logger.exception(
            "Immediate LAN SNAT reconcile failed for tunnel server %s; current "
            "desired state will replay on reconnect",
            server_id,
        )


async def _forward_migration_plan(
    server_id: uuid.UUID,
    db: AsyncSession,
    *,
    inherited_old_ip: str | None = None,
    inherited_new_ip: str | None = None,
    changed_ip_id: uuid.UUID | None = None,
    bound_old_ip: str | None = None,
    bound_new_ip: str | None = None,
) -> list[tuple[uuid.UUID, str, str]]:
    """Return exact old/new IP work for active raw forwards."""
    rows = (
        await db.scalars(
            select(PortForward)
            .join(
                TunnelClientAttachment,
                PortForward.attachment_id == TunnelClientAttachment.id,
            )
            .where(
                TunnelClientAttachment.tunnel_server_id == server_id,
                PortForward.service_kind == "raw",
                PortForward.active.is_(True),
            )
        )
    ).all()
    plan: list[tuple[uuid.UUID, str, str]] = []
    for forward in rows:
        if (
            forward.tunnel_server_ip_id is None
            and inherited_new_ip
            and inherited_old_ip != inherited_new_ip
        ):
            plan.append((forward.id, inherited_old_ip or "", inherited_new_ip))
        elif (
            changed_ip_id is not None
            and forward.tunnel_server_ip_id == changed_ip_id
            and bound_old_ip
            and bound_new_ip
            and bound_old_ip != bound_new_ip
        ):
            plan.append((forward.id, bound_old_ip, bound_new_ip))
    return plan


async def _remove_old_forward_rules(
    plan: list[tuple[uuid.UUID, str, str]], db: AsyncSession
) -> list[RawForwardRule]:
    """Remove exact old-IP rules before changing desired endpoint state."""
    rules: list[RawForwardRule] = []
    for forward_id, old_ip, _ in plan:
        if not old_ip:
            continue
        forward = await db.scalar(
            select(PortForward).where(PortForward.id == forward_id)
        )
        if forward is None:
            continue
        rules.append(RawForwardRule(snapshot_raw_forward(forward), old_ip))
    try:
        return await remove_raw_forward_rules_confirmed(
            rules,
            db,
            timeout_seconds=FORWARD_REMOVE_RESULT_TIMEOUT_SECONDS,
        )
    except RawForwardRemovalError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "The tunnel server did not confirm old public-IP rule removal "
                f"within {FORWARD_REMOVE_RESULT_TIMEOUT_SECONDS:g} seconds "
                f"({exc.state.value}). The endpoint change was not saved."
            ),
        ) from exc


async def _best_effort_forward_rules(
    plan: list[tuple[uuid.UUID, str, str]],
    db: AsyncSession,
) -> None:
    """Add committed desired rules after an endpoint mutation."""
    for forward_id, _, new_ip in plan:
        try:
            forward = await db.scalar(
                select(PortForward).where(PortForward.id == forward_id)
            )
            if forward is None:
                continue
            await dispatch_raw_forward(
                forward,
                "iptables_add_forward",
                db,
                public_ip_override=new_ip,
            )
        except Exception:
            await db.rollback()
            logger.exception(
                "Immediate forward replay failed for port forward %s; current "
                "desired state will replay on reconnect",
                forward_id,
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
    _: User = Depends(require_ops_role),
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
    async with serialize_server_runtime_mutation(body.tunnel_server_id, db):
        return await _create_ip_locked(body, db)


async def _create_ip_locked(
    body: TunnelServerIPCreate,
    db: AsyncSession,
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
    duplicate = await db.scalar(
        select(TunnelServerIP.id).where(
            TunnelServerIP.tunnel_server_id == body.tunnel_server_id,
            TunnelServerIP.address == body.address,
        )
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Address {body.address} already exists on this tunnel server",
        )

    old_primary = await db.scalar(
        select(TunnelServerIP.address).where(
            TunnelServerIP.tunnel_server_id == body.tunnel_server_id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    forward_plan = (
        await _forward_migration_plan(
            server.id,
            db,
            inherited_old_ip=old_primary,
            inherited_new_ip=body.address,
        )
        if is_primary
        else []
    )
    confirmed_removals = await _remove_old_forward_rules(forward_plan, db)

    ip = TunnelServerIP(
        tunnel_server_id=body.tunnel_server_id,
        address=body.address,
        label=body.label,
        is_primary=False,  # write false first to avoid the partial unique index conflict
    )
    try:
        db.add(ip)
        await db.flush()
        if is_primary:
            await _demote_other_primaries(body.tunnel_server_id, ip.id, db)
            ip.is_primary = True
        await db.commit()
    except IntegrityError:
        await db.rollback()
        await restore_raw_forward_rules(confirmed_removals, db)
        raise HTTPException(
            status_code=409,
            detail="Conflict creating IP or setting the primary endpoint",
        )
    except Exception:
        await db.rollback()
        await restore_raw_forward_rules(confirmed_removals, db)
        raise

    await db.refresh(ip)

    if is_primary:
        await _reconcile_endpoint_change(server.id, db)
        await _best_effort_forward_rules(forward_plan, db)
        if forward_plan:
            emit_port_forward_changed()

    ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.id == ip.id))
    if ip is None:
        raise HTTPException(status_code=404, detail="IP not found after creation")

    emit_tunnel_server_changed()
    return await _serialize(ip, db)


@router.patch("/{ip_id}", response_model=TunnelServerIPRead)
async def update_ip(
    ip_id: str,
    body: TunnelServerIPUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    server_id = await db.scalar(
        select(TunnelServerIP.tunnel_server_id).where(TunnelServerIP.id == ip_id)
    )
    if server_id is None:
        raise HTTPException(status_code=404, detail="IP not found")
    async with serialize_server_runtime_mutation(server_id, db):
        return await _update_ip_locked(ip_id, body, db)


async def _update_ip_locked(
    ip_id: str,
    body: TunnelServerIPUpdate,
    db: AsyncSession,
):
    ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.id == ip_id))
    if not ip:
        raise HTTPException(status_code=404, detail="IP not found")
    server = await db.scalar(select(TunnelServer).where(TunnelServer.id == ip.tunnel_server_id))

    was_primary = ip.is_primary
    old_address = ip.address
    promoting = body.is_primary is True and not was_primary
    demoting = body.is_primary is False and ip.is_primary

    if demoting and await _has_attachments(ip.tunnel_server_id, db):
        raise HTTPException(
            status_code=409,
            detail=(
                "Cannot remove the primary endpoint while tunnel clients are attached. "
                "Set another IP as primary first."
            ),
        )

    changes = body.model_dump(exclude_unset=True)
    if "is_primary" in changes:
        # Handle primary flips below; don't apply via setattr.
        changes.pop("is_primary")

    new_address = changes.get("address", old_address)
    old_primary = await db.scalar(
        select(TunnelServerIP.address).where(
            TunnelServerIP.tunnel_server_id == ip.tunnel_server_id,
            TunnelServerIP.is_primary.is_(True),
        )
    )
    endpoint_will_change = promoting or (
        was_primary and "address" in changes and new_address != old_address
    )
    address_will_change = "address" in changes and new_address != old_address
    forward_plan = await _forward_migration_plan(
        ip.tunnel_server_id,
        db,
        inherited_old_ip=old_primary if endpoint_will_change else None,
        inherited_new_ip=new_address if endpoint_will_change else None,
        changed_ip_id=ip.id if address_will_change else None,
        bound_old_ip=old_address if address_will_change else None,
        bound_new_ip=new_address if address_will_change else None,
    )
    confirmed_removals = await _remove_old_forward_rules(forward_plan, db)

    try:
        for field, value in changes.items():
            setattr(ip, field, value)
        if promoting:
            await _demote_other_primaries(ip.tunnel_server_id, ip.id, db)
            ip.is_primary = True
        elif demoting:
            ip.is_primary = False
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        await restore_raw_forward_rules(confirmed_removals, db)
        raise HTTPException(status_code=409, detail=str(exc.orig))
    except Exception:
        await db.rollback()
        await restore_raw_forward_rules(confirmed_removals, db)
        raise

    await db.refresh(ip)
    endpoint_changed = promoting or (
        was_primary and "address" in changes and ip.address != old_address
    )
    if endpoint_changed and server:
        await _reconcile_endpoint_change(server.id, db)
    if address_will_change and not endpoint_changed and server:
        await _reconcile_lan_snat(server.id, db)
    if forward_plan:
        await _best_effort_forward_rules(forward_plan, db)
        emit_port_forward_changed()

    ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.id == ip.id))
    if ip is None:
        raise HTTPException(status_code=404, detail="IP not found after update")

    emit_tunnel_server_changed()
    return await _serialize(ip, db)


@router.delete("/{ip_id}", status_code=204)
async def delete_ip(
    ip_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    server_id = await db.scalar(
        select(TunnelServerIP.tunnel_server_id).where(TunnelServerIP.id == ip_id)
    )
    if server_id is None:
        raise HTTPException(status_code=404, detail="IP not found")
    async with serialize_server_runtime_mutation(server_id, db):
        return await _delete_ip_locked(ip_id, db)


async def _delete_ip_locked(
    ip_id: str,
    db: AsyncSession,
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

    lan_pins = await db.scalar(
        select(func.count(GatewayLanClient.id)).where(
            GatewayLanClient.egress_tunnel_server_ip_id == ip.id
        )
    )
    if lan_pins and lan_pins > 0:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{lan_pins} LAN egress pin(s) reference this IP. "
                "Move or clear them before deletion."
            ),
        )

    was_primary = ip.is_primary

    if was_primary and await _has_attachments(ip.tunnel_server_id, db):
        raise HTTPException(
            status_code=409,
            detail=(
                "Cannot delete the primary endpoint while tunnel clients are attached. "
                "Set another IP as primary first."
            ),
        )

    await db.delete(ip)
    await db.commit()

    emit_tunnel_server_changed()

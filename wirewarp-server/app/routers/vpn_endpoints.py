"""Admin CRUD for VPN endpoints — one per gateway.

Also hosts the per-(user, endpoint) permission endpoints:
  GET    /{eid}/permissions                       — admin sheet payload
  GET    /{eid}/users/{uid}/permissions           — single user's rules
  PUT    /{eid}/users/{uid}/permissions           — replace; reissues iptables

Permissions live on `(user, endpoint)`. Every device profile a user has
on that endpoint inherits this set; on PUT we walk every profile and
dispatch `vpn_peer_update_rules` so the gateway's iptables match.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete as sa_delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import log_auth_event, require_role
from app.database import get_db
from app.models.tunnel_client import TunnelClient
from app.models.user import User
from app.models.vpn_endpoint import VpnEndpoint
from app.models.vpn_permission import VpnPermission
from app.models.vpn_profile import VpnProfile
from app.schemas.vpn import (
    VpnEndpointCreate,
    VpnEndpointRead,
    VpnEndpointUpdate,
    VpnPermissionInput,
    VpnPermissionRead,
    VpnUserPermissionsRead,
)
from app.services.network_alloc import allocate_vpn_network
from app.services.vpn_ops import (
    dispatch_vpn_endpoint_down,
    dispatch_vpn_endpoint_up,
    dispatch_vpn_peer_update_rules,
    load_user_endpoint_permissions,
)


router = APIRouter()


@router.get("", response_model=list[VpnEndpointRead])
async def list_endpoints(
    db: AsyncSession = Depends(get_db),
    # Read-only list is accessible to vpn_user too — MyVpn uses this to
    # populate the "issue a profile for" dropdown. Mutating endpoints
    # below stay admin/operator only.
    _: User = Depends(require_role("admin", "operator", "viewer", "vpn_user")),
):
    rows = (await db.execute(select(VpnEndpoint).order_by(VpnEndpoint.created_at.asc()))).scalars().all()
    return list(rows)


@router.get("/{endpoint_id}", response_model=VpnEndpointRead)
async def get_endpoint(
    endpoint_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator", "viewer", "vpn_user")),
):
    ep = await db.get(VpnEndpoint, endpoint_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="VPN endpoint not found")
    return ep


@router.post("", response_model=VpnEndpointRead, status_code=201)
async def create_endpoint(
    body: VpnEndpointCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    client = await db.get(TunnelClient, body.tunnel_client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    if not client.is_gateway:
        raise HTTPException(
            status_code=400,
            detail="VPN endpoints can only be hosted on gateway clients",
        )

    network = await allocate_vpn_network(db)
    ep = VpnEndpoint(
        tunnel_client_id=body.tunnel_client_id,
        wg_interface=body.wg_interface,
        listen_port=body.listen_port,
        vpn_network=network,
        public_endpoint=body.public_endpoint,
        dns_servers=body.dns_servers,
        enabled=True,
    )
    db.add(ep)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=400,
            detail="A VPN endpoint already exists for this tunnel client",
        )
    await db.refresh(ep)

    # Fire-and-forget: agent may be offline, replay on reconnect handles it.
    await dispatch_vpn_endpoint_up(ep, db, actor_user_id=actor.id)
    await log_auth_event(
        db,
        "vpn.endpoint.create",
        actor_user_id=actor.id,
        details={
            "endpoint_id": str(ep.id),
            "tunnel_client_id": str(ep.tunnel_client_id),
            "vpn_network": ep.vpn_network,
            "listen_port": ep.listen_port,
        },
    )
    return ep


@router.patch("/{endpoint_id}", response_model=VpnEndpointRead)
async def update_endpoint(
    endpoint_id: uuid.UUID,
    body: VpnEndpointUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    ep = await db.get(VpnEndpoint, endpoint_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="VPN endpoint not found")

    payload = body.model_dump(exclude_unset=True)
    listen_port_changed = "listen_port" in payload and payload["listen_port"] != ep.listen_port
    enabled_changed = "enabled" in payload and payload["enabled"] != ep.enabled

    for field, val in payload.items():
        setattr(ep, field, val)
    await db.commit()
    await db.refresh(ep)

    # Re-issue endpoint_up if anything changed that the agent cares about.
    if listen_port_changed or "dns_servers" in payload:
        await dispatch_vpn_endpoint_up(ep, db, actor_user_id=actor.id)
    if enabled_changed and not ep.enabled:
        await dispatch_vpn_endpoint_down(ep, db, actor_user_id=actor.id)
    elif enabled_changed and ep.enabled:
        await dispatch_vpn_endpoint_up(ep, db, actor_user_id=actor.id)

    await log_auth_event(
        db,
        "vpn.endpoint.update",
        actor_user_id=actor.id,
        details={"endpoint_id": str(ep.id), "changes": list(payload.keys())},
    )
    return ep


@router.delete("/{endpoint_id}", status_code=204)
async def delete_endpoint(
    endpoint_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    ep = await db.get(VpnEndpoint, endpoint_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="VPN endpoint not found")
    await dispatch_vpn_endpoint_down(ep, db, actor_user_id=actor.id)
    await db.delete(ep)
    await db.commit()
    await log_auth_event(
        db,
        "vpn.endpoint.delete",
        actor_user_id=actor.id,
        details={"endpoint_id": str(endpoint_id)},
    )


# ---- per-user permissions on this endpoint ----


class PermissionsBody(BaseModel):
    permissions: list[VpnPermissionInput]


@router.get("/{endpoint_id}/permissions", response_model=list[VpnUserPermissionsRead])
async def list_endpoint_permissions(
    endpoint_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    """Sheet payload — every vpn_enabled user with their current
    per-endpoint rule set + profile count. Users without permissions yet
    appear with an empty `permissions` list so the admin can pre-provision
    them."""
    ep = await db.get(VpnEndpoint, endpoint_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="VPN endpoint not found")

    users = (
        await db.execute(
            select(User).where(User.vpn_enabled == True).order_by(User.username)  # noqa: E712
        )
    ).scalars().all()

    perm_rows = (
        await db.execute(
            select(VpnPermission).where(
                VpnPermission.vpn_endpoint_id == endpoint_id
            )
        )
    ).scalars().all()
    by_user: dict[uuid.UUID, list[VpnPermission]] = {}
    for p in perm_rows:
        by_user.setdefault(p.user_id, []).append(p)

    profile_counts = dict(
        (
            await db.execute(
                select(VpnProfile.user_id, func.count(VpnProfile.id))
                .where(VpnProfile.vpn_endpoint_id == endpoint_id)
                .group_by(VpnProfile.user_id)
            )
        ).all()
    )

    return [
        VpnUserPermissionsRead(
            user_id=u.id,
            username=u.username,
            auth_provider=u.auth_provider,
            profile_count=int(profile_counts.get(u.id, 0)),
            permissions=[
                VpnPermissionRead.model_validate(p, from_attributes=True)
                for p in by_user.get(u.id, [])
            ],
        )
        for u in users
    ]


@router.get(
    "/{endpoint_id}/users/{user_id}/permissions",
    response_model=list[VpnPermissionRead],
)
async def get_user_permissions(
    endpoint_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    perms = await load_user_endpoint_permissions(user_id, endpoint_id, db)
    return list(perms)


@router.put(
    "/{endpoint_id}/users/{user_id}/permissions",
    response_model=list[VpnPermissionRead],
)
async def replace_user_permissions(
    endpoint_id: uuid.UUID,
    user_id: uuid.UUID,
    body: PermissionsBody,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin", "operator")),
):
    """Replace the user's full permission set on this endpoint, then
    push the new rule list to every profile that user has on the
    endpoint via dispatch_vpn_peer_update_rules. Setting permissions
    BEFORE the user has any profiles is the intended flow — the rules
    are picked up at profile-create time."""
    ep = await db.get(VpnEndpoint, endpoint_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="VPN endpoint not found")
    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    await db.execute(
        sa_delete(VpnPermission).where(
            VpnPermission.user_id == user_id,
            VpnPermission.vpn_endpoint_id == endpoint_id,
        )
    )
    for entry in body.permissions:
        db.add(
            VpnPermission(
                user_id=user_id,
                vpn_endpoint_id=endpoint_id,
                destination=entry.destination,
                protocol=entry.protocol,
                port_range_start=entry.port_range_start,
                port_range_end=entry.port_range_end,
            )
        )
    await db.commit()

    perms = await load_user_endpoint_permissions(user_id, endpoint_id, db)

    # Reapply iptables on the gateway for every profile this user has on
    # this endpoint. Each profile is one peer with the same rule set.
    profiles = (
        await db.execute(
            select(VpnProfile).where(
                VpnProfile.user_id == user_id,
                VpnProfile.vpn_endpoint_id == endpoint_id,
            )
        )
    ).scalars().all()
    for profile in profiles:
        await dispatch_vpn_peer_update_rules(
            profile, ep, perms, db, actor_user_id=actor.id
        )

    await log_auth_event(
        db,
        "vpn.permission.change",
        actor_user_id=actor.id,
        details={
            "endpoint_id": str(endpoint_id),
            "target_user_id": str(user_id),
            "rule_count": len(perms),
            "profile_count": len(profiles),
        },
    )
    return list(perms)

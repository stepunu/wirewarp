"""VPN profile management.

Two role bands:
  * `/me*` — current user's own profiles. Requires `vpn_enabled` AND a
    permission set already pre-provisioned for this user on the chosen
    endpoint (admins manage permissions via the vpn-endpoints router).
  * Admin / operator endpoints — list + CRUD any user's profiles.

Private keys are generated server-side and returned exactly once (in the
rendered .conf and a separate field for QR rendering). The server never
stores the private key.

Permissions live on `(user, endpoint)`, NOT on individual profiles. Each
device profile a user creates inherits the rule set in place at create
time AND tracks subsequent edits (the `vpn_peer_update_rules` dispatch
walks every profile of that (user, endpoint) when permissions change —
see `app/routers/vpn_endpoints.py`).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, log_auth_event, require_role
from app.database import get_db
from app.models.user import User
from app.models.vpn_endpoint import VpnEndpoint
from app.models.vpn_profile import VpnProfile
from app.schemas.vpn import (
    VpnProfileAdminCreate,
    VpnProfileIssued,
    VpnProfileRead,
    VpnProfileSelfCreate,
    VpnProfileUpdate,
)
from app.services.network_alloc import allocate_vpn_peer_ip
from app.services.vpn_ops import (
    dispatch_vpn_peer_add,
    dispatch_vpn_peer_remove,
    generate_keypair,
    generate_psk,
    load_user_endpoint_permissions,
    render_conf,
)


router = APIRouter()


def _ensure_vpn_enabled(user: User) -> None:
    if not user.vpn_enabled:
        raise HTTPException(
            status_code=403,
            detail="VPN access is not enabled for your account. Ask an admin or check your IdP group.",
        )


async def _create_profile(
    db: AsyncSession,
    *,
    user: User,
    endpoint_id: uuid.UUID,
    label: str,
    tunnel_mode: str,
    actor: User,
    require_permissions: bool,
) -> VpnProfileIssued:
    """Shared by self-serve and admin create. Allocates the tunnel IP,
    generates keypair + PSK, persists the profile, looks up the user's
    pre-provisioned permission set on this endpoint, and dispatches
    `vpn_peer_add` to the gateway agent.
    """
    endpoint = await db.get(VpnEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="VPN endpoint not found")
    if not endpoint.enabled:
        raise HTTPException(status_code=400, detail="VPN endpoint is disabled")
    if tunnel_mode == "split" and not endpoint.remote_subnets:
        raise HTTPException(
            status_code=400,
            detail="Split profiles require at least one endpoint remote subnet",
        )

    permissions = await load_user_endpoint_permissions(user.id, endpoint.id, db)
    if require_permissions and not permissions:
        raise HTTPException(
            status_code=403,
            detail=(
                "No VPN permissions configured for your account on this endpoint. "
                "Ask an admin or operator to grant access first (VPN endpoints → Permissions)."
            ),
        )

    tunnel_ip = await allocate_vpn_peer_ip(endpoint.id, db)
    keys = generate_keypair()
    psk = generate_psk()

    profile = VpnProfile(
        user_id=user.id,
        vpn_endpoint_id=endpoint.id,
        label=label,
        tunnel_ip=tunnel_ip,
        wg_public_key=keys.public_key,
        wg_psk=psk,
        tunnel_mode=tunnel_mode,
        issued_route_revision=(
            endpoint.route_revision if tunnel_mode == "split" else None
        ),
        endpoint=endpoint,
    )
    db.add(profile)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Tunnel IP collision — try again")
    await db.refresh(profile)

    config_text = render_conf(
        endpoint=endpoint,
        profile=profile,
        permissions=permissions,
        private_key=keys.private_key,
    )

    await dispatch_vpn_peer_add(
        profile=profile,
        endpoint=endpoint,
        permissions=permissions,
        db=db,
        actor_user_id=actor.id,
    )
    await log_auth_event(
        db,
        "vpn.profile.create",
        actor_user_id=actor.id,
        details={
            "profile_id": str(profile.id),
            "user_id": str(user.id),
            "endpoint_id": str(endpoint.id),
            "label": profile.label,
            "tunnel_mode": profile.tunnel_mode,
            "rule_count": len(permissions),
        },
    )

    return VpnProfileIssued(
        id=profile.id,
        user_id=profile.user_id,
        vpn_endpoint_id=profile.vpn_endpoint_id,
        label=profile.label,
        tunnel_ip=profile.tunnel_ip,
        wg_public_key=profile.wg_public_key,
        tunnel_mode=profile.tunnel_mode,  # type: ignore[arg-type]
        issued_route_revision=profile.issued_route_revision,
        config_route_status=profile.config_route_status,  # type: ignore[arg-type]
        last_handshake_at=None,
        created_at=profile.created_at,
        config_text=config_text,
        wg_private_key=keys.private_key,
        permissions=[
            {
                "id": p.id,
                "user_id": p.user_id,
                "vpn_endpoint_id": p.vpn_endpoint_id,
                "destination": p.destination,
                "protocol": p.protocol,
                "port_range_start": p.port_range_start,
                "port_range_end": p.port_range_end,
            }
            for p in permissions
        ],
    )


async def _regenerate_keys(
    db: AsyncSession,
    *,
    profile: VpnProfile,
    actor: User,
) -> VpnProfileIssued:
    endpoint = await db.get(VpnEndpoint, profile.vpn_endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="VPN endpoint not found")
    permissions = await load_user_endpoint_permissions(
        profile.user_id, profile.vpn_endpoint_id, db
    )

    old_pubkey = profile.wg_public_key
    keys = generate_keypair()
    profile.wg_public_key = keys.public_key
    profile.wg_psk = generate_psk()
    if profile.tunnel_mode == "split":
        profile.issued_route_revision = endpoint.route_revision
    await db.commit()
    await db.refresh(profile)

    placeholder = VpnProfile(
        id=profile.id,
        user_id=profile.user_id,
        vpn_endpoint_id=profile.vpn_endpoint_id,
        label=profile.label,
        tunnel_ip=profile.tunnel_ip,
        wg_public_key=old_pubkey,
        wg_psk="",
        tunnel_mode=profile.tunnel_mode,
        issued_route_revision=profile.issued_route_revision,
    )
    await dispatch_vpn_peer_remove(placeholder, endpoint, db, actor_user_id=actor.id)
    await dispatch_vpn_peer_add(
        profile=profile,
        endpoint=endpoint,
        permissions=permissions,
        db=db,
        actor_user_id=actor.id,
    )
    await log_auth_event(
        db,
        "vpn.profile.regenerate",
        actor_user_id=actor.id,
        details={"profile_id": str(profile.id)},
    )

    config_text = render_conf(
        endpoint=endpoint,
        profile=profile,
        permissions=permissions,
        private_key=keys.private_key,
    )
    return VpnProfileIssued(
        id=profile.id,
        user_id=profile.user_id,
        vpn_endpoint_id=profile.vpn_endpoint_id,
        label=profile.label,
        tunnel_ip=profile.tunnel_ip,
        wg_public_key=profile.wg_public_key,
        tunnel_mode=profile.tunnel_mode,  # type: ignore[arg-type]
        issued_route_revision=profile.issued_route_revision,
        config_route_status=profile.config_route_status,  # type: ignore[arg-type]
        last_handshake_at=profile.last_handshake_at,
        created_at=profile.created_at,
        config_text=config_text,
        wg_private_key=keys.private_key,
        permissions=[
            {
                "id": p.id,
                "user_id": p.user_id,
                "vpn_endpoint_id": p.vpn_endpoint_id,
                "destination": p.destination,
                "protocol": p.protocol,
                "port_range_start": p.port_range_start,
                "port_range_end": p.port_range_end,
            }
            for p in permissions
        ],
    )


# ---- self-serve endpoints ----


@router.get("/me", response_model=list[VpnProfileRead])
async def list_my_profiles(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_vpn_enabled(current_user)
    rows = (
        await db.execute(
            select(VpnProfile)
            .where(VpnProfile.user_id == current_user.id)
            .order_by(VpnProfile.created_at.asc())
        )
    ).scalars().all()
    return list(rows)


@router.post("/me", response_model=VpnProfileIssued, status_code=201)
async def create_my_profile(
    body: VpnProfileSelfCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_vpn_enabled(current_user)
    return await _create_profile(
        db,
        user=current_user,
        endpoint_id=body.vpn_endpoint_id,
        label=body.label,
        tunnel_mode=body.tunnel_mode,
        actor=current_user,
        require_permissions=True,
    )


@router.post("/me/{profile_id}/regenerate", response_model=VpnProfileIssued)
async def regenerate_my_profile(
    profile_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_vpn_enabled(current_user)
    profile = await db.get(VpnProfile, profile_id)
    if profile is None or profile.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="VPN profile not found")
    return await _regenerate_keys(db, profile=profile, actor=current_user)


@router.delete("/me/{profile_id}", status_code=204)
async def delete_my_profile(
    profile_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_vpn_enabled(current_user)
    profile = await db.get(VpnProfile, profile_id)
    if profile is None or profile.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="VPN profile not found")
    endpoint = await db.get(VpnEndpoint, profile.vpn_endpoint_id)
    if endpoint:
        await dispatch_vpn_peer_remove(profile, endpoint, db, actor_user_id=current_user.id)
    await db.delete(profile)
    await db.commit()
    await log_auth_event(
        db,
        "vpn.profile.delete",
        actor_user_id=current_user.id,
        details={"profile_id": str(profile_id), "self_serve": True},
    )


# ---- admin / operator endpoints ----


@router.get("", response_model=list[VpnProfileRead])
async def list_profiles(
    user_id: uuid.UUID | None = Query(default=None),
    endpoint_id: uuid.UUID | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    q = select(VpnProfile)
    if user_id is not None:
        q = q.where(VpnProfile.user_id == user_id)
    if endpoint_id is not None:
        q = q.where(VpnProfile.vpn_endpoint_id == endpoint_id)
    q = q.order_by(VpnProfile.created_at.asc())
    rows = (await db.execute(q)).scalars().all()
    return list(rows)


@router.post("", response_model=VpnProfileIssued, status_code=201)
async def create_profile(
    body: VpnProfileAdminCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    user = await db.get(User, body.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    # Admin can override the "permissions must exist first" gate so they
    # can create a placeholder profile and define permissions afterwards
    # without locking themselves out — useful during initial bring-up.
    return await _create_profile(
        db,
        user=user,
        endpoint_id=body.vpn_endpoint_id,
        label=body.label,
        tunnel_mode=body.tunnel_mode,
        actor=actor,
        require_permissions=False,
    )


@router.patch("/{profile_id}", response_model=VpnProfileRead)
async def update_profile(
    profile_id: uuid.UUID,
    body: VpnProfileUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    profile = await db.get(VpnProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="VPN profile not found")
    payload = body.model_dump(exclude_unset=True)
    for field, val in payload.items():
        setattr(profile, field, val)
    await db.commit()
    await db.refresh(profile)

    await log_auth_event(
        db,
        "vpn.profile.update",
        actor_user_id=actor.id,
        details={"profile_id": str(profile.id), "changes": list(payload.keys())},
    )
    return profile


@router.delete("/{profile_id}", status_code=204)
async def delete_profile(
    profile_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    profile = await db.get(VpnProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="VPN profile not found")
    endpoint = await db.get(VpnEndpoint, profile.vpn_endpoint_id)
    if endpoint:
        await dispatch_vpn_peer_remove(profile, endpoint, db, actor_user_id=actor.id)
    await db.delete(profile)
    await db.commit()
    await log_auth_event(
        db,
        "vpn.profile.delete",
        actor_user_id=actor.id,
        details={"profile_id": str(profile_id), "self_serve": False},
    )

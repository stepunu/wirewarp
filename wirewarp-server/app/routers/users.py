"""Admin user management.

All endpoints require role=admin. Local users get a password set; OIDC/
LDAP users are JIT-created on first login and only their role/is_active
can be changed here.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_password, log_auth_event, require_role
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserAdminUpdate, UserCreate, UserRead


router = APIRouter()


@router.get("", response_model=list[UserRead])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    rows = (await db.execute(select(User).order_by(User.created_at.asc()))).scalars().all()
    return list(rows)


@router.post("", response_model=UserRead, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    if await db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(status_code=400, detail="Username already exists")
    if await db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status_code=400, detail="Email already exists")
    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        is_active=True,
        auth_provider="local",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await log_auth_event(
        db,
        "auth.user_create",
        actor_user_id=actor.id,
        details={"username": user.username, "role": user.role},
    )
    return user


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: uuid.UUID,
    body: UserAdminUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    changes: dict = {}
    if body.role is not None and body.role != user.role:
        user.role = body.role
        changes["role"] = body.role
    if body.is_active is not None and body.is_active != user.is_active:
        if not body.is_active and user.id == actor.id:
            raise HTTPException(status_code=400, detail="Cannot disable yourself")
        user.is_active = body.is_active
        changes["is_active"] = body.is_active
    if body.vpn_enabled is not None and body.vpn_enabled != user.vpn_enabled:
        if user.auth_provider != "local":
            raise HTTPException(
                status_code=400,
                detail="VPN access for OIDC/LDAP users is driven by the `vpn_group` config field, not by this toggle",
            )
        user.vpn_enabled = body.vpn_enabled
        changes["vpn_enabled"] = body.vpn_enabled

    if changes:
        await db.commit()
        await db.refresh(user)
        if "vpn_enabled" in changes:
            event = "auth.user.vpn_change"
        elif "is_active" in changes:
            event = "auth.user_disable"
        else:
            event = "auth.role_change"
        await log_auth_event(
            db,
            event,
            actor_user_id=actor.id,
            details={"target_user": user.username, **changes},
        )
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    target_username = user.username
    await db.delete(user)
    await db.commit()
    await log_auth_event(
        db,
        "auth.user_delete",
        actor_user_id=actor.id,
        details={"target_user": target_username},
    )

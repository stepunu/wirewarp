"""LDAP login endpoint."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import create_access_token, log_auth_event
from app.database import get_db
from app.models.system_settings import SystemSettings
from app.models.user import User
from app.schemas.user import TokenResponse
from app.services.ldap_auth import ldap_authenticate
from app.services.secrets import decrypt_ldap_config


router = APIRouter()


class LdapLoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login", response_model=TokenResponse)
async def ldap_login(body: LdapLoginRequest, db: AsyncSession = Depends(get_db)):
    row = await db.get(SystemSettings, 1)
    if not row or row.auth_provider != "ldap" or not row.ldap_config:
        raise HTTPException(status_code=400, detail="LDAP not configured")
    cfg = decrypt_ldap_config(row.ldap_config) or {}

    try:
        result = await ldap_authenticate(body.username, body.password, cfg)
    except Exception as exc:  # noqa: BLE001
        await log_auth_event(
            db,
            "auth.login.failure",
            details={"method": "ldap", "reason": str(exc)[:200]},
            success=False,
        )
        raise HTTPException(status_code=502, detail=f"LDAP error: {exc}")

    if result is None:
        await log_auth_event(
            db,
            "auth.login.failure",
            details={"method": "ldap", "username": body.username},
            success=False,
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user = await _jit_upsert(
        db,
        external_id=result.user_dn,
        username=body.username,
        email=f"{body.username}@ldap.local",
        role=result.role,
        vpn_enabled=result.vpn_enabled,
    )
    if not user.is_active:
        await log_auth_event(
            db,
            "auth.login.failure",
            actor_user_id=user.id,
            details={"reason": "disabled", "method": "ldap"},
            success=False,
        )
        raise HTTPException(status_code=401, detail="User disabled")

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    await log_auth_event(
        db,
        "auth.login.success",
        actor_user_id=user.id,
        details={"method": "ldap"},
    )
    return TokenResponse(access_token=create_access_token(user.username))


async def _jit_upsert(
    db: AsyncSession,
    *,
    external_id: str,
    username: str,
    email: str,
    role: str,
    vpn_enabled: bool = False,
) -> User:
    result = await db.execute(
        select(User).where(
            User.auth_provider == "ldap", User.external_id == external_id
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        base = username
        suffix = 0
        while True:
            candidate = base if suffix == 0 else f"{base}-ldap{suffix}"
            existing = await db.scalar(select(User).where(User.username == candidate))
            if not existing:
                username = candidate
                break
            suffix += 1
        user = User(
            username=username,
            email=email,
            password_hash=None,
            role=role,
            is_active=True,
            auth_provider="ldap",
            external_id=external_id,
            vpn_enabled=vpn_enabled,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        await log_auth_event(
            db,
            "auth.user_create",
            actor_user_id=user.id,
            details={"provider": "ldap", "role": role, "jit": True, "vpn_enabled": vpn_enabled},
        )
    else:
        changed = False
        if user.role != role:
            user.role = role
            changed = True
        if user.vpn_enabled != vpn_enabled:
            user.vpn_enabled = vpn_enabled
            changed = True
            await log_auth_event(
                db,
                "auth.user.vpn_change",
                actor_user_id=user.id,
                details={"provider": "ldap", "vpn_enabled": vpn_enabled, "jit": True},
            )
        if changed:
            await db.commit()
    return user

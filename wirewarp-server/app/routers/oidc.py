"""OIDC login + callback endpoints."""
from __future__ import annotations

import secrets as _secrets
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import create_access_token, log_auth_event
from app.database import get_db
from app.models.oauth_state import OAuthState
from app.models.system_settings import SystemSettings
from app.models.user import User
from app.services.oidc_auth import (
    claims_grant_vpn,
    discover,
    exchange_code_for_userinfo,
    map_claims_to_role,
)
from app.services.secrets import decrypt_oidc_config


router = APIRouter()


_STATE_TTL = timedelta(minutes=5)


async def _load_config(db: AsyncSession) -> dict:
    row = await db.get(SystemSettings, 1)
    if not row or row.auth_provider != "oidc" or not row.oidc_config:
        raise HTTPException(status_code=400, detail="OIDC not configured")
    return decrypt_oidc_config(row.oidc_config) or {}


async def _prune_states(db: AsyncSession) -> None:
    cutoff = datetime.now(timezone.utc) - _STATE_TTL
    await db.execute(
        OAuthState.__table__.delete().where(OAuthState.created_at < cutoff)
    )


@router.get("/login")
async def oidc_login(request: Request, db: AsyncSession = Depends(get_db)):
    cfg = await _load_config(db)
    meta = await discover(cfg["issuer"])
    auth_endpoint = meta["authorization_endpoint"]

    state = _secrets.token_urlsafe(32)
    nonce = _secrets.token_urlsafe(32)
    db.add(OAuthState(state=state, nonce=nonce))
    await _prune_states(db)
    await db.commit()

    scopes = cfg.get("scopes") or ["openid", "email", "profile"]
    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_url"],
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
    }
    return RedirectResponse(f"{auth_endpoint}?{urlencode(params)}")


@router.get("/callback")
async def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    if error or not code or not state:
        raise HTTPException(status_code=400, detail=f"OIDC error: {error or 'missing code/state'}")

    state_row = await db.get(OAuthState, state)
    if state_row is None:
        raise HTTPException(status_code=400, detail="Unknown OIDC state")
    if state_row.created_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc) - _STATE_TTL:
        await db.delete(state_row)
        await db.commit()
        raise HTTPException(status_code=400, detail="Expired OIDC state")
    expected_nonce = state_row.nonce
    await db.delete(state_row)
    await db.commit()

    cfg = await _load_config(db)
    try:
        claims = await exchange_code_for_userinfo(cfg, code, state, expected_nonce)
    except Exception as exc:  # noqa: BLE001
        await log_auth_event(
            db,
            "auth.login.failure",
            details={"method": "oidc", "reason": str(exc)[:200]},
            success=False,
        )
        raise HTTPException(status_code=400, detail=f"OIDC exchange failed: {exc}")

    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=400, detail="OIDC claims missing sub")

    role_claim = cfg.get("role_claim", "groups")
    role = map_claims_to_role(
        claims,
        role_claim,
        cfg.get("claim_role_map") or {},
        cfg.get("default_role", "viewer"),
    )
    vpn_enabled = claims_grant_vpn(claims, role_claim, cfg.get("vpn_group"))

    username = (
        claims.get(cfg.get("username_claim", "preferred_username"))
        or claims.get("preferred_username")
        or claims.get("email")
        or f"oidc-{sub}"
    )
    email = claims.get(cfg.get("email_claim", "email")) or f"{username}@oidc.local"

    user = await _jit_upsert(
        db,
        provider="oidc",
        external_id=str(sub),
        username=str(username),
        email=str(email),
        role=role,
        vpn_enabled=vpn_enabled,
    )
    if not user.is_active:
        await log_auth_event(
            db,
            "auth.login.failure",
            actor_user_id=user.id,
            details={"reason": "disabled", "method": "oidc"},
            success=False,
        )
        raise HTTPException(status_code=401, detail="User disabled")

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    await log_auth_event(
        db,
        "auth.login.success",
        actor_user_id=user.id,
        details={"method": "oidc"},
    )

    token = create_access_token(user.username)
    return RedirectResponse(f"/#token={token}")


async def _jit_upsert(
    db: AsyncSession,
    *,
    provider: str,
    external_id: str,
    username: str,
    email: str,
    role: str,
    vpn_enabled: bool = False,
) -> User:
    """Find-or-create a user keyed on `(auth_provider, external_id)`.
    Updates the role and VPN access on every login so changes in the
    IdP propagate.
    """
    result = await db.execute(
        select(User).where(
            User.auth_provider == provider, User.external_id == external_id
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        # Avoid clashing with an existing local user that happens to share
        # the username/email — append the provider tag if needed.
        base_username = username
        suffix = 0
        while True:
            candidate = base_username if suffix == 0 else f"{base_username}-{provider}{suffix}"
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
            auth_provider=provider,
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
            details={"provider": provider, "role": role, "jit": True, "vpn_enabled": vpn_enabled},
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
                details={"provider": provider, "vpn_enabled": vpn_enabled, "jit": True},
            )
        if changed:
            await db.commit()
    return user

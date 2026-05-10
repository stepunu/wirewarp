from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import log_auth_event, require_role
from app.database import get_db
from app.models.system_settings import SystemSettings
from app.models.user import User
from app.schemas.system_settings import (
    AuthTestRequest,
    AuthTestResponse,
    SystemSettingsRead,
    SystemSettingsUpdate,
)
from app.services.ldap_auth import ldap_test_bind
from app.services.oidc_auth import discover
from app.services.secrets import (
    encrypt_ldap_config,
    encrypt_oidc_config,
    encrypt_secret,
    looks_like_fernet,
)


router = APIRouter()


async def _get_or_create(db: AsyncSession) -> SystemSettings:
    row = await db.get(SystemSettings, 1)
    if not row:
        row = SystemSettings(id=1)
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


@router.get("", response_model=SystemSettingsRead)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    return await _get_or_create(db)


def _merge_provider_config(
    existing: dict[str, Any] | None,
    incoming: dict[str, Any] | None,
    secret_keys: tuple[str, ...],
) -> dict[str, Any] | None:
    """Merge a UI-submitted config over what's already in the DB.

    Empty/missing secret fields keep the existing encrypted value (lets
    the UI omit the secret unless the operator wants to rotate it). The
    rest of the config is fully replaced by the incoming dict.
    """
    if incoming is None:
        return existing
    out = dict(incoming)
    if existing:
        for k in secret_keys:
            if not out.get(k) and existing.get(k):
                out[k] = existing[k]
    return out


@router.patch("", response_model=SystemSettingsRead)
async def update_settings(
    body: SystemSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await _get_or_create(db)
    payload = body.model_dump(exclude_unset=True)

    auth_provider_changed = False
    config_changed = False

    for field, val in payload.items():
        if field == "cloudflare_api_token":
            if val is None or val == "":
                row.cloudflare_api_token = None
            elif looks_like_fernet(val):
                row.cloudflare_api_token = val
            else:
                row.cloudflare_api_token = encrypt_secret(val)
        elif field == "oidc_config":
            merged = _merge_provider_config(row.oidc_config, val, ("client_secret",))
            row.oidc_config = encrypt_oidc_config(merged)
            config_changed = True
        elif field == "ldap_config":
            merged = _merge_provider_config(row.ldap_config, val, ("bind_password",))
            row.ldap_config = encrypt_ldap_config(merged)
            config_changed = True
        elif field == "auth_provider":
            if val != row.auth_provider:
                auth_provider_changed = True
            row.auth_provider = val
        else:
            setattr(row, field, val)

    await db.commit()
    await db.refresh(row)

    if auth_provider_changed or config_changed:
        await log_auth_event(
            db,
            "auth.provider_config_change",
            actor_user_id=actor.id,
            details={
                "active_provider": row.auth_provider,
                "oidc_set": bool(row.oidc_config),
                "ldap_set": bool(row.ldap_config),
            },
        )

    return row


@router.post("/auth/test", response_model=AuthTestResponse)
async def test_auth_provider(
    body: AuthTestRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    """Probe the configured (or supplied) IdP. Used by the Settings UI's
    'Test connection' button. For OIDC: fetch the discovery document.
    For LDAP: do a bind probe (anonymous or service-account)."""
    row = await _get_or_create(db)
    if body.provider == "oidc":
        cfg = body.config or row.oidc_config or {}
        issuer = cfg.get("issuer")
        if not issuer:
            return AuthTestResponse(ok=False, detail="missing issuer")
        try:
            meta = await discover(issuer)
            return AuthTestResponse(
                ok=True,
                detail=f"issuer ok — token_endpoint={meta.get('token_endpoint','?')}",
            )
        except Exception as exc:  # noqa: BLE001
            return AuthTestResponse(ok=False, detail=str(exc))
    if body.provider == "ldap":
        cfg = body.config or row.ldap_config or {}
        if not cfg.get("url"):
            return AuthTestResponse(ok=False, detail="missing url")
        ok, detail = await ldap_test_bind(cfg)
        return AuthTestResponse(ok=ok, detail=detail)
    raise HTTPException(status_code=400, detail="Unknown provider")

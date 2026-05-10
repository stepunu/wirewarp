from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.system_settings import SystemSettings
from app.models.user import User
from app.schemas.user import (
    LoginRequest,
    ProvidersRead,
    TokenResponse,
    UserCreate,
    UserRead,
)
from app.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    log_auth_event,
    require_role,
    verify_password,
)


router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()
    if (
        not user
        or user.auth_provider != "local"
        or not user.password_hash
        or not verify_password(body.password, user.password_hash)
    ):
        await log_auth_event(
            db,
            "auth.login.failure",
            details={"username": body.username, "method": "local"},
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    if not user.is_active:
        await log_auth_event(
            db,
            "auth.login.failure",
            actor_user_id=user.id,
            details={"reason": "disabled", "method": "local"},
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User disabled"
        )

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    await log_auth_event(
        db,
        "auth.login.success",
        actor_user_id=user.id,
        details={"method": "local"},
    )
    token = create_access_token(user.username)
    return TokenResponse(access_token=token)


@router.post("/register", response_model=UserRead, status_code=201)
async def register(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    """Create a local user. Admin-only — no first-run open path. Use the
    `wirewarp-server/scripts/create_admin.py` helper for bootstrap.
    """
    result = await db.execute(select(User).where(User.username == body.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")
    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        auth_provider="local",
        is_active=True,
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


@router.post("/logout", status_code=204)
async def logout(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Audit-only — JWTs are stateless so there's nothing server-side to
    invalidate. The frontend drops its token; the server records who
    logged out so the audit trail isn't deceptive."""
    await log_auth_event(db, "auth.logout", actor_user_id=current_user.id)


@router.get("/providers", response_model=ProvidersRead)
async def get_providers(db: AsyncSession = Depends(get_db)):
    """Public — no auth. Tells the login page which form to render."""
    row = await db.get(SystemSettings, 1)
    return ProvidersRead(active_provider=(row.auth_provider if row else "local"))


@router.get("/me", response_model=UserRead)
async def me(current_user: User = Depends(get_current_user)):
    return current_user

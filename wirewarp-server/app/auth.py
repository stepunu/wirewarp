from datetime import datetime, timedelta, timezone
from typing import Any
import uuid

import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.database import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# bcrypt has a 72-byte effective password limit; bcrypt 4.x raises on
# longer inputs where passlib used to silently truncate. Mirror the
# old behavior so hashes produced by passlib (pre-rewrite) still verify
# for the same plaintext.
def _prep(password: str) -> bytes:
    return password.encode("utf-8")[:72]


# Token kinds carried in the JWT `typ` claim. User tokens authenticate
# dashboard sessions; agent tokens authenticate the WS handshake on
# /ws/agent. Mixing the two is a forgery risk that the previous version
# of this module exposed.
TYP_USER = "user"
TYP_AGENT = "agent"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prep(password), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(_prep(plain), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def create_access_token(
    subject: Any,
    expires_delta: timedelta | None = None,
    typ: str = TYP_USER,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return jwt.encode(
        {"sub": str(subject), "exp": expire, "typ": typ},
        settings.SECRET_KEY,
        algorithm="HS256",
    )


def create_agent_token(subject: Any, expires_delta: timedelta | None = None) -> str:
    return create_access_token(subject, expires_delta=expires_delta, typ=TYP_AGENT)


def decode_token(token: str, expected_typ: str = TYP_USER) -> str:
    """Decode + validate a JWT and return the `sub` claim.

    Tokens issued before the 0016 deploy lack the `typ` claim entirely.
    During the grace window we accept those tokens for both user and
    agent auth — the threat model the typ split protects against
    (cross-token confusion within the new format) doesn't apply to
    pre-split tokens, which were all issued by the same trusted secret
    key. Tokens that DO carry a `typ` claim are still validated
    strictly.

    Long-running agent JWTs (10-year expiry) mean this leniency
    effectively persists for the lifetime of any pre-0016 agent token.
    Removing it cleanly is a follow-up: re-issue agent JWTs via the
    existing `POST /api/agents/{id}/issue-jwt` endpoint, then drop the
    grace.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )
    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    typ = payload.get("typ")
    if typ is not None and typ != expected_typ:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type"
        )
    return sub


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
):
    from app.models.user import User

    username = decode_token(token, expected_typ=TYP_USER)
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User disabled"
        )
    return user


def require_role(*roles: str):
    """FastAPI dependency factory: 403 if the current user's role isn't
    in `roles`. Returns the user object so callers can use it.
    """

    async def _checker(current_user=Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return current_user

    return _checker


async def log_auth_event(
    db: AsyncSession,
    event_type: str,
    *,
    actor_user_id: uuid.UUID | None = None,
    details: dict | None = None,
    success: bool | None = True,
) -> None:
    """Insert a CommandLog row that represents an auth event rather than
    an agent command. Stored alongside agent commands so the audit log
    has a single source of truth.
    """
    from app.models.command_log import CommandLog

    db.add(
        CommandLog(
            id=uuid.uuid4(),
            agent_id=None,
            actor_user_id=actor_user_id,
            command_type=event_type,
            event_type=event_type,
            params=None,
            details_json=details,
            success=success,
            output=None,
        )
    )
    await db.commit()

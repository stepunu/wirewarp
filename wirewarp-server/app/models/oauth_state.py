from datetime import datetime

from sqlalchemy import String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class OAuthState(Base):
    """One row per in-flight OIDC authorization request.

    Created by `GET /api/auth/oidc/login`, consumed (and deleted) by
    `GET /api/auth/oidc/callback`. Survives multi-process deploys where
    the login + callback may land on different workers. Rows older than a
    few minutes are pruned opportunistically on each callback.
    """

    __tablename__ = "oauth_states"

    state: Mapped[str] = mapped_column(String, primary_key=True)
    nonce: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

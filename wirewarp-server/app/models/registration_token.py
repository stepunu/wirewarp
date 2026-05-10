import uuid
from datetime import datetime

from sqlalchemy import String, Boolean, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class RegistrationToken(Base):
    __tablename__ = "registration_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # SHA-256 hex digest of the plaintext token. The plaintext is returned
    # to the admin on issuance (response body of POST /api/agents/tokens)
    # exactly once and is never persisted server-side. The agent presents
    # the plaintext at /ws/agent register; the server hashes the input and
    # looks up by token_hash.
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    agent_type: Mapped[str] = mapped_column(String, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

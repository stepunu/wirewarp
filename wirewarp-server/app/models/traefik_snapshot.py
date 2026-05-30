"""Latest Traefik status snapshot per agent (mirrors crowdsec_snapshots structure).

One row per agent, upserted on each `traefik_status` frame from the agent.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class TraefikSnapshot(Base):
    __tablename__ = "traefik_snapshots"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    installed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    running: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    routes_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    phase: Mapped[str] = mapped_column(String, nullable=False, default="unknown")
    last_error: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

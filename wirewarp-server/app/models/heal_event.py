"""Agent heal-event log row.

One row per `heal_event` frame the agent emits when its 60s healer
re-installs missing routing state. Append-only — operator-visible audit
trail for runtime drift, separate from the existing audit log so the
two retention policies can diverge.
"""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AgentHealEvent(Base):
    __tablename__ = "agent_heal_events"

    # BigInteger.with_variant(Integer) gives PG a BIGINT but lets SQLite
    # use its rowid alias for autoincrement — without this, on-disk
    # SQLite tests fail with "NOT NULL constraint failed: ...id".
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    mode: Mapped[str] = mapped_column(String, nullable=False)  # 'server' | 'client'
    interface: Mapped[str | None] = mapped_column(String, nullable=True)
    healed: Mapped[list] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    agent: Mapped["Agent"] = relationship("Agent", back_populates="heal_events")  # noqa: F821

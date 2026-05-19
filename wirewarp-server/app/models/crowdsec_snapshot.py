"""Latest CrowdSec status snapshot per agent.

Upserted by the server agent's 5-minute poller. `running=False` is the
sentinel for "cscli not installed" — the UI prefers a muted card with
remediation copy over hiding the slot entirely.
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
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CrowdSecSnapshot(Base):
    __tablename__ = "crowdsec_snapshots"

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
    running: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    total_decisions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    top_scenarios: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    top_ips: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

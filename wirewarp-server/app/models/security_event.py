"""Append-only security event log.

Sources: 'crowdsec' (decisions/alerts), 'appsec' (WAF hits), 'traefik'
(access log anomalies). Rows are never updated or deleted — only appended.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_agent_occurred", "agent_id", "occurred_at"),
    )

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
    # 'crowdsec' | 'appsec' | 'traefik'
    source: Mapped[str] = mapped_column(String, nullable=False)
    # scenario / attack type name
    kind: Mapped[str] = mapped_column(String, nullable=False)
    ip: Mapped[str | None] = mapped_column(String, nullable=True)
    value: Mapped[str | None] = mapped_column(String, nullable=True)
    # 'ban' | 'captcha' | 'log' | ...
    action: Mapped[str | None] = mapped_column(String, nullable=True)
    raw: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

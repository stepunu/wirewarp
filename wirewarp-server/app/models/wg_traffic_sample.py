"""Append-only traffic samples copied from wg_peer_snapshots.

One row per (agent, interface, public_key) sample. The background
traffic_sampler task inserts rows every 60 s and prunes rows older
than 30 days. The series feeds the Security Overview charts.
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
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WgTrafficSample(Base):
    __tablename__ = "wg_traffic_samples"
    __table_args__ = (
        Index("ix_wg_traffic_samples_agent_sampled", "agent_id", "sampled_at"),
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
    interface: Mapped[str] = mapped_column(String, nullable=False)
    public_key: Mapped[str] = mapped_column(String, nullable=False)
    rx_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sampled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

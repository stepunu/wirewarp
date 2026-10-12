from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EdgeNode(Base):
    __tablename__ = "edge_nodes"

    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    edge_mode: Mapped[str] = mapped_column(String, nullable=False, default="tcp_udp_only")
    edge_state: Mapped[str] = mapped_column(String, nullable=False, default="disabled")
    edge_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    edge_enabled_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    edge_disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    edge_disabled_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    edge_install_phase: Mapped[str] = mapped_column(String, nullable=False, default="disabled")
    edge_last_error: Mapped[str | None] = mapped_column(String)
    edge_rate_limit_rps: Mapped[int | None] = mapped_column(Integer)
    edge_rate_limit_burst: Mapped[int | None] = mapped_column(Integer)
    lan_bind_ip: Mapped[str | None] = mapped_column(String)
    public_bind_ip: Mapped[str | None] = mapped_column(String)
    relay_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

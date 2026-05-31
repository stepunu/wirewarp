from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EdgeNodePolicy(Base):
    __tablename__ = "edge_node_policies"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        primary_key=True,
    )
    default_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("edge_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    client_ip_strategy: Mapped[str] = mapped_column(String, nullable=False, default="remote_addr")
    trusted_proxy_cidrs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    cloudflare_mode: Mapped[str] = mapped_column(String, nullable=False, default="off")
    access_log_retention_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=72)
    security_event_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    policy_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

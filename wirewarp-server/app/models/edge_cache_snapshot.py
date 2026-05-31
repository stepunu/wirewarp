from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EdgeCacheSnapshot(Base):
    __tablename__ = "edge_cache_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    backend: Mapped[str] = mapped_column(String, nullable=False, default="nginx_proxy_cache")
    installed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    running: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    phase: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    cache_path: Mapped[str | None] = mapped_column(String, nullable=True)
    max_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    current_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    keys_zone_size: Mapped[str | None] = mapped_column(String, nullable=True)
    last_config_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    last_test_status: Mapped[str | None] = mapped_column(String, nullable=True)
    last_purge_result: Mapped[str | None] = mapped_column(String, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (UniqueConstraint("agent_id", "backend", name="uq_edge_cache_snapshot_agent_backend"),)

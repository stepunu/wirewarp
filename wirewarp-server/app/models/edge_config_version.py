from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EdgeConfigVersion(Base):
    __tablename__ = "edge_config_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    desired_hash: Mapped[str] = mapped_column(String, nullable=False)
    rendered_static_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    rendered_dynamic_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    rendered_dynamic_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    rendered_cache_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    rendered_cache_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    agent_result: Mapped[str | None] = mapped_column(String, nullable=True)

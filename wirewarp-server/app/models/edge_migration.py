"""Durable ownership and verification records for VPS route migration."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EdgeMigration(Base):
    __tablename__ = "edge_migrations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_route_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("http_routes.id", ondelete="RESTRICT"), nullable=False, unique=True)
    source_agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False)
    target_agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False)
    target_attachment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"), nullable=False)
    stage_route_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("http_routes.id", ondelete="SET NULL"))
    phase: Mapped[str] = mapped_column(String, nullable=False, default="staged")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    target_visibility: Mapped[str] = mapped_column(String, nullable=False)
    original_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    staged_fingerprint: Mapped[str | None] = mapped_column(String)
    switched_fingerprint: Mapped[str | None] = mapped_column(String)
    resource_map: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    stage_desired_hash: Mapped[str | None] = mapped_column(String)
    stage_version_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    stage_command_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    test_command_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    final_version_ids: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    rollback_version_ids: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    last_error: Mapped[str | None] = mapped_column(String)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

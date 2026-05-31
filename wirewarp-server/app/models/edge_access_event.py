from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EdgeAccessEvent(Base):
    __tablename__ = "edge_access_events"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    route_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("port_forwards.id", ondelete="SET NULL"), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    host: Mapped[str | None] = mapped_column(String, nullable=True)
    path: Mapped[str | None] = mapped_column(String, nullable=True)
    method: Mapped[str | None] = mapped_column(String, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    client_country: Mapped[str | None] = mapped_column(String, nullable=True)
    client_asn: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    referer: Mapped[str | None] = mapped_column(String, nullable=True)
    action: Mapped[str] = mapped_column(String, nullable=False, default="pass")
    source: Mapped[str] = mapped_column(String, nullable=False, default="traefik")
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cache_status: Mapped[str | None] = mapped_column(String, nullable=True)
    upstream_url: Mapped[str | None] = mapped_column(String, nullable=True)
    upstream_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    matched_rule: Mapped[str | None] = mapped_column(String, nullable=True)
    sampled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

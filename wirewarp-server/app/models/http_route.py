from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class HTTPRoute(Base):
    __tablename__ = "http_routes"
    __table_args__ = (CheckConstraint("visibility IN ('lan_only', 'public_only', 'both')", name="ck_http_route_visibility"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String, nullable=False)
    destination_ip: Mapped[str] = mapped_column(String, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    visibility: Mapped[str] = mapped_column(String, nullable=False, default="lan_only")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    edge_route_config: Mapped["EdgeRouteConfig | None"] = relationship("EdgeRouteConfig", back_populates="route", uselist=False, passive_deletes=True, cascade="all, delete-orphan")
    public_ingress: Mapped["HTTPPublicIngress | None"] = relationship("HTTPPublicIngress", back_populates="route", uselist=False, passive_deletes=True, cascade="all, delete-orphan")

    @property
    def service_kind(self) -> str:
        return "http"

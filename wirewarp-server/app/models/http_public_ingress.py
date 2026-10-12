from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class HTTPPublicIngress(Base):
    __tablename__ = "http_public_ingresses"

    route_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("http_routes.id", ondelete="CASCADE"), primary_key=True)
    attachment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"), nullable=False)
    tunnel_server_ip_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("tunnel_server_ips.id", ondelete="RESTRICT"))
    public_port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    route: Mapped["HTTPRoute"] = relationship("HTTPRoute", back_populates="public_ingress")

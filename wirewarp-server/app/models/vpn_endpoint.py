import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import String, Boolean, Integer, DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class VpnEndpoint(Base):
    __tablename__ = "vpn_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tunnel_client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tunnel_clients.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    wg_interface: Mapped[str] = mapped_column(String, nullable=False, default="wg-vpn0")
    listen_port: Mapped[int] = mapped_column(Integer, nullable=False, default=51821)
    vpn_network: Mapped[str] = mapped_column(String, nullable=False)
    public_endpoint: Mapped[str] = mapped_column(String, nullable=False)
    wg_public_key: Mapped[str | None] = mapped_column(String, nullable=True)
    dns_servers: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    profiles: Mapped[list["VpnProfile"]] = relationship(  # noqa: F821
        "VpnProfile", back_populates="endpoint", cascade="all, delete-orphan"
    )

import uuid
from datetime import datetime

from sqlalchemy import String, Boolean, ForeignKey, DateTime, func, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class TunnelServerIP(Base):
    __tablename__ = "tunnel_server_ips"
    __table_args__ = (UniqueConstraint("tunnel_server_id", "address", name="uq_ts_ip_address"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tunnel_server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tunnel_servers.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str] = mapped_column(String, nullable=False)
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tunnel_server: Mapped["TunnelServer"] = relationship("TunnelServer", back_populates="ips")  # noqa: F821

import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Boolean, ForeignKey, DateTime, func, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class PortForward(Base):
    __tablename__ = "port_forwards"
    __table_args__ = (UniqueConstraint("tunnel_server_id", "protocol", "public_port"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tunnel_server_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tunnel_servers.id", ondelete="CASCADE"))
    tunnel_client_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tunnel_clients.id", ondelete="CASCADE"))
    protocol: Mapped[str] = mapped_column(String, nullable=False)  # 'tcp' | 'udp'
    public_port: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_ip: Mapped[str] = mapped_column(String, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tunnel_server: Mapped["TunnelServer"] = relationship("TunnelServer", back_populates="port_forwards")  # noqa: F821
    tunnel_client: Mapped["TunnelClient"] = relationship("TunnelClient", back_populates="port_forwards")  # noqa: F821

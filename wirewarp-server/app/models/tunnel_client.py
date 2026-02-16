import uuid
from datetime import datetime

from sqlalchemy import String, Boolean, ForeignKey, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class TunnelClient(Base):
    __tablename__ = "tunnel_clients"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"))
    tunnel_server_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("tunnel_servers.id", ondelete="SET NULL"))
    tunnel_ip: Mapped[str | None] = mapped_column(String)
    vm_network: Mapped[str | None] = mapped_column(String)
    lan_ip: Mapped[str | None] = mapped_column(String)
    is_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    wg_public_key: Mapped[str | None] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="disconnected")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    agent: Mapped["Agent"] = relationship("Agent", back_populates="tunnel_client")  # noqa: F821
    tunnel_server: Mapped["TunnelServer"] = relationship("TunnelServer", back_populates="tunnel_clients")  # noqa: F821
    port_forwards: Mapped[list["PortForward"]] = relationship("PortForward", back_populates="tunnel_client")  # noqa: F821

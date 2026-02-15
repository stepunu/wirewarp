import uuid
from datetime import datetime

from sqlalchemy import String, Integer, ForeignKey, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class TunnelServer(Base):
    __tablename__ = "tunnel_servers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"))
    wg_port: Mapped[int] = mapped_column(Integer, default=51820)
    wg_interface: Mapped[str] = mapped_column(String, default="wg0")
    public_ip: Mapped[str | None] = mapped_column(String)
    public_iface: Mapped[str] = mapped_column(String, default="eth0")
    wg_public_key: Mapped[str | None] = mapped_column(String)
    tunnel_network: Mapped[str] = mapped_column(String, default="10.0.0.0/24")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    agent: Mapped["Agent"] = relationship("Agent", back_populates="tunnel_server")  # noqa: F821
    tunnel_clients: Mapped[list["TunnelClient"]] = relationship("TunnelClient", back_populates="tunnel_server")  # noqa: F821
    port_forwards: Mapped[list["PortForward"]] = relationship("PortForward", back_populates="tunnel_server")  # noqa: F821

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
    public_iface: Mapped[str] = mapped_column(String, default="eth0")
    wg_public_key: Mapped[str | None] = mapped_column(String)
    tunnel_network: Mapped[str] = mapped_column(String, default="10.0.0.0/24")
    edge_mode: Mapped[str] = mapped_column(String, nullable=False, default="tcp_udp_only")
    edge_state: Mapped[str] = mapped_column(String, nullable=False, default="disabled")
    edge_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    edge_enabled_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    edge_disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    edge_disabled_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    edge_install_phase: Mapped[str] = mapped_column(String, nullable=False, default="disabled")
    edge_last_error: Mapped[str | None] = mapped_column(String, nullable=True)
    edge_rate_limit_rps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    edge_rate_limit_burst: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    agent: Mapped["Agent"] = relationship("Agent", back_populates="tunnel_server")  # noqa: F821
    attachments: Mapped[list["TunnelClientAttachment"]] = relationship(  # noqa: F821
        "TunnelClientAttachment",
        back_populates="tunnel_server",
        passive_deletes=True,
    )
    ips: Mapped[list["TunnelServerIP"]] = relationship(  # noqa: F821
        "TunnelServerIP",
        back_populates="tunnel_server",
        passive_deletes=True,
        order_by="TunnelServerIP.created_at",
        cascade="all, delete-orphan",
    )

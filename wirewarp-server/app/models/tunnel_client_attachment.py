import uuid
from datetime import datetime

from sqlalchemy import String, Integer, ForeignKey, DateTime, func, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class TunnelClientAttachment(Base):
    """One peering between a TunnelClient (homelab gateway) and a TunnelServer (VPS).

    Each attachment owns a kernel `wgN` interface on the agent, its own
    keypair, tunnel IP, fwmark, and routing table — so a single gateway
    client can peer with multiple VPSes simultaneously and reply-path routing
    stays unambiguous (-i wgN at iptables disambiguates by tunnel server).
    """

    __tablename__ = "tunnel_client_attachments"
    __table_args__ = (
        UniqueConstraint("tunnel_client_id", "tunnel_server_id", name="uq_tca_client_server"),
        UniqueConstraint("tunnel_server_id", "tunnel_ip", name="uq_tca_server_ip"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tunnel_client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tunnel_clients.id", ondelete="CASCADE"), nullable=False
    )
    tunnel_server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tunnel_servers.id", ondelete="CASCADE"), nullable=False
    )
    tunnel_ip: Mapped[str] = mapped_column(String, nullable=False)
    wg_interface: Mapped[str] = mapped_column(String, nullable=False)
    wg_public_key: Mapped[str | None] = mapped_column(String, nullable=True)
    fwmark: Mapped[int] = mapped_column(Integer, nullable=False)
    route_table_id: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tunnel_client: Mapped["TunnelClient"] = relationship("TunnelClient", back_populates="attachments")  # noqa: F821
    tunnel_server: Mapped["TunnelServer"] = relationship("TunnelServer", back_populates="attachments")  # noqa: F821
    port_forwards: Mapped[list["PortForward"]] = relationship(  # noqa: F821
        "PortForward", back_populates="attachment", passive_deletes=True
    )

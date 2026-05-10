import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import String, BigInteger, ForeignKey, DateTime, func, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class GatewayLanClient(Base):
    """One LAN host the gateway has observed forwarding non-LAN traffic.

    The agent's scraper enumerates these from the gateway's conntrack
    table (request-side src in LAN subnet, dst outside) and the kernel
    ARP cache. `egress_attachment_id` is the operator's per-host pin:
    NULL = unpinned (egresses via the LAN's default router); non-NULL =
    `ip rule from <lan_ip> table <attachment.route_table_id>` is
    installed on the gateway, forcing this host's outbound through the
    chosen tunnel.
    """

    __tablename__ = "gateway_lan_clients"
    __table_args__ = (
        UniqueConstraint("tunnel_client_id", "lan_ip", name="uq_glc_client_lan_ip"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tunnel_client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tunnel_clients.id", ondelete="CASCADE"), nullable=False
    )
    lan_ip: Mapped[str] = mapped_column(String, nullable=False)
    mac: Mapped[str | None] = mapped_column(String, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    bytes_recent: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    egress_attachment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tunnel_client_attachments.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Optional further pin: SNAT this host's outbound to a specific IP held
    # by the chosen attachment's tunnel server. NULL = MASQUERADE, traffic
    # appears as the server's primary IP. Non-NULL = per-host SNAT rule on
    # the VPS that wins over the generic MASQUERADE.
    egress_tunnel_server_ip_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tunnel_server_ips.id", ondelete="SET NULL"),
        nullable=True,
    )
    # List of DNS records (one entry per record) the control server should
    # PATCH to track this LAN client's egress IP. Schema per entry:
    #   {"provider": "cloudflare", "zone_id": "...", "record_id": "...",
    #    "name": "lan.example.com"}
    # `name` is informational so the UI can render the list without
    # round-tripping the provider API.
    dns_record_ids: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSONB, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tunnel_client: Mapped["TunnelClient"] = relationship("TunnelClient", back_populates="lan_clients")  # noqa: F821
    egress_attachment: Mapped["TunnelClientAttachment | None"] = relationship(  # noqa: F821
        "TunnelClientAttachment"
    )
    egress_tunnel_server_ip: Mapped["TunnelServerIP | None"] = relationship(  # noqa: F821
        "TunnelServerIP"
    )

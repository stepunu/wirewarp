import uuid
from datetime import datetime

from sqlalchemy import (
    String,
    Integer,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class VpnProfile(Base):
    __tablename__ = "vpn_profiles"
    __table_args__ = (
        UniqueConstraint("vpn_endpoint_id", "tunnel_ip", name="uq_vpn_profile_endpoint_ip"),
        CheckConstraint(
            "tunnel_mode IN ('split','full')", name="ck_vpn_profile_tunnel_mode"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    vpn_endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vpn_endpoints.id", ondelete="CASCADE"),
        nullable=False,
    )
    label: Mapped[str] = mapped_column(String, nullable=False)
    tunnel_ip: Mapped[str] = mapped_column(String, nullable=False)
    wg_public_key: Mapped[str] = mapped_column(String, nullable=False)
    wg_psk: Mapped[str] = mapped_column(String, nullable=False)
    tunnel_mode: Mapped[str] = mapped_column(String, nullable=False, default="split")
    issued_route_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_handshake_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    endpoint: Mapped["VpnEndpoint"] = relationship(  # noqa: F821
        "VpnEndpoint", back_populates="profiles", lazy="selectin"
    )

    @property
    def config_route_status(self) -> str:
        if self.tunnel_mode == "full":
            return "not_applicable"
        if self.issued_route_revision is None:
            return "legacy"
        if self.issued_route_revision == self.endpoint.route_revision:
            return "current"
        return "stale"

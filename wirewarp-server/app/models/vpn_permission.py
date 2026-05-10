import uuid

from sqlalchemy import String, Integer, ForeignKey, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class VpnPermission(Base):
    __tablename__ = "vpn_permissions"
    __table_args__ = (
        CheckConstraint(
            "protocol IN ('tcp','udp','icmp','any')",
            name="ck_vpn_permission_protocol",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Permissions are keyed on (user, endpoint) so the admin can
    # pre-provision access before the user has any device profile.
    # Every device profile that user creates on that endpoint inherits
    # this rule set.
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vpn_endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vpn_endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    destination: Mapped[str] = mapped_column(String, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False, default="any")
    port_range_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port_range_end: Mapped[int | None] = mapped_column(Integer, nullable=True)

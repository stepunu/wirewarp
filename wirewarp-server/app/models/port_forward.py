import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Boolean, ForeignKey, DateTime, func, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class PortForward(Base):
    __tablename__ = "port_forwards"
    __table_args__ = (
        UniqueConstraint(
            "attachment_id",
            "tunnel_server_ip_id",
            "protocol",
            "public_port",
            name="uq_pf_attach_ip_proto_port",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attachment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    tunnel_server_ip_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tunnel_server_ips.id", ondelete="RESTRICT"), nullable=True
    )
    protocol: Mapped[str] = mapped_column(String, nullable=False)  # 'tcp' | 'udp'
    public_port: Mapped[int] = mapped_column(Integer, nullable=False)
    public_port_end: Mapped[int | None] = mapped_column(Integer, nullable=True)  # set for ranges
    destination_ip: Mapped[str] = mapped_column(String, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_port_end: Mapped[int | None] = mapped_column(Integer, nullable=True)  # set for ranges
    description: Mapped[str | None] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    attachment: Mapped["TunnelClientAttachment"] = relationship(  # noqa: F821
        "TunnelClientAttachment", back_populates="port_forwards"
    )
    tunnel_server_ip: Mapped["TunnelServerIP | None"] = relationship("TunnelServerIP")  # noqa: F821

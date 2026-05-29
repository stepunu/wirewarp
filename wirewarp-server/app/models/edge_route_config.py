"""Per-HTTP-route edge configuration.

Keyed 1:1 to a port_forwards row (service_kind='http'). Stores WAF
mode, rate-limit, antibot, auth, ACL, geo-block, and TLS source so
the server can render a complete Traefik dynamic config.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EdgeRouteConfig(Base):
    __tablename__ = "edge_route_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    port_forward_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("port_forwards.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    # 'off' | 'observe' | 'block'
    waf_mode: Mapped[str] = mapped_column(String, nullable=False, default="off")
    rate_limit_rps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rate_limit_burst: Mapped[int | None] = mapped_column(Integer, nullable=True)
    antibot: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # 'none' | 'basic' | 'forward'
    auth_mode: Mapped[str] = mapped_column(String, nullable=False, default="none")
    auth_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ip_allow: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    ip_deny: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    geo_block: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    # 'letsencrypt' | 'selfsigned' | 'none'
    tls_source: Mapped[str] = mapped_column(
        String, nullable=False, default="letsencrypt"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    port_forward: Mapped["PortForward"] = relationship(  # noqa: F821
        "PortForward", back_populates="edge_route_config"
    )

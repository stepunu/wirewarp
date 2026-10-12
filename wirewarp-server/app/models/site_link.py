import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SiteLink(Base):
    __tablename__ = "site_links"
    __table_args__ = (
        CheckConstraint("direction IN ('a_to_b', 'b_to_a', 'bidirectional')", name="ck_site_link_direction"),
        CheckConstraint("site_a_gateway_id != site_b_gateway_id", name="ck_site_link_distinct_sites"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    site_a_gateway_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="RESTRICT"))
    site_b_gateway_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="RESTRICT"))
    site_a_attachment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"))
    site_b_attachment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"))
    hub_agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="RESTRICT"))
    site_a_subnets: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    site_b_subnets: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    direction: Mapped[str] = mapped_column(String, nullable=False, default="bidirectional")
    snat_at_a: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    snat_at_b: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    access_rules: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SiteLinkAgentState(Base):
    """Keep aggregate ownership after the last link is deleted."""

    __tablename__ = "site_link_agent_states"
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    desired_hash: Mapped[str | None] = mapped_column(String)
    applied_revision: Mapped[int | None] = mapped_column(Integer)
    applied_hash: Mapped[str | None] = mapped_column(String)
    phase: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    last_error: Mapped[str | None] = mapped_column(String)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    command_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class SiteLinkAgentGeneration(Base):
    """Retain replay protection after managed ownership is released."""

    __tablename__ = "site_link_agent_generations"
    __table_args__ = (CheckConstraint("revision >= 0", name="ck_site_link_generation_revision"),)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

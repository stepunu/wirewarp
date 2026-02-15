import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)  # 'server' | 'client'
    hostname: Mapped[str | None] = mapped_column(String)
    public_ip: Mapped[str | None] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="pending")  # connected | disconnected | pending
    version: Mapped[str | None] = mapped_column(String)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tunnel_server: Mapped["TunnelServer"] = relationship("TunnelServer", back_populates="agent", uselist=False)  # noqa: F821
    tunnel_client: Mapped["TunnelClient"] = relationship("TunnelClient", back_populates="agent", uselist=False)  # noqa: F821
    command_logs: Mapped[list["CommandLog"]] = relationship("CommandLog", back_populates="agent")  # noqa: F821
    metrics: Mapped[list["Metric"]] = relationship("Metric", back_populates="agent")  # noqa: F821

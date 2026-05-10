import uuid
from datetime import datetime

from sqlalchemy import String, Boolean, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class ServiceTemplate(Base):
    __tablename__ = "service_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False)  # 'tcp' | 'udp' | 'both'
    ports: Mapped[str] = mapped_column(String, nullable=False)  # e.g. "2302-2305,27016"
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

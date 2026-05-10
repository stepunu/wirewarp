import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Boolean, CheckConstraint, Index, func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


_external_id_present = text("external_id IS NOT NULL")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin','operator','viewer')", name="ck_users_role"),
        Index(
            "uq_users_provider_external",
            "auth_provider",
            "external_id",
            unique=True,
            postgresql_where=_external_id_present,
            sqlite_where=_external_id_present,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, nullable=False, default="admin")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    auth_provider: Mapped[str] = mapped_column(String, nullable=False, default="local", server_default="local")
    external_id: Mapped[str | None] = mapped_column(String, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    vpn_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

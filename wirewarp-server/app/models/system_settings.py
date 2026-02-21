from sqlalchemy import String, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SystemSettings(Base):
    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    public_url: Mapped[str | None] = mapped_column(String, nullable=True)
    internal_url: Mapped[str | None] = mapped_column(String, nullable=True)
    instance_name: Mapped[str] = mapped_column(String, default="WireWarp")
    agent_token_expiry_hours: Mapped[int] = mapped_column(Integer, default=24)

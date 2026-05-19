"""WireGuard per-peer snapshot row.

One row per (agent, interface, public_key). Updated on every heartbeat
via UPSERT. `kind` is `mesh` for tunnel-mesh peers (wg0 on server,
wgN on gateway client) or `vpn` for road-warrior endpoints (wg-vpn*).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WgPeerSnapshot(Base):
    __tablename__ = "wg_peer_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "agent_id", "interface", "public_key", name="uq_wg_peer_snapshot_aip"
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    interface: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)  # 'mesh' | 'vpn'
    public_key: Mapped[str] = mapped_column(String, nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String, nullable=True)
    allowed_ips: Mapped[str | None] = mapped_column(String, nullable=True)
    last_handshake_unix: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    persistent_keepalive: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

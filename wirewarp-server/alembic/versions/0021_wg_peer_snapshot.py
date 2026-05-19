"""Per-peer wg_peer_snapshots table — latest-snapshot per (agent, iface, pubkey).

Unifies the mesh (`wg0` on servers, `wgN` on gateway clients) and VPN
(`wg-vpnN` on gateways) sides of `wg show <iface> dump` into one table.
One row per peer; UPSERT replaces values on every heartbeat. The agent
sends the full set in the heartbeat under `all_peers` and the server's
`handle_heartbeat` reconciles by primary key.

`kind` is derived server-side from the interface prefix — `wg-vpn*` is
VPN, everything else is mesh — so the routers can filter cheaply.

Also adds `ix_metrics_agent_timestamp` on the existing `metrics` table.
Not strictly required by anything in this PR but cheap, and the
ring-buffer queries that land in later phases need it.

Revision ID: 0021
Revises: 0020
Create Date: 2026-05-19
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wg_peer_snapshots",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("interface", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),  # 'mesh' | 'vpn'
        sa.Column("public_key", sa.String(), nullable=False),
        sa.Column("endpoint", sa.String(), nullable=True),
        sa.Column("allowed_ips", sa.String(), nullable=True),
        sa.Column("last_handshake_unix", sa.BigInteger(), nullable=True),
        sa.Column("rx_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("tx_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("persistent_keepalive", sa.Integer(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "agent_id", "interface", "public_key", name="uq_wg_peer_snapshot_aip"
        ),
    )
    op.create_index(
        "ix_wg_peer_snapshot_agent_id",
        "wg_peer_snapshots",
        ["agent_id"],
    )
    op.create_index(
        "ix_metrics_agent_timestamp",
        "metrics",
        ["agent_id", sa.text("timestamp DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_metrics_agent_timestamp", table_name="metrics")
    op.drop_index("ix_wg_peer_snapshot_agent_id", table_name="wg_peer_snapshots")
    op.drop_table("wg_peer_snapshots")

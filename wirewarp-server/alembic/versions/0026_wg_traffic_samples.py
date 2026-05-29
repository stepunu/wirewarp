"""Add wg_traffic_samples table for append-only bandwidth snapshots.

Sampled from wg_peer_snapshots every 60 s by the traffic_sampler
background task. Feeds Security Overview time-series charts.

Revision ID: 0026
Revises: 0025
Create Date: 2026-05-29
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wg_traffic_samples",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("interface", sa.String(), nullable=False),
        sa.Column("public_key", sa.String(), nullable=False),
        sa.Column("rx_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("tx_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "sampled_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_wg_traffic_samples_agent_sampled",
        "wg_traffic_samples",
        ["agent_id", "sampled_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_wg_traffic_samples_agent_sampled", table_name="wg_traffic_samples")
    op.drop_table("wg_traffic_samples")

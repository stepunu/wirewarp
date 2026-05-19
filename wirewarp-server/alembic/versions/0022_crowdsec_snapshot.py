"""Per-tunnel-server CrowdSec status snapshot.

One row per agent — server-side polls every 5 minutes and the row is
upserted on each push. The agent reports `running: false` when cscli is
not installed, so the row always exists once the poller has fired once;
the UI uses that sentinel to draw a "not detected" card rather than
nothing.

Revision ID: 0022
Revises: 0021
Create Date: 2026-05-19
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "crowdsec_snapshots",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("running", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("total_decisions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "top_scenarios",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "top_ips",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("crowdsec_snapshots")

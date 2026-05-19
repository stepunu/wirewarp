"""Agent heal events stream.

The agent's periodic healer (see wirewarp-agent/internal/handlers/{client,server}_heal.go)
emits a `heal_event` frame each time it re-installs a missing piece of
routing state — `ip rule fwmark`, custom-table routes, mangle CONNMARK
rules, MSS clamps, etc. Each emission lands in this append-only table so
operators can audit drift via the UI without trawling agent logs.

Append-only; no retention policy yet. Index `(agent_id, occurred_at DESC)`
covers the "last 24h per agent" query that drives the AgentDetail card
and the per-server / per-client dashboard summary in later phases.

Revision ID: 0020
Revises: 0019
Create Date: 2026-05-19
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_heal_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("interface", sa.String(), nullable=True),
        sa.Column(
            "healed",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_heal_events_agent_id_occurred_at",
        "agent_heal_events",
        ["agent_id", sa.text("occurred_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_heal_events_agent_id_occurred_at", table_name="agent_heal_events")
    op.drop_table("agent_heal_events")

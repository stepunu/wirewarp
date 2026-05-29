"""Add security_events append-only event log.

Sources: 'crowdsec' (decisions/alerts), 'appsec' (WAF hits via the
Traefik plugin), 'traefik' (access log anomalies). Rows are never
updated or deleted — only appended — so the table grows monotonically
and can be queried by time range for the Events feed.

Revision ID: 0030
Revises: 0029
Create Date: 2026-05-29
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(), nullable=False),  # 'crowdsec'|'appsec'|'traefik'
        sa.Column("kind", sa.String(), nullable=False),    # scenario / attack type
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("value", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=True),   # 'ban'|'captcha'|'log'|...
        sa.Column(
            "raw",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_security_events_agent_occurred",
        "security_events",
        ["agent_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_events_agent_occurred", table_name="security_events")
    op.drop_table("security_events")

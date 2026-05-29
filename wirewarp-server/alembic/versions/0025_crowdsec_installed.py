"""Track whether cscli is installed, separately from the service running.

The agent now reports two facts in its `crowdsec_status` frame:
`installed` (the cscli binary is present) and `running` (the crowdsec
systemd service is active). Previously the agent collapsed both into
`running`, so a host where the apt install succeeded but the service
failed to start looked identical to a host with no CrowdSec at all —
the dashboard showed "not detected" in both cases. This column stores
the new `installed` fact so the UI can tell the two apart and surface
the service error.

Existing rows default to installed=false; the next 5-minute poll from
each agent overwrites it with the real value.

Revision ID: 0025
Revises: 0024
Create Date: 2026-05-29
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "crowdsec_snapshots",
        sa.Column(
            "installed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    # Drop the server_default now that existing rows are backfilled — new
    # rows always set the value explicitly from the model default.
    op.alter_column("crowdsec_snapshots", "installed", server_default=None)


def downgrade() -> None:
    op.drop_column("crowdsec_snapshots", "installed")

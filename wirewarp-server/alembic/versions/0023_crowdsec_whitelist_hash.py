"""Track which whitelist content each crowdsec agent currently holds.

The control server periodically (re-)computes the expected WireWarp
auto-whitelist for every tunnel-server agent — other agents' public
IPs, WG/VPN subnets, gateway LAN subnets, per-host LAN clients — and
hashes it. When the hash differs from what the agent last applied, the
server dispatches a `crowdsec_sync_whitelist` command. This column
stores the most recently applied hash so the diff is one cheap lookup.

Revision ID: 0023
Revises: 0022
Create Date: 2026-05-19
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "crowdsec_snapshots",
        sa.Column("whitelist_hash", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("crowdsec_snapshots", "whitelist_hash")

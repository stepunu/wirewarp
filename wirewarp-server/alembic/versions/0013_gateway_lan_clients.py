"""LAN client discovery + egress pinning per gateway

The gateway agent periodically reports the set of LAN hosts it sees
forwarding non-LAN traffic through it (i.e. hosts that have set the
gateway as their default route). The control server stores those
discoveries here so the dashboard can show them, and so the operator
can pin a host's egress to a specific attachment.

`egress_attachment_id` is a soft-set FK: NULL = unpinned (LAN host
egresses via its normal default — the home ISP). Non-NULL = pinned;
the agent installs `ip rule from <lan_ip> table <route_table_id>`
keyed off the chosen attachment.

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "gateway_lan_clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tunnel_client_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_clients.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("lan_ip", sa.String(), nullable=False),
        sa.Column("mac", sa.String(), nullable=True),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("bytes_recent", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "egress_attachment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_client_attachments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tunnel_client_id", "lan_ip", name="uq_glc_client_lan_ip"),
    )
    op.create_index(
        "ix_glc_last_seen", "gateway_lan_clients", ["last_seen"], unique=False
    )


def downgrade():
    op.drop_index("ix_glc_last_seen", table_name="gateway_lan_clients")
    op.drop_table("gateway_lan_clients")

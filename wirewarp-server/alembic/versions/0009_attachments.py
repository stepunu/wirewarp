"""multi-server gateway: tunnel_client_attachments table + backfill

Each row represents one peering between a homelab gateway (TunnelClient) and
one TunnelServer. Existing single-server clients are backfilled into one
attachment with wg_interface='wg0', fwmark=0x101, route_table_id=100.

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tunnel_client_attachments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tunnel_client_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_clients.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tunnel_server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tunnel_ip", sa.String(), nullable=False),
        sa.Column("wg_interface", sa.String(), nullable=False),
        sa.Column("wg_public_key", sa.String(), nullable=True),
        sa.Column("fwmark", sa.Integer(), nullable=False),
        sa.Column("route_table_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tunnel_client_id", "tunnel_server_id", name="uq_tca_client_server"),
        sa.UniqueConstraint("tunnel_server_id", "tunnel_ip", name="uq_tca_server_ip"),
    )

    # Backfill from existing single-server tunnel_clients. Only rows that
    # already have both tunnel_server_id and tunnel_ip become an attachment.
    op.execute(
        """
        INSERT INTO tunnel_client_attachments (
            id, tunnel_client_id, tunnel_server_id, tunnel_ip,
            wg_interface, wg_public_key, fwmark, route_table_id, created_at
        )
        SELECT
            gen_random_uuid(),
            id,
            tunnel_server_id,
            tunnel_ip,
            'wg0',
            wg_public_key,
            257,
            100,
            now()
        FROM tunnel_clients
        WHERE tunnel_server_id IS NOT NULL
          AND tunnel_ip IS NOT NULL
          AND tunnel_ip <> ''
        """
    )


def downgrade():
    op.drop_table("tunnel_client_attachments")

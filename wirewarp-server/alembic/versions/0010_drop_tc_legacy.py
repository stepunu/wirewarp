"""multi-server gateway: drop legacy single-server columns from tunnel_clients

These columns are subsumed by tunnel_client_attachments. Down migration
re-adds them as nullable but cannot restore data.

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade():
    # Drop the FK constraint first; pg auto-named it on the original CREATE.
    op.execute(
        "ALTER TABLE tunnel_clients DROP CONSTRAINT IF EXISTS tunnel_clients_tunnel_server_id_fkey"
    )
    op.drop_column("tunnel_clients", "tunnel_server_id")
    op.drop_column("tunnel_clients", "tunnel_ip")
    op.drop_column("tunnel_clients", "wg_public_key")


def downgrade():
    op.add_column(
        "tunnel_clients",
        sa.Column(
            "tunnel_server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_servers.id"),
            nullable=True,
        ),
    )
    op.add_column("tunnel_clients", sa.Column("tunnel_ip", sa.String(), nullable=True))
    op.add_column("tunnel_clients", sa.Column("wg_public_key", sa.String(), nullable=True))

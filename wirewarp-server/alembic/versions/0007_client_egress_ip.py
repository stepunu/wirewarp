"""client egress IP: per-tunnel-client SNAT to a chosen tunnel_server_ip

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "tunnel_clients",
        sa.Column(
            "egress_ip_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "tunnel_server_ips.id",
                ondelete="RESTRICT",
                name="fk_tunnel_clients_egress_ip_id",
            ),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column("tunnel_clients", "egress_ip_id")

"""drop client egress IP: feature didn't fit the gateway model (gateways
don't egress through the tunnel; their LAN's outbound goes via the LAN
router). Reverting cleanly before the multi-server gateway refactor.

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tunnel_clients") as batch:
        batch.drop_constraint("fk_tunnel_clients_egress_ip_id", type_="foreignkey")
    op.drop_column("tunnel_clients", "egress_ip_id")


def downgrade():
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

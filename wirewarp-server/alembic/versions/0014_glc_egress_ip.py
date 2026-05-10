"""Per-IP egress pinning for LAN clients.

Today `gateway_lan_clients.egress_attachment_id` chooses which tunnel
attachment a LAN host's outbound traffic takes — but the public source
IP that traffic appears as is determined by the VPS's MASQUERADE rule,
which always picks the primary IP for the outbound socket. That's
limiting when the operator wants to alias a specific LAN host onto a
non-primary IP (e.g. dedicating .176 to one workload while .175 stays
the default).

Add `egress_tunnel_server_ip_id` so the operator can pick *which* of
the chosen attachment's server's public IPs to SNAT to. NULL keeps
today's MASQUERADE behaviour. Non-NULL drives a per-host SNAT rule
installed on the tunnel-server agent: the rule sits before the generic
MASQUERADE in POSTROUTING and rewrites only this LAN host's source.

ON DELETE SET NULL on the FK so deleting a TunnelServerIP just clears
the pin and falls back to MASQUERADE without nuking the row.

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "gateway_lan_clients",
        sa.Column(
            "egress_tunnel_server_ip_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_server_ips.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column("gateway_lan_clients", "egress_tunnel_server_ip_id")

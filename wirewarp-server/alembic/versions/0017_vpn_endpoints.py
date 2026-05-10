"""VPN endpoints + per-user profiles + per-profile permissions.

Adds a road-warrior WireGuard server to gateway agents (replaces wg-easy).
Per the design: each gateway with VPN enabled has one `vpn_endpoints`
row, each user with `vpn_enabled=true` may have N `vpn_profiles` per
endpoint (one per device — phone, laptop), and each profile carries a
list of `vpn_permissions` rules that the gateway agent materialises as
iptables ACCEPT rules. WireGuard private keys are never persisted
server-side; only the public key, PSK, and assigned tunnel IP live in
the DB.

Revision ID: 0017
Revises: 0016
Create Date: 2026-05-10
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("vpn_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.create_table(
        "vpn_endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tunnel_client_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_clients.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("wg_interface", sa.String(), nullable=False, server_default="wg-vpn0"),
        sa.Column("listen_port", sa.Integer(), nullable=False, server_default="51821"),
        sa.Column("vpn_network", sa.String(), nullable=False),
        sa.Column("public_endpoint", sa.String(), nullable=False),
        sa.Column("wg_public_key", sa.String(), nullable=True),
        sa.Column(
            "dns_servers",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "vpn_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "vpn_endpoint_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vpn_endpoints.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("tunnel_ip", sa.String(), nullable=False),
        sa.Column("wg_public_key", sa.String(), nullable=False),
        sa.Column("wg_psk", sa.String(), nullable=False),
        sa.Column(
            "tunnel_mode",
            sa.String(),
            nullable=False,
            server_default="split",
        ),
        sa.Column("last_handshake_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "vpn_endpoint_id", "tunnel_ip", name="uq_vpn_profile_endpoint_ip"
        ),
        sa.CheckConstraint(
            "tunnel_mode IN ('split','full')", name="ck_vpn_profile_tunnel_mode"
        ),
    )

    op.create_table(
        "vpn_permissions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vpn_profile_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vpn_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("destination", sa.String(), nullable=False),
        sa.Column(
            "protocol",
            sa.String(),
            nullable=False,
            server_default="any",
        ),
        sa.Column("port_range_start", sa.Integer(), nullable=True),
        sa.Column("port_range_end", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "protocol IN ('tcp','udp','icmp','any')",
            name="ck_vpn_permission_protocol",
        ),
    )
    op.create_index(
        "ix_vpn_permissions_profile_id",
        "vpn_permissions",
        ["vpn_profile_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_vpn_permissions_profile_id", table_name="vpn_permissions")
    op.drop_table("vpn_permissions")
    op.drop_table("vpn_profiles")
    op.drop_table("vpn_endpoints")
    op.drop_column("users", "vpn_enabled")

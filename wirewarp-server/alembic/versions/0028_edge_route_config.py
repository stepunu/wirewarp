"""Add edge_route_configs table for per-HTTP-route security settings.

One row per port_forwards row (service_kind='http'). Stores WAF mode,
rate-limit, antibot, auth, ACL, geo-block, and TLS source so the
server can render a complete Traefik dynamic config per route.

Revision ID: 0028
Revises: 0027
Create Date: 2026-05-29
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "edge_route_configs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column(
            "port_forward_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("port_forwards.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "waf_mode",
            sa.String(),
            nullable=False,
            server_default="off",
        ),
        sa.Column("rate_limit_rps", sa.Integer(), nullable=True),
        sa.Column("rate_limit_burst", sa.Integer(), nullable=True),
        sa.Column(
            "antibot",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "auth_mode",
            sa.String(),
            nullable=False,
            server_default="none",
        ),
        sa.Column(
            "auth_config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "ip_allow",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "ip_deny",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "geo_block",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "tls_source",
            sa.String(),
            nullable=False,
            server_default="letsencrypt",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("edge_route_configs")

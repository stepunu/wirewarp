"""Add server edge defaults and Traefik import metadata.

Revision ID: 0033
Revises: 0032
Create Date: 2026-05-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tunnel_servers", sa.Column("edge_rate_limit_rps", sa.Integer(), nullable=True))
    op.add_column("tunnel_servers", sa.Column("edge_rate_limit_burst", sa.Integer(), nullable=True))

    op.add_column(
        "edge_route_configs",
        sa.Column("upstream_scheme", sa.String(), nullable=False, server_default="http"),
    )
    op.add_column(
        "edge_route_configs",
        sa.Column("upstream_insecure_skip_verify", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("edge_route_configs", sa.Column("imported_router_name", sa.String(), nullable=True))
    op.add_column("edge_route_configs", sa.Column("imported_service_name", sa.String(), nullable=True))
    op.add_column(
        "edge_route_configs",
        sa.Column("imported_middlewares", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "edge_route_configs",
        sa.Column("import_warnings", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("edge_route_configs", "import_warnings")
    op.drop_column("edge_route_configs", "imported_middlewares")
    op.drop_column("edge_route_configs", "imported_service_name")
    op.drop_column("edge_route_configs", "imported_router_name")
    op.drop_column("edge_route_configs", "upstream_insecure_skip_verify")
    op.drop_column("edge_route_configs", "upstream_scheme")
    op.drop_column("tunnel_servers", "edge_rate_limit_burst")
    op.drop_column("tunnel_servers", "edge_rate_limit_rps")

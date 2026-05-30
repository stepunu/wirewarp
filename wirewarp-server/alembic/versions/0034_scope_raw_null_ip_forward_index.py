"""Scope null-IP port uniqueness to raw forwards.

Revision ID: 0034
Revises: 0033
Create Date: 2026-05-31
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def _partial_where() -> sa.TextClause:
    return sa.text("tunnel_server_ip_id IS NULL AND service_kind = 'raw'")


def upgrade() -> None:
    op.drop_index("ix_pf_attach_null_ip_proto_port", table_name="port_forwards")
    op.create_index(
        "ix_pf_attach_null_ip_proto_port",
        "port_forwards",
        ["attachment_id", "protocol", "public_port"],
        unique=True,
        postgresql_where=_partial_where(),
        sqlite_where=_partial_where(),
    )


def downgrade() -> None:
    op.drop_index("ix_pf_attach_null_ip_proto_port", table_name="port_forwards")
    op.create_index(
        "ix_pf_attach_null_ip_proto_port",
        "port_forwards",
        ["attachment_id", "protocol", "public_port"],
        unique=True,
        postgresql_where=sa.text("tunnel_server_ip_id IS NULL"),
        sqlite_where=sa.text("tunnel_server_ip_id IS NULL"),
    )

"""Add service_kind and domain columns to port_forwards.

`service_kind` distinguishes raw iptables DNAT forwards ('raw') from
Traefik-managed HTTP(S) routes ('http'). `domain` holds the FQDN for
Host-rule matching in Traefik. Existing rows default to 'raw' /
NULL — semantically unchanged from before this migration.

Revision ID: 0027
Revises: 0026
Create Date: 2026-05-29
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "port_forwards",
        sa.Column(
            "service_kind",
            sa.String(),
            nullable=False,
            server_default="raw",
        ),
    )
    op.add_column(
        "port_forwards",
        sa.Column("domain", sa.String(), nullable=True),
    )
    # Drop the server_default so the ORM default ('raw') is the authority
    # for new rows; the server_default was only needed to backfill existing rows.
    op.alter_column("port_forwards", "service_kind", server_default=None)


def downgrade() -> None:
    op.drop_column("port_forwards", "domain")
    op.drop_column("port_forwards", "service_kind")

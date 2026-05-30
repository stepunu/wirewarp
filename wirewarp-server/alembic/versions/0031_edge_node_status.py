"""Add edge component phases and CAPTCHA settings.

Revision ID: 0031
Revises: 0030
Create Date: 2026-05-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "crowdsec_snapshots",
        sa.Column("phase", sa.String(), nullable=False, server_default="unknown"),
    )
    op.add_column("crowdsec_snapshots", sa.Column("last_error", sa.String(), nullable=True))
    op.add_column(
        "crowdsec_snapshots",
        sa.Column("appsec_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "crowdsec_snapshots",
        sa.Column("bouncer_registered", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "traefik_snapshots",
        sa.Column("phase", sa.String(), nullable=False, server_default="unknown"),
    )
    op.add_column("traefik_snapshots", sa.Column("last_error", sa.String(), nullable=True))
    op.add_column("system_settings", sa.Column("captcha_provider", sa.String(), nullable=True))
    op.add_column("system_settings", sa.Column("captcha_site_key", sa.String(), nullable=True))
    op.add_column("system_settings", sa.Column("captcha_secret_key", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("system_settings", "captcha_secret_key")
    op.drop_column("system_settings", "captcha_site_key")
    op.drop_column("system_settings", "captcha_provider")
    op.drop_column("traefik_snapshots", "last_error")
    op.drop_column("traefik_snapshots", "phase")
    op.drop_column("crowdsec_snapshots", "bouncer_registered")
    op.drop_column("crowdsec_snapshots", "appsec_enabled")
    op.drop_column("crowdsec_snapshots", "last_error")
    op.drop_column("crowdsec_snapshots", "phase")

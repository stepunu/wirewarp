"""Add settings-backed Let's Encrypt ACME config.

Revision ID: 0032
Revises: 0031
Create Date: 2026-05-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "system_settings",
        sa.Column("letsencrypt_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("system_settings", sa.Column("letsencrypt_email", sa.String(), nullable=True))
    op.add_column(
        "system_settings",
        sa.Column("letsencrypt_challenge", sa.String(), nullable=False, server_default="dns-01"),
    )
    op.add_column(
        "system_settings",
        sa.Column("letsencrypt_dns_provider", sa.String(), nullable=True, server_default="cloudflare"),
    )
    op.add_column(
        "system_settings",
        sa.Column("letsencrypt_dns_resolvers", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    bind = op.get_bind()
    default_resolvers = '["1.1.1.1:53"]'
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "UPDATE system_settings "
                "SET letsencrypt_dns_resolvers = CAST(:resolvers AS jsonb) "
                "WHERE letsencrypt_dns_resolvers IS NULL"
            ).bindparams(resolvers=default_resolvers)
        )
    else:
        op.execute(
            sa.text(
                "UPDATE system_settings "
                "SET letsencrypt_dns_resolvers = :resolvers "
                "WHERE letsencrypt_dns_resolvers IS NULL"
            ).bindparams(resolvers=default_resolvers)
        )
    op.add_column(
        "system_settings",
        sa.Column("letsencrypt_use_staging", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "system_settings",
        sa.Column("letsencrypt_cloudflare_api_token", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("system_settings", "letsencrypt_cloudflare_api_token")
    op.drop_column("system_settings", "letsencrypt_use_staging")
    op.drop_column("system_settings", "letsencrypt_dns_resolvers")
    op.drop_column("system_settings", "letsencrypt_dns_provider")
    op.drop_column("system_settings", "letsencrypt_challenge")
    op.drop_column("system_settings", "letsencrypt_email")
    op.drop_column("system_settings", "letsencrypt_enabled")

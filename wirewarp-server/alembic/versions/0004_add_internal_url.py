"""add internal_url to system_settings

Revision ID: 0004
Revises: 0003
Create Date: 2026-02-21
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("system_settings", sa.Column("internal_url", sa.String(), nullable=True))


def downgrade():
    op.drop_column("system_settings", "internal_url")

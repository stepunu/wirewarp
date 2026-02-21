"""Add system_settings table

Revision ID: 0003
Revises: 0002
Create Date: 2026-02-21

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "system_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_url", sa.String(), nullable=True),
        sa.Column("instance_name", sa.String(), nullable=False, server_default="WireWarp"),
        sa.Column("agent_token_expiry_hours", sa.Integer(), nullable=False, server_default="24"),
    )
    op.execute("INSERT INTO system_settings (id) VALUES (1)")


def downgrade() -> None:
    op.drop_table("system_settings")

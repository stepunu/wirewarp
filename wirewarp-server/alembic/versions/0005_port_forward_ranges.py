"""add port range support to port_forwards

Revision ID: 0005
Revises: 0004
Create Date: 2026-03-10
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("port_forwards", sa.Column("public_port_end", sa.Integer(), nullable=True))
    op.add_column("port_forwards", sa.Column("destination_port_end", sa.Integer(), nullable=True))


def downgrade():
    op.drop_column("port_forwards", "destination_port_end")
    op.drop_column("port_forwards", "public_port_end")

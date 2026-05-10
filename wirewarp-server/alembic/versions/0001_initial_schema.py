"""Initial schema

Revision ID: 0001
Revises:
Create Date: 2026-02-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("hostname", sa.String()),
        sa.Column("public_ip", sa.String()),
        sa.Column("status", sa.String(), server_default="pending"),
        sa.Column("version", sa.String()),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "registration_tokens",
        sa.Column("token", sa.String(), primary_key=True),
        sa.Column("agent_type", sa.String(), nullable=False),
        sa.Column("used", sa.Boolean(), server_default="false"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(), unique=True, nullable=False),
        sa.Column("email", sa.String(), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(), server_default="admin"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "tunnel_servers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("wg_port", sa.Integer(), server_default="51820"),
        sa.Column("wg_interface", sa.String(), server_default="wg0"),
        sa.Column("public_ip", sa.String()),
        sa.Column("public_iface", sa.String(), server_default="eth0"),
        sa.Column("wg_public_key", sa.String()),
        sa.Column("tunnel_network", sa.String(), server_default="10.0.0.0/24"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "tunnel_clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("tunnel_server_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tunnel_servers.id")),
        sa.Column("tunnel_ip", sa.String()),
        sa.Column("vm_network", sa.String()),
        sa.Column("lan_ip", sa.String()),
        sa.Column("is_gateway", sa.Boolean(), server_default="false"),
        sa.Column("wg_public_key", sa.String()),
        sa.Column("status", sa.String(), server_default="disconnected"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "port_forwards",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tunnel_server_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tunnel_servers.id", ondelete="CASCADE")),
        sa.Column("tunnel_client_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tunnel_clients.id", ondelete="CASCADE")),
        sa.Column("protocol", sa.String(), nullable=False),
        sa.Column("public_port", sa.Integer(), nullable=False),
        sa.Column("destination_ip", sa.String(), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("description", sa.String()),
        sa.Column("active", sa.Boolean(), server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tunnel_server_id", "protocol", "public_port"),
    )

    op.create_table(
        "service_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(), unique=True, nullable=False),
        sa.Column("protocol", sa.String(), nullable=False),
        sa.Column("ports", sa.String(), nullable=False),
        sa.Column("is_builtin", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "command_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id")),
        sa.Column("command_type", sa.String(), nullable=False),
        sa.Column("params", postgresql.JSONB()),
        sa.Column("success", sa.Boolean()),
        sa.Column("output", sa.Text()),
        sa.Column("executed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "metrics",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("metrics")
    op.drop_table("command_log")
    op.drop_table("service_templates")
    op.drop_table("port_forwards")
    op.drop_table("tunnel_clients")
    op.drop_table("tunnel_servers")
    op.drop_table("users")
    op.drop_table("registration_tokens")
    op.drop_table("agents")

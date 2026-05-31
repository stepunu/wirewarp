"""Add edge profiles, node policy, and path rules.

Revision ID: 0036
Revises: 0035
Create Date: 2026-05-31
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "edge_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("scope", sa.String(), nullable=False, server_default="global"),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("policy_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("slug", name="uq_edge_profile_slug"),
    )
    op.create_table(
        "edge_node_policies",
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("default_profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("edge_profiles.id", ondelete="SET NULL"), nullable=True),
        sa.Column("client_ip_strategy", sa.String(), nullable=False, server_default="remote_addr"),
        sa.Column("trusted_proxy_cidrs", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("cloudflare_mode", sa.String(), nullable=False, server_default="off"),
        sa.Column("access_log_retention_hours", sa.Integer(), nullable=False, server_default="72"),
        sa.Column("security_event_retention_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("policy_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "edge_path_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("route_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("port_forwards.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("match", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("policy_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("route_id", "name", name="uq_edge_path_rule_route_name"),
    )
    op.add_column("edge_route_configs", sa.Column("profile_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("edge_route_configs", sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("edge_route_configs", sa.Column("policy_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_foreign_key(
        "fk_edge_route_configs_profile_id_edge_profiles",
        "edge_route_configs",
        "edge_profiles",
        ["profile_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_edge_route_configs_profile_id_edge_profiles", "edge_route_configs", type_="foreignkey")
    op.drop_column("edge_route_configs", "policy_json")
    op.drop_column("edge_route_configs", "priority")
    op.drop_column("edge_route_configs", "profile_id")
    op.drop_table("edge_path_rules")
    op.drop_table("edge_node_policies")
    op.drop_table("edge_profiles")

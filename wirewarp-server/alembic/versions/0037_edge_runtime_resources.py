"""Add edge runtime resources.

Revision ID: 0037
Revises: 0036
Create Date: 2026-05-31
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "edge_access_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("route_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("port_forwards.id", ondelete="SET NULL"), nullable=True),
        sa.Column("request_id", sa.String(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("host", sa.String(), nullable=True),
        sa.Column("path", sa.String(), nullable=True),
        sa.Column("method", sa.String(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("client_ip", sa.String(), nullable=True),
        sa.Column("client_country", sa.String(), nullable=True),
        sa.Column("client_asn", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("referer", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False, server_default="pass"),
        sa.Column("source", sa.String(), nullable=False, server_default="traefik"),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("cache_status", sa.String(), nullable=True),
        sa.Column("upstream_url", sa.String(), nullable=True),
        sa.Column("upstream_status", sa.Integer(), nullable=True),
        sa.Column("bytes_in", sa.Integer(), nullable=True),
        sa.Column("bytes_out", sa.Integer(), nullable=True),
        sa.Column("matched_rule", sa.String(), nullable=True),
        sa.Column("sampled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_edge_access_agent_time", "edge_access_events", ["agent_id", "occurred_at"])
    op.create_index("ix_edge_access_route_time", "edge_access_events", ["route_id", "occurred_at"])

    op.create_table(
        "edge_cache_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("backend", sa.String(), nullable=False, server_default="nginx_proxy_cache"),
        sa.Column("installed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("running", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("phase", sa.String(), nullable=False, server_default="pending"),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("cache_path", sa.String(), nullable=True),
        sa.Column("max_size_bytes", sa.Integer(), nullable=True),
        sa.Column("current_size_bytes", sa.Integer(), nullable=True),
        sa.Column("keys_zone_size", sa.String(), nullable=True),
        sa.Column("last_config_hash", sa.String(), nullable=True),
        sa.Column("last_test_status", sa.String(), nullable=True),
        sa.Column("last_purge_result", sa.String(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("agent_id", "backend", name="uq_edge_cache_snapshot_agent_backend"),
    )
    op.create_table(
        "edge_fragments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("route_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("port_forwards.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("fragment_type", sa.String(), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("validation_state", sa.String(), nullable=False, server_default="valid"),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "edge_config_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("desired_hash", sa.String(), nullable=False),
        sa.Column("rendered_static_hash", sa.String(), nullable=True),
        sa.Column("rendered_dynamic_hash", sa.String(), nullable=True),
        sa.Column("rendered_dynamic_yaml", sa.Text(), nullable=True),
        sa.Column("rendered_cache_hash", sa.String(), nullable=True),
        sa.Column("rendered_cache_config", sa.Text(), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("agent_result", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("edge_config_versions")
    op.drop_table("edge_fragments")
    op.drop_table("edge_cache_snapshots")
    op.drop_index("ix_edge_access_route_time", table_name="edge_access_events")
    op.drop_index("ix_edge_access_agent_time", table_name="edge_access_events")
    op.drop_table("edge_access_events")

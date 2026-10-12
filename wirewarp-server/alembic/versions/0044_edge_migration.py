"""Persist reviewable VPS to gateway route migration ownership."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0044_edge_migration"
down_revision = "0043_site_links"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("edge_route_configs", sa.Column("inherit_node_policy", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_table(
        "edge_migrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_route_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("http_routes.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("source_agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("target_agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("target_attachment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("stage_route_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("http_routes.id", ondelete="SET NULL")),
        sa.Column("phase", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("target_visibility", sa.String(), nullable=False),
        sa.Column("original_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("source_fingerprint", sa.String(), nullable=False),
        sa.Column("staged_fingerprint", sa.String()),
        sa.Column("switched_fingerprint", sa.String()),
        sa.Column("resource_map", postgresql.JSONB(), nullable=False),
        sa.Column("stage_desired_hash", sa.String()),
        sa.Column("stage_version_id", postgresql.UUID(as_uuid=True)),
        sa.Column("stage_command_id", postgresql.UUID(as_uuid=True)),
        sa.Column("test_command_id", postgresql.UUID(as_uuid=True)),
        sa.Column("final_version_ids", postgresql.JSONB(), nullable=False),
        sa.Column("rollback_version_ids", postgresql.JSONB(), nullable=False),
        sa.Column("last_error", sa.String()),
        sa.Column("created_by", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade():
    if op.get_bind().execute(sa.text("SELECT EXISTS(SELECT 1 FROM edge_migrations) OR EXISTS(SELECT 1 FROM edge_route_configs WHERE inherit_node_policy = false)")).scalar():
        raise RuntimeError("Refuse to drop route migration ownership and rollback records")
    op.drop_table("edge_migrations")
    op.drop_column("edge_route_configs", "inherit_node_policy")

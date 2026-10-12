"""Persist site links and aggregate per-agent reconciliation state."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0043_site_links"
down_revision = "0042_gateway_public_relay"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "site_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("site_a_gateway_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("site_b_gateway_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("site_a_attachment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("site_b_attachment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("hub_agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("site_a_subnets", postgresql.JSONB(), nullable=False),
        sa.Column("site_b_subnets", postgresql.JSONB(), nullable=False),
        sa.Column("direction", sa.String(), nullable=False),
        sa.Column("snat_at_a", sa.Boolean(), nullable=False),
        sa.Column("snat_at_b", sa.Boolean(), nullable=False),
        sa.Column("access_rules", postgresql.JSONB(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("direction IN ('a_to_b', 'b_to_a', 'bidirectional')", name="ck_site_link_direction"),
        sa.CheckConstraint("site_a_gateway_id != site_b_gateway_id", name="ck_site_link_distinct_sites"),
    )
    op.create_table(
        "site_link_agent_states",
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("desired_hash", sa.String()),
        sa.Column("applied_revision", sa.Integer()),
        sa.Column("applied_hash", sa.String()),
        sa.Column("phase", sa.String(), nullable=False),
        sa.Column("last_error", sa.String()),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("command_id", postgresql.UUID(as_uuid=True)),
    )


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT EXISTS(SELECT 1 FROM site_links) OR EXISTS(SELECT 1 FROM site_link_agent_states)")).scalar():
        raise RuntimeError("Refuse to drop persisted site link ownership; reconcile removal before a manual downgrade")
    op.drop_table("site_link_agent_states")
    op.drop_table("site_links")

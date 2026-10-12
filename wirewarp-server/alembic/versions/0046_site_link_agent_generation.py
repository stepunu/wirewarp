"""Keep Site Links revisions after managed teardown."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0046_site_link_generations"
down_revision = "0045_edge_config_snapshot"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("site_link_agent_generations",
                    sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True),
                    sa.Column("revision", sa.Integer(), nullable=False),
                    sa.CheckConstraint("revision >= 0", name="ck_site_link_generation_revision"))
    op.get_bind().execute(sa.text("INSERT INTO site_link_agent_generations (agent_id, revision) SELECT agent_id, revision FROM site_link_agent_states"))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM site_link_agent_generations LIMIT 1")).first():
        raise RuntimeError("Site Links revision history exists. Preserve replay protection before downgrading.")
    op.drop_table("site_link_agent_generations")

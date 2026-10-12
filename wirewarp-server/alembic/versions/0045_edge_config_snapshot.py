"""Keep source configuration for reproducible Edge rollbacks."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0045_edge_config_snapshot"
down_revision = "0044_edge_migration"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("edge_config_versions", sa.Column("source_snapshot", postgresql.JSONB(), nullable=True))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM edge_config_versions WHERE source_snapshot IS NOT NULL LIMIT 1")).first():
        raise RuntimeError("Edge rollback snapshots exist. Preserve them before downgrading.")
    op.drop_column("edge_config_versions", "source_snapshot")

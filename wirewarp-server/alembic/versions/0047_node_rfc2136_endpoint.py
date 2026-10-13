"""Allow a node to use its reachable RFC2136 update endpoint."""
from alembic import op
import sqlalchemy as sa

revision = "0047_node_rfc2136_endpoint"
down_revision = "0046_site_link_generations"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("edge_nodes", sa.Column("rfc2136_nameserver_override", sa.String(), nullable=True))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM edge_nodes WHERE rfc2136_nameserver_override IS NOT NULL LIMIT 1")).first():
        raise RuntimeError("Clear node RFC2136 update endpoint overrides before downgrading.")
    op.drop_column("edge_nodes", "rfc2136_nameserver_override")

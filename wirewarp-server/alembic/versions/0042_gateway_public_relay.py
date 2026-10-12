"""Add relay lifecycle state and remove obsolete server edge capability fields."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0042_gateway_public_relay"
down_revision = "0041_agent_owned_http_routes"
branch_labels = None
depends_on = None

EDGE_FIELDS = (
    "edge_mode", "edge_state", "edge_enabled_at", "edge_enabled_by",
    "edge_disabled_at", "edge_disabled_by", "edge_install_phase",
    "edge_last_error", "edge_rate_limit_rps", "edge_rate_limit_burst",
)


def upgrade():
    op.add_column("edge_nodes", sa.Column("relay_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    for field in EDGE_FIELDS:
        op.drop_column("tunnel_servers", field)


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM edge_nodes WHERE relay_enabled LIMIT 1")).first():
        raise RuntimeError("Disable gateway public relays before downgrading")
    defaults = {"edge_mode": "tcp_udp_only", "edge_state": "disabled", "edge_install_phase": "disabled"}
    for field in EDGE_FIELDS:
        if field.endswith("_at"):
            column = sa.Column(field, sa.DateTime(timezone=True))
        elif field.endswith("_by"):
            column = sa.Column(field, postgresql.UUID(as_uuid=True))
        elif field.startswith("edge_rate_limit"):
            column = sa.Column(field, sa.Integer())
        else:
            column = sa.Column(field, sa.String(), nullable=field not in defaults, server_default=defaults.get(field))
        op.add_column("tunnel_servers", column)
    assignments = ", ".join(f"{field} = e.{field}" for field in EDGE_FIELDS)
    op.get_bind().execute(sa.text(f"UPDATE tunnel_servers s SET {assignments} FROM edge_nodes e WHERE e.agent_id = s.agent_id"))
    op.drop_column("edge_nodes", "relay_enabled")

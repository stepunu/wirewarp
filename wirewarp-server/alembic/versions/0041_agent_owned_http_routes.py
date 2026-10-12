"""Move HTTP routes and edge capabilities from tunnel servers to agents."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0041_agent_owned_http_routes"
down_revision = "0040_rfc2136_acme_settings"
branch_labels = None
depends_on = None

EDGE_FIELDS = (
    "edge_mode", "edge_state", "edge_enabled_at", "edge_enabled_by",
    "edge_disabled_at", "edge_disabled_by", "edge_install_phase",
    "edge_last_error", "edge_rate_limit_rps", "edge_rate_limit_burst",
)
ROUTE_FKS = (
    ("edge_route_configs", "port_forward_id", "CASCADE"),
    ("edge_path_rules", "route_id", "CASCADE"),
    ("edge_fragments", "route_id", "CASCADE"),
    ("edge_access_events", "route_id", "SET NULL"),
)


def _retarget_route_fks(target: str, *, downgrade: bool = False) -> None:
    bind = op.get_bind()
    for table, original_column, action in ROUTE_FKS:
        old_column = "route_id" if downgrade and table == "edge_route_configs" else original_column
        new_column = original_column if downgrade else "route_id"
        foreign_keys = sa.inspect(bind).get_foreign_keys(table)
        matches = [fk for fk in foreign_keys if fk["constrained_columns"] == [old_column]]
        if len(matches) != 1 or not matches[0]["name"]:
            raise RuntimeError(f"Cannot identify route foreign key for {table}")
        op.drop_constraint(matches[0]["name"], table, type_="foreignkey")
        if old_column != new_column:
            op.alter_column(table, old_column, new_column_name=new_column)
        op.create_foreign_key(f"fk_{table}_{new_column}", table, target, [new_column], ["id"], ondelete=action)


def upgrade() -> None:
    bind = op.get_bind()
    invalid = bind.execute(sa.text("""
        SELECT p.id FROM port_forwards p
        LEFT JOIN tunnel_client_attachments a ON a.id = p.attachment_id
        LEFT JOIN tunnel_servers s ON s.id = a.tunnel_server_id
        LEFT JOIN agents ag ON ag.id = s.agent_id
        WHERE p.service_kind = 'http' AND
        (ag.id IS NULL OR p.domain IS NULL OR p.active IS NULL OR
         p.protocol <> 'tcp' OR p.public_port_end IS NOT NULL OR p.destination_port_end IS NOT NULL)
    """)).scalars().all()
    if invalid:
        raise RuntimeError(f"HTTP routes cannot be migrated without a valid owner and single TCP binding: {invalid}")
    for table, column, _ in ROUTE_FKS:
        invalid = bind.execute(sa.text(f"""
            SELECT r.{column} FROM {table} r LEFT JOIN port_forwards p ON p.id = r.{column}
            WHERE r.{column} IS NOT NULL AND (p.id IS NULL OR p.service_kind <> 'http')
        """)).scalars().all()
        if invalid:
            raise RuntimeError(f"Invalid HTTP route references in {table}: {invalid}")

    uuid_type = postgresql.UUID(as_uuid=True)
    op.create_table(
        "edge_nodes",
        sa.Column("agent_id", uuid_type, sa.ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("edge_mode", sa.String(), nullable=False, server_default="tcp_udp_only"),
        sa.Column("edge_state", sa.String(), nullable=False, server_default="disabled"),
        sa.Column("edge_enabled_at", sa.DateTime(timezone=True)),
        sa.Column("edge_enabled_by", uuid_type),
        sa.Column("edge_disabled_at", sa.DateTime(timezone=True)),
        sa.Column("edge_disabled_by", uuid_type),
        sa.Column("edge_install_phase", sa.String(), nullable=False, server_default="disabled"),
        sa.Column("edge_last_error", sa.String()),
        sa.Column("edge_rate_limit_rps", sa.Integer()),
        sa.Column("edge_rate_limit_burst", sa.Integer()),
        sa.Column("lan_bind_ip", sa.String()),
        sa.Column("public_bind_ip", sa.String()),
    )
    op.create_table(
        "http_routes",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("agent_id", uuid_type, sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("destination_ip", sa.String(), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("description", sa.String()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("visibility", sa.String(), nullable=False, server_default="lan_only"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("visibility IN ('lan_only', 'public_only', 'both')", name="ck_http_route_visibility"),
    )
    op.create_index("ix_http_routes_agent_id", "http_routes", ["agent_id"])
    op.create_table(
        "http_public_ingresses",
        sa.Column("route_id", uuid_type, sa.ForeignKey("http_routes.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("attachment_id", uuid_type, sa.ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("tunnel_server_ip_id", uuid_type, sa.ForeignKey("tunnel_server_ips.id", ondelete="RESTRICT")),
        sa.Column("public_port", sa.Integer(), nullable=False, server_default="443"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    fields = ", ".join(EDGE_FIELDS)
    bind.execute(sa.text(f"INSERT INTO edge_nodes (agent_id, {fields}) SELECT agent_id, {fields} FROM tunnel_servers"))
    bind.execute(sa.text("""
        INSERT INTO http_routes (id, agent_id, domain, destination_ip, destination_port, description, active, visibility, created_at)
        SELECT p.id, s.agent_id, p.domain, p.destination_ip, p.destination_port, p.description, p.active, 'public_only', COALESCE(p.created_at, now())
        FROM port_forwards p JOIN tunnel_client_attachments a ON a.id = p.attachment_id
        JOIN tunnel_servers s ON s.id = a.tunnel_server_id WHERE p.service_kind = 'http'
    """))
    bind.execute(sa.text("""
        INSERT INTO http_public_ingresses (route_id, attachment_id, tunnel_server_ip_id, public_port, active)
        SELECT id, attachment_id, tunnel_server_ip_id, public_port, active FROM port_forwards WHERE service_kind = 'http'
    """))
    _retarget_route_fks("http_routes")
    bind.execute(sa.text("DELETE FROM port_forwards WHERE service_kind = 'http'"))


def downgrade() -> None:
    bind = op.get_bind()
    invalid = bind.execute(sa.text("""
        SELECT r.id FROM http_routes r
        LEFT JOIN http_public_ingresses i ON i.route_id = r.id
        LEFT JOIN tunnel_client_attachments a ON a.id = i.attachment_id
        LEFT JOIN tunnel_servers s ON s.id = a.tunnel_server_id
        WHERE r.visibility <> 'public_only' OR i.route_id IS NULL OR s.agent_id IS DISTINCT FROM r.agent_id
        OR i.active IS DISTINCT FROM r.active
        OR EXISTS (SELECT 1 FROM port_forwards p WHERE p.id = r.id)
    """)).scalars().all()
    if invalid:
        raise RuntimeError(f"Cannot downgrade gateway, LAN, or incompatible HTTP routes: {invalid}")
    binds = bind.execute(sa.text("SELECT agent_id FROM edge_nodes WHERE lan_bind_ip IS NOT NULL OR public_bind_ip IS NOT NULL")).scalars().all()
    if binds:
        raise RuntimeError(f"Cannot downgrade explicit edge listeners: {binds}")
    bind.execute(sa.text("""
        INSERT INTO port_forwards (id, attachment_id, tunnel_server_ip_id, protocol, public_port, destination_ip, destination_port, description, active, service_kind, domain, created_at)
        SELECT r.id, i.attachment_id, i.tunnel_server_ip_id, 'tcp', i.public_port, r.destination_ip, r.destination_port, r.description, r.active, 'http', r.domain, r.created_at
        FROM http_routes r JOIN http_public_ingresses i ON i.route_id = r.id
    """))
    _retarget_route_fks("port_forwards", downgrade=True)
    assignments = ", ".join(f"{field} = e.{field}" for field in EDGE_FIELDS)
    bind.execute(sa.text(f"UPDATE tunnel_servers s SET {assignments} FROM edge_nodes e WHERE e.agent_id = s.agent_id"))
    op.drop_table("http_public_ingresses")
    op.drop_index("ix_http_routes_agent_id", table_name="http_routes")
    op.drop_table("http_routes")
    op.drop_table("edge_nodes")

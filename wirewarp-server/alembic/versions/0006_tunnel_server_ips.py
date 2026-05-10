"""multi-IP per tunnel server: tunnel_server_ips table, port_forwards FK, drop tunnel_servers.public_ip

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Create tunnel_server_ips table
    op.create_table(
        "tunnel_server_ips",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tunnel_server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("address", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tunnel_server_id", "address", name="uq_ts_ip_address"),
    )

    # 2. Partial unique index: at most one primary IP per tunnel server.
    op.create_index(
        "ix_ts_ip_one_primary",
        "tunnel_server_ips",
        ["tunnel_server_id"],
        unique=True,
        postgresql_where=sa.text("is_primary = true"),
    )

    # 3. Backfill from the legacy single-IP column. gen_random_uuid() requires pgcrypto; fall back to uuid_generate_v4()
    #    if pgcrypto is missing. Postgres 13+ has gen_random_uuid() built-in via pgcrypto extension which Postgres 16
    #    enables in the default contrib set — the WireWarp compose stack uses postgres:16-alpine which includes it.
    op.execute(
        """
        INSERT INTO tunnel_server_ips (id, tunnel_server_id, address, is_primary, created_at)
        SELECT gen_random_uuid(), id, public_ip, true, now()
        FROM tunnel_servers
        WHERE public_ip IS NOT NULL AND public_ip <> ''
        """
    )

    # 4. Add nullable FK to port_forwards. RESTRICT so deleting an IP with bound forwards is blocked.
    op.add_column(
        "port_forwards",
        sa.Column(
            "tunnel_server_ip_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_server_ips.id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )

    # 5. Drop the old port-uniqueness constraint. Postgres auto-named it
    #    `port_forwards_tunnel_server_id_protocol_public_port_key` from the unnamed
    #    UniqueConstraint in migration 0001. Use IF EXISTS to tolerate naming variance.
    op.execute(
        "ALTER TABLE port_forwards DROP CONSTRAINT IF EXISTS port_forwards_tunnel_server_id_protocol_public_port_key"
    )

    # 6. New uniqueness for non-NULL ip bindings.
    op.create_unique_constraint(
        "uq_pf_server_ip_proto_port",
        "port_forwards",
        ["tunnel_server_id", "tunnel_server_ip_id", "protocol", "public_port"],
    )

    # 7. Partial unique index covering NULL ip bindings (Postgres treats NULLs as distinct in
    #    regular UNIQUE, so two "primary-bound" forwards on the same port would otherwise be allowed).
    op.create_index(
        "ix_pf_server_null_ip_proto_port",
        "port_forwards",
        ["tunnel_server_id", "protocol", "public_port"],
        unique=True,
        postgresql_where=sa.text("tunnel_server_ip_id IS NULL"),
    )

    # 8. Drop the legacy single-IP column. Primary IP is now derived from tunnel_server_ips.
    op.drop_column("tunnel_servers", "public_ip")


def downgrade():
    # Restore the legacy column.
    op.add_column(
        "tunnel_servers",
        sa.Column("public_ip", sa.String(), nullable=True),
    )
    op.execute(
        """
        UPDATE tunnel_servers ts
        SET public_ip = ip.address
        FROM tunnel_server_ips ip
        WHERE ip.tunnel_server_id = ts.id AND ip.is_primary = true
        """
    )

    op.drop_index("ix_pf_server_null_ip_proto_port", table_name="port_forwards")
    op.drop_constraint("uq_pf_server_ip_proto_port", "port_forwards", type_="unique")

    # Recreate the original unnamed unique constraint (Postgres will auto-name it).
    op.create_unique_constraint(
        "port_forwards_tunnel_server_id_protocol_public_port_key",
        "port_forwards",
        ["tunnel_server_id", "protocol", "public_port"],
    )

    op.drop_column("port_forwards", "tunnel_server_ip_id")
    op.drop_index("ix_ts_ip_one_primary", table_name="tunnel_server_ips")
    op.drop_table("tunnel_server_ips")

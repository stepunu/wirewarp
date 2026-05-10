"""multi-server gateway: drop legacy port_forwards FKs, swap unique constraint

attachment_id becomes NOT NULL. The dual (server_id, client_id) FK pair is
replaced by a single attachment_id pointer. Unique index migrates from
(tunnel_server_id, tunnel_server_ip_id, protocol, public_port) to
(attachment_id, tunnel_server_ip_id, protocol, public_port).

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("port_forwards", "attachment_id", nullable=False)

    # Drop the legacy unique constraints / partial indexes that reference tunnel_server_id.
    op.execute("ALTER TABLE port_forwards DROP CONSTRAINT IF EXISTS uq_pf_server_ip_proto_port")
    op.execute("DROP INDEX IF EXISTS ix_pf_server_null_ip_proto_port")

    # Drop the legacy FKs + columns.
    op.execute(
        "ALTER TABLE port_forwards DROP CONSTRAINT IF EXISTS port_forwards_tunnel_server_id_fkey"
    )
    op.execute(
        "ALTER TABLE port_forwards DROP CONSTRAINT IF EXISTS port_forwards_tunnel_client_id_fkey"
    )
    op.drop_column("port_forwards", "tunnel_server_id")
    op.drop_column("port_forwards", "tunnel_client_id")

    # Recreate uniqueness over the new pivot column.
    op.create_unique_constraint(
        "uq_pf_attach_ip_proto_port",
        "port_forwards",
        ["attachment_id", "tunnel_server_ip_id", "protocol", "public_port"],
    )
    # Partial unique index covering NULL ip bindings (NULLs are distinct under regular UNIQUE).
    op.create_index(
        "ix_pf_attach_null_ip_proto_port",
        "port_forwards",
        ["attachment_id", "protocol", "public_port"],
        unique=True,
        postgresql_where=sa.text("tunnel_server_ip_id IS NULL"),
    )


def downgrade():
    op.drop_index("ix_pf_attach_null_ip_proto_port", table_name="port_forwards")
    op.drop_constraint("uq_pf_attach_ip_proto_port", "port_forwards", type_="unique")

    op.add_column(
        "port_forwards",
        sa.Column(
            "tunnel_server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_servers.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.add_column(
        "port_forwards",
        sa.Column(
            "tunnel_client_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_clients.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    # Backfill legacy FKs from attachment join so downgrade preserves data.
    op.execute(
        """
        UPDATE port_forwards pf
        SET tunnel_server_id = tca.tunnel_server_id,
            tunnel_client_id = tca.tunnel_client_id
        FROM tunnel_client_attachments tca
        WHERE tca.id = pf.attachment_id
        """
    )

    op.create_unique_constraint(
        "uq_pf_server_ip_proto_port",
        "port_forwards",
        ["tunnel_server_id", "tunnel_server_ip_id", "protocol", "public_port"],
    )
    op.create_index(
        "ix_pf_server_null_ip_proto_port",
        "port_forwards",
        ["tunnel_server_id", "protocol", "public_port"],
        unique=True,
        postgresql_where=sa.text("tunnel_server_ip_id IS NULL"),
    )

    op.alter_column("port_forwards", "attachment_id", nullable=True)

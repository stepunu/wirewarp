"""Add node edge capability state.

Revision ID: 0035
Revises: 0034
Create Date: 2026-05-31
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tunnel_servers",
        sa.Column("edge_mode", sa.String(), nullable=False, server_default="tcp_udp_only"),
    )
    op.add_column(
        "tunnel_servers",
        sa.Column("edge_state", sa.String(), nullable=False, server_default="disabled"),
    )
    op.add_column("tunnel_servers", sa.Column("edge_enabled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tunnel_servers", sa.Column("edge_enabled_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("tunnel_servers", sa.Column("edge_disabled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tunnel_servers", sa.Column("edge_disabled_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column(
        "tunnel_servers",
        sa.Column("edge_install_phase", sa.String(), nullable=False, server_default="disabled"),
    )
    op.add_column("tunnel_servers", sa.Column("edge_last_error", sa.String(), nullable=True))

    op.create_table(
        "edge_component_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("component", sa.String(), nullable=False),
        sa.Column("desired", sa.String(), nullable=False, server_default="disabled"),
        sa.Column("installed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("running", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("phase", sa.String(), nullable=False, server_default="disabled"),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("agent_id", "component", name="uq_edge_component_agent_component"),
    )

    op.execute(
        """
        UPDATE tunnel_servers
        SET edge_mode = 'security_edge',
            edge_state = 'enabled',
            edge_install_phase = 'pending'
        WHERE agent_id IN (
            SELECT agent_id FROM crowdsec_snapshots
            UNION
            SELECT agent_id FROM traefik_snapshots
            UNION
            SELECT ts.agent_id
            FROM tunnel_servers ts
            JOIN tunnel_client_attachments tca ON tca.tunnel_server_id = ts.id
            JOIN port_forwards pf ON pf.attachment_id = tca.id
            WHERE pf.service_kind = 'http'
            UNION
            SELECT ts.agent_id
            FROM tunnel_servers ts
            WHERE ts.edge_rate_limit_rps IS NOT NULL
               OR ts.edge_rate_limit_burst IS NOT NULL
        )
        """
    )


def downgrade() -> None:
    op.drop_table("edge_component_states")
    op.drop_column("tunnel_servers", "edge_last_error")
    op.drop_column("tunnel_servers", "edge_install_phase")
    op.drop_column("tunnel_servers", "edge_disabled_by")
    op.drop_column("tunnel_servers", "edge_disabled_at")
    op.drop_column("tunnel_servers", "edge_enabled_by")
    op.drop_column("tunnel_servers", "edge_enabled_at")
    op.drop_column("tunnel_servers", "edge_state")
    op.drop_column("tunnel_servers", "edge_mode")

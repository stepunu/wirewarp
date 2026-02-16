"""Fix cascade deletes for command_log and tunnel_clients

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-16

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # command_log.agent_id: no action -> SET NULL
    op.drop_constraint("command_log_agent_id_fkey", "command_log", type_="foreignkey")
    op.create_foreign_key(
        "command_log_agent_id_fkey", "command_log", "agents",
        ["agent_id"], ["id"], ondelete="SET NULL",
    )

    # tunnel_clients.tunnel_server_id: no action -> SET NULL
    op.drop_constraint("tunnel_clients_tunnel_server_id_fkey", "tunnel_clients", type_="foreignkey")
    op.create_foreign_key(
        "tunnel_clients_tunnel_server_id_fkey", "tunnel_clients", "tunnel_servers",
        ["tunnel_server_id"], ["id"], ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("tunnel_clients_tunnel_server_id_fkey", "tunnel_clients", type_="foreignkey")
    op.create_foreign_key(
        "tunnel_clients_tunnel_server_id_fkey", "tunnel_clients", "tunnel_servers",
        ["tunnel_server_id"], ["id"],
    )

    op.drop_constraint("command_log_agent_id_fkey", "command_log", type_="foreignkey")
    op.create_foreign_key(
        "command_log_agent_id_fkey", "command_log", "agents",
        ["agent_id"], ["id"],
    )

"""Add 'vpn_user' role.

Extends the users.role CHECK constraint with a new value `vpn_user`,
representing end-users whose only purpose is to download a WireGuard
profile from /vpn. They have no access to operational pages.

Revision ID: 0019
Revises: 0018
Create Date: 2026-05-10
"""

from alembic import op


revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('admin','operator','viewer','vpn_user')",
    )


def downgrade() -> None:
    # Refuse to downgrade if any vpn_user rows exist — caller must
    # demote them first.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM users WHERE role = 'vpn_user') "
        "THEN RAISE EXCEPTION 'Cannot downgrade: vpn_user rows present'; "
        "END IF; END $$;"
    )
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('admin','operator','viewer')",
    )

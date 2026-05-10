"""VPN permissions are per-(user, endpoint), not per-profile.

The original design keyed `vpn_permissions` on `vpn_profile_id`. That
meant the operator could only configure access AFTER the user had
created a profile — backwards. The intent is "admin pre-provisions
what Alice can reach on this gateway, then any device profile she
creates inherits those rules". So we re-shape the table:

  * drop the FK to `vpn_profiles.id`
  * add `user_id` (FK -> users) and `vpn_endpoint_id` (FK -> vpn_endpoints)
  * existing rows are migrated by joining through the deleted
    `vpn_profile_id`. If there are no rules yet (the typical case for
    early adopters), the migration is a structural no-op.

Revision ID: 0018
Revises: 0017
Create Date: 2026-05-10
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    op.add_column(
        "vpn_permissions",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "vpn_permissions",
        sa.Column(
            "vpn_endpoint_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
    )

    # Backfill existing rows by joining through vpn_profiles. Safe even
    # if no rows exist.
    bind.execute(
        sa.text(
            """
            UPDATE vpn_permissions vp
               SET user_id = p.user_id,
                   vpn_endpoint_id = p.vpn_endpoint_id
              FROM vpn_profiles p
             WHERE p.id = vp.vpn_profile_id
            """
        )
    )

    # Anything that didn't get backfilled (orphan rows) gets dropped —
    # there's no sensible (user, endpoint) target for them.
    bind.execute(
        sa.text("DELETE FROM vpn_permissions WHERE user_id IS NULL OR vpn_endpoint_id IS NULL")
    )

    op.alter_column("vpn_permissions", "user_id", nullable=False)
    op.alter_column("vpn_permissions", "vpn_endpoint_id", nullable=False)

    op.create_foreign_key(
        "fk_vpn_permissions_user",
        "vpn_permissions",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_vpn_permissions_endpoint",
        "vpn_permissions",
        "vpn_endpoints",
        ["vpn_endpoint_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_index("ix_vpn_permissions_profile_id", table_name="vpn_permissions")
    op.drop_constraint(
        "vpn_permissions_vpn_profile_id_fkey",
        "vpn_permissions",
        type_="foreignkey",
    )
    op.drop_column("vpn_permissions", "vpn_profile_id")

    op.create_index(
        "ix_vpn_permissions_user_endpoint",
        "vpn_permissions",
        ["user_id", "vpn_endpoint_id"],
    )


def downgrade() -> None:
    op.add_column(
        "vpn_permissions",
        sa.Column(
            "vpn_profile_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
    )
    op.drop_index(
        "ix_vpn_permissions_user_endpoint", table_name="vpn_permissions"
    )
    op.drop_constraint(
        "fk_vpn_permissions_endpoint", "vpn_permissions", type_="foreignkey"
    )
    op.drop_constraint(
        "fk_vpn_permissions_user", "vpn_permissions", type_="foreignkey"
    )
    # Best-effort: pick the first profile per (user, endpoint) and assign
    # all that user's rules to it. Not lossless, but downgrade is dev-only.
    op.execute(
        """
        UPDATE vpn_permissions vp
           SET vpn_profile_id = (
             SELECT id FROM vpn_profiles
              WHERE user_id = vp.user_id
                AND vpn_endpoint_id = vp.vpn_endpoint_id
              ORDER BY created_at
              LIMIT 1
           )
        """
    )
    op.execute(
        "DELETE FROM vpn_permissions WHERE vpn_profile_id IS NULL"
    )
    op.alter_column("vpn_permissions", "vpn_profile_id", nullable=False)
    op.create_foreign_key(
        "vpn_permissions_vpn_profile_id_fkey",
        "vpn_permissions",
        "vpn_profiles",
        ["vpn_profile_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_vpn_permissions_profile_id",
        "vpn_permissions",
        ["vpn_profile_id"],
    )
    op.drop_column("vpn_permissions", "vpn_endpoint_id")
    op.drop_column("vpn_permissions", "user_id")

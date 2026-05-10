"""multi-server gateway: add port_forwards.attachment_id with backfill

Backfill via JOIN on (tunnel_client_id, tunnel_server_id). If any pf row
remains NULL after backfill we abort the migration loudly — better to block
the deploy than silently orphan iptables rules.

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "port_forwards",
        sa.Column(
            "attachment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tunnel_client_attachments.id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE port_forwards pf
        SET attachment_id = tca.id
        FROM tunnel_client_attachments tca
        WHERE tca.tunnel_client_id = pf.tunnel_client_id
          AND tca.tunnel_server_id = pf.tunnel_server_id
        """
    )

    # Fail loudly if any port_forwards row could not be matched to an attachment.
    op.execute(
        """
        DO $$
        DECLARE orphan_count int;
        BEGIN
            SELECT COUNT(*) INTO orphan_count FROM port_forwards WHERE attachment_id IS NULL;
            IF orphan_count > 0 THEN
                RAISE EXCEPTION
                    'orphaned port_forwards: % rows have no matching tunnel_client_attachment. Refusing to drop legacy columns.',
                    orphan_count;
            END IF;
        END $$;
        """
    )


def downgrade():
    op.execute(
        "ALTER TABLE port_forwards DROP CONSTRAINT IF EXISTS port_forwards_attachment_id_fkey"
    )
    op.drop_column("port_forwards", "attachment_id")

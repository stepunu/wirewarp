"""Add RFC2136 credentials for managed ACME DNS challenges."""
from alembic import op
import sqlalchemy as sa

revision = "0040_rfc2136_acme_settings"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name in ("nameserver", "tsig_key", "tsig_secret"):
        op.add_column("system_settings", sa.Column(f"letsencrypt_rfc2136_{name}", sa.String(), nullable=True))
    op.add_column("system_settings", sa.Column("letsencrypt_rfc2136_tsig_algorithm", sa.String(), nullable=False, server_default="hmac-sha256"))
    op.add_column("system_settings", sa.Column("letsencrypt_dns_delay_seconds", sa.Integer(), nullable=False, server_default="30"))


def downgrade() -> None:
    op.drop_column("system_settings", "letsencrypt_dns_delay_seconds")
    for name in ("tsig_algorithm", "tsig_secret", "tsig_key", "nameserver"):
        op.drop_column("system_settings", f"letsencrypt_rfc2136_{name}")

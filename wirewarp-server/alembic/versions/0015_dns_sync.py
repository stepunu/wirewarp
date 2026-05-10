"""DNS sync infrastructure: per-LAN-client record list + provider settings.

When a LAN client's egress IP changes, the operator usually wants their
public DNS records to follow so existing hostnames keep resolving to a
working VPS. Schema:

  * `gateway_lan_clients.dns_record_ids`: array of {provider, zone_id,
    record_id, name} entries. Each entry is one DNS A record that should
    be PATCHed to the new egress IP whenever this LAN client's egress
    changes. JSONB so the per-record metadata can vary by provider.

  * `system_settings.dns_provider`: which provider implementation to
    invoke. NULL means DNS sync is disabled — egress changes still work
    but the dashboard surfaces a "update DNS manually" notice instead.

  * `system_settings.cloudflare_api_token`: token for the CF provider.
    Stored plain (the operator already trusts the database with admin
    creds + agent JWTs); the dashboard never returns it back, only a
    masked indicator that one is set.

Revision ID: 0015
Revises: 0014
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "gateway_lan_clients",
        sa.Column(
            "dns_record_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.add_column(
        "system_settings",
        sa.Column("dns_provider", sa.String(), nullable=True),
    )
    op.add_column(
        "system_settings",
        sa.Column("cloudflare_api_token", sa.String(), nullable=True),
    )


def downgrade():
    op.drop_column("system_settings", "cloudflare_api_token")
    op.drop_column("system_settings", "dns_provider")
    op.drop_column("gateway_lan_clients", "dns_record_ids")

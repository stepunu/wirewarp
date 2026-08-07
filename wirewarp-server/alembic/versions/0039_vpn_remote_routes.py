"""Add stable VPN client route state.

Revision ID: 0039
Revises: 0038_edge_upstream_pools
Create Date: 2026-08-07
"""
from __future__ import annotations

import ipaddress
import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0039"
down_revision = "0038_edge_upstream_pools"
branch_labels = None
depends_on = None


def _ipv4_network(value: str | None) -> ipaddress.IPv4Network | None:
    if not value:
        return None
    try:
        return ipaddress.IPv4Network(value, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None


def _canonical_route_envelope(
    vm_network: str | None,
    vpn_network: str,
    permission_destinations: list[str],
) -> list[str]:
    """Build a minimal canonical route list for one existing endpoint."""
    vpn = _ipv4_network(vpn_network)
    routes: list[ipaddress.IPv4Network] = []
    for value in [vm_network, *permission_destinations]:
        candidate = _ipv4_network(value)
        if candidate is None or candidate.prefixlen == 0:
            continue
        if vpn is not None and candidate.overlaps(vpn):
            continue
        if any(candidate.subnet_of(existing) for existing in routes):
            continue
        routes = [
            existing for existing in routes if not existing.subnet_of(candidate)
        ]
        routes.append(candidate)
    return [route.with_prefixlen for route in routes]


def upgrade() -> None:
    op.add_column(
        "vpn_endpoints",
        sa.Column(
            "remote_subnets",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "vpn_endpoints",
        sa.Column("route_revision", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "vpn_profiles",
        sa.Column("issued_route_revision", sa.Integer(), nullable=True),
    )

    bind = op.get_bind()
    endpoints = bind.execute(
        sa.text(
            """
            SELECT ve.id, ve.vpn_network, tc.vm_network
            FROM vpn_endpoints AS ve
            JOIN tunnel_clients AS tc ON tc.id = ve.tunnel_client_id
            ORDER BY ve.id
            """
        )
    ).mappings()
    for endpoint in endpoints:
        destinations = list(
            bind.execute(
                sa.text(
                    """
                    SELECT destination
                    FROM vpn_permissions
                    WHERE vpn_endpoint_id = :endpoint_id
                    ORDER BY id
                    """
                ),
                {"endpoint_id": endpoint["id"]},
            ).scalars()
        )
        routes = _canonical_route_envelope(
            endpoint["vm_network"], endpoint["vpn_network"], destinations
        )
        bind.execute(
            sa.text(
                """
                UPDATE vpn_endpoints
                SET remote_subnets = CAST(:routes AS jsonb)
                WHERE id = :endpoint_id
                """
            ),
            {"routes": json.dumps(routes), "endpoint_id": endpoint["id"]},
        )


def downgrade() -> None:
    op.drop_column("vpn_profiles", "issued_route_revision")
    op.drop_column("vpn_endpoints", "route_revision")
    op.drop_column("vpn_endpoints", "remote_subnets")

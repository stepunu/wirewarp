"""Split comma- or whitespace-joined `destination` values into one row each.

Until now, the API accepted a literal joined string in
`vpn_permissions.destination` (e.g.
`"192.168.20.5/32,192.168.20.90/32"`) because the Pydantic schema
didn't validate the field. The agent's `validate.IPv4CIDR` rejects
those strings, so the `vpn_peer_add` command fails and the peer never
appears in `wg-vpn0` — the user can't connect.

The new schema validator (`VpnPermissionInput.destination`) rejects
joined input at the API boundary; this migration cleans up the rows
already written that way. For every (user_id, vpn_endpoint_id,
protocol, port_range_start, port_range_end) row whose destination
contains a separator (`,`, `;`, or whitespace), we split it into N
rows, one per IPv4 host/CIDR, and delete the original.

After running, the operator should re-dispatch `vpn_peer_add` for the
affected (user, endpoint) pairs. The simplest path is to delete and
recreate the profile in the dashboard — that flow already calls
`dispatch_vpn_peer_add` with the now-correct permission set. The list
of affected pairs is logged at migration time.

Revision ID: 0024
Revises: 0023
Create Date: 2026-05-24
"""
from __future__ import annotations

import logging
import re

from alembic import op
import sqlalchemy as sa


revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


_SEP = re.compile(r"[\s,;]+")


def upgrade() -> None:
    bind = op.get_bind()
    log = logging.getLogger("alembic.0024")

    rows = bind.execute(
        sa.text(
            """
            SELECT id, user_id, vpn_endpoint_id, destination, protocol,
                   port_range_start, port_range_end
              FROM vpn_permissions
             WHERE destination ~ '[,;\\s]'
            """
        )
    ).fetchall()

    affected_pairs: set[tuple[str, str]] = set()
    rewritten = 0
    dropped_orphans = 0
    for r in rows:
        parts = [p for p in (s.strip() for s in _SEP.split(r.destination or "")) if p]
        if not parts:
            bind.execute(
                sa.text("DELETE FROM vpn_permissions WHERE id = :id"),
                {"id": r.id},
            )
            dropped_orphans += 1
            continue

        bind.execute(
            sa.text("DELETE FROM vpn_permissions WHERE id = :id"),
            {"id": r.id},
        )
        for dest in parts:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO vpn_permissions
                      (id, user_id, vpn_endpoint_id, destination, protocol,
                       port_range_start, port_range_end)
                    VALUES
                      (gen_random_uuid(), :uid, :eid, :dest, :proto,
                       :prs, :pre)
                    """
                ),
                {
                    "uid": r.user_id,
                    "eid": r.vpn_endpoint_id,
                    "dest": dest,
                    "proto": r.protocol,
                    "prs": r.port_range_start,
                    "pre": r.port_range_end,
                },
            )
            rewritten += 1
        affected_pairs.add((str(r.user_id), str(r.vpn_endpoint_id)))

    if affected_pairs:
        log.warning(
            "0024: rewrote %d joined-destination rows into %d rows across "
            "%d (user, endpoint) pairs. Recreate the affected VPN profiles "
            "in the dashboard so the gateway gets a fresh vpn_peer_add. "
            "Pairs (user_id, endpoint_id): %s",
            len(rows),
            rewritten,
            len(affected_pairs),
            sorted(affected_pairs),
        )
    if dropped_orphans:
        log.warning(
            "0024: dropped %d empty-destination rows.", dropped_orphans
        )


def downgrade() -> None:
    # The split is lossy in the inverse direction (we no longer know which
    # rows used to share a single string), so downgrade is a no-op.
    pass

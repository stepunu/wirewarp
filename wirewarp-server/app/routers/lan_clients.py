"""Discovered LAN clients per gateway + per-host egress pinning.

The list is populated by the gateway agent's heartbeat (see
`app.websocket.handlers.handle_heartbeat`) — a passive scrape of the
gateway's conntrack table for flows originating in the LAN subnet
heading to non-LAN destinations, joined with the kernel ARP cache for
MAC info.

The pin has two layers:
  * `egress_attachment_id` controls *routing* — `ip rule from <lan_ip>
    table <route_table_id>` on the gateway, sending the host's outbound
    through the chosen wgN.
  * `egress_tunnel_server_ip_id` controls *source NAT on the VPS* — a
    per-host SNAT rule rewrites the public source to that specific IP
    rather than the server's primary (the default MASQUERADE behaviour).

Both layers can be cleared independently. If the routing pin is
cleared, the IP pin is also cleared (no point SNAT-pinning if traffic
isn't taking the tunnel anymore).
"""

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.gateway_lan_client import GatewayLanClient
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.user import User
from sqlalchemy.exc import IntegrityError

from app.schemas.gateway_lan_client import (
    GatewayLanClientCreate,
    GatewayLanClientRead,
    GatewayLanClientUpdate,
)
from app.auth import get_current_user, require_role, require_ops_role
from app.models.system_settings import SystemSettings
from app.realtime.bus import bus
from app.realtime.events import (
    emit_lan_client_changed,
    emit_port_forward_changed,
    emit_tunnel_server_changed,
)
from app.routers.port_forwards import migrate_port_forwards_to_pin
from app.services.port_forward_ops import serialize_server_runtime_mutation
from app.services.dns_sync import (
    DiscoveredRecord,
    provider_from_settings,
    sync_lan_client_egress,
)
from app.services.tunnel_server_ops import (
    dispatch_set_lan_egress,
    dispatch_set_lan_snat,
)
from app.websocket.hub import manager

logger = logging.getLogger(__name__)

router = APIRouter()


async def _resolve_new_ip_address(
    attachment: TunnelClientAttachment,
    explicit_ip_id: uuid.UUID | None,
    db: AsyncSession,
) -> str | None:
    """Determine the public IP an egress pin maps to: explicit IP if set,
    else the attachment's server's primary. Used to drive DNS sync —
    the records get pointed at this address.
    """
    from app.services.primary_ip import get_primary_ip
    if explicit_ip_id is not None:
        ip = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.id == explicit_ip_id))
        if ip is not None:
            return ip.address
    return await get_primary_ip(attachment.tunnel_server_id, db)


async def _run_dns_sync(
    lan_client: GatewayLanClient,
    new_ip: str,
    db: AsyncSession,
) -> None:
    """Push the egress IP change to the configured DNS provider for every
    record on this LAN client's `dns_record_ids` list. If no provider is
    configured (open-source operators not on Cloudflare), publish a
    `dns.manual_update_needed` event so the dashboard can surface a
    notice listing what to update by hand.

    Failures are logged but never raised — DNS sync is best-effort
    metadata, the data plane (DNAT + SNAT) has already been applied.
    """
    records = lan_client.dns_record_ids or []
    if not records:
        return

    settings = await db.get(SystemSettings, 1)
    provider = provider_from_settings(settings) if settings is not None else None
    if provider is None:
        bus.publish_nowait(
            "dns.manual_update_needed",
            lan_ip=lan_client.lan_ip,
            new_ip=new_ip,
            records=[r.get("name", "?") for r in records],
        )
        logger.info(
            "DNS sync skipped (no provider configured) — operator must "
            "manually point %d record(s) at %s",
            len(records), new_ip,
        )
        return

    updated, failed = await sync_lan_client_egress(records, new_ip, provider)
    if updated:
        bus.publish_nowait(
            "dns.synced",
            lan_ip=lan_client.lan_ip,
            new_ip=new_ip,
            records=updated,
        )
    if failed:
        bus.publish_nowait(
            "dns.sync_failed",
            lan_ip=lan_client.lan_ip,
            failures=[{"name": n, "error": e} for n, e in failed],
        )


async def _resolve_ip(
    ip_id: uuid.UUID, attachment: TunnelClientAttachment, db: AsyncSession
) -> TunnelServerIP:
    """Fetch the TunnelServerIP and verify it belongs to the attachment's
    server. 400 otherwise — operators should not be able to mix-and-match
    an IP from one server onto an attachment for a different server.
    """
    ip_row = await db.scalar(select(TunnelServerIP).where(TunnelServerIP.id == ip_id))
    if ip_row is None:
        raise HTTPException(
            status_code=400,
            detail=f"egress_tunnel_server_ip_id {ip_id} not found",
        )
    if ip_row.tunnel_server_id != attachment.tunnel_server_id:
        raise HTTPException(
            status_code=400,
            detail=(
                "egress_tunnel_server_ip_id must belong to the same tunnel "
                "server as egress_attachment_id"
            ),
        )
    return ip_row


@router.get("/lan-clients", response_model=list[GatewayLanClientRead])
async def list_all_lan_clients(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """All discovered LAN clients across every gateway. Used by the
    top-level LAN clients page so it can render one table covering the
    whole homelab without N round trips.
    """
    rows = await db.execute(
        select(GatewayLanClient).order_by(GatewayLanClient.last_seen.desc())
    )
    return rows.scalars().all()


@router.get(
    "/tunnel-clients/{client_id}/lan-clients",
    response_model=list[GatewayLanClientRead],
)
async def list_lan_clients(
    client_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    rows = await db.execute(
        select(GatewayLanClient)
        .where(GatewayLanClient.tunnel_client_id == client_id)
        .order_by(GatewayLanClient.last_seen.desc())
    )
    return rows.scalars().all()


@router.post(
    "/tunnel-clients/{client_id}/lan-clients",
    response_model=GatewayLanClientRead,
    status_code=201,
)
async def create_lan_client(
    client_id: uuid.UUID,
    body: GatewayLanClientCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    if body.egress_attachment_id is not None or body.egress_tunnel_server_ip_id is not None:
        async with serialize_server_runtime_mutation(uuid.UUID(int=0), db):
            return await _create_lan_client_locked(client_id, body, db)
    return await _create_lan_client_locked(client_id, body, db)


async def _create_lan_client_locked(
    client_id: uuid.UUID,
    body: GatewayLanClientCreate,
    db: AsyncSession,
):
    """Manually register a LAN host. Useful when the host hasn't sent any
    public-bound traffic yet so the agent's conntrack scrape hasn't
    discovered it, or when you want to pre-configure an egress pin
    before traffic flows. The (tunnel_client_id, lan_ip) UNIQUE
    constraint makes this idempotent — re-POSTing returns 409.
    """
    client = await db.scalar(select(TunnelClient).where(TunnelClient.id == client_id))
    if client is None:
        raise HTTPException(status_code=404, detail="Gateway client not found")
    if (
        body.egress_attachment_id is not None
        or body.egress_tunnel_server_ip_id is not None
    ) and not client.is_gateway:
        raise HTTPException(
            status_code=409,
            detail="LAN egress can only be assigned to a gateway client",
        )

    attachment: TunnelClientAttachment | None = None
    new_ip_row: TunnelServerIP | None = None
    if body.egress_attachment_id is not None:
        attachment = await db.scalar(
            select(TunnelClientAttachment).where(
                TunnelClientAttachment.id == body.egress_attachment_id,
                TunnelClientAttachment.tunnel_client_id == client_id,
            )
        )
        if attachment is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "egress_attachment_id must reference an attachment owned "
                    "by this gateway client"
                ),
            )
        if not manager.is_connected(str(client.agent_id)):
            raise HTTPException(
                status_code=503,
                detail=(
                    f"Gateway agent (id={client.agent_id}) not connected — "
                    "bring it back online and retry, or omit egress_attachment_id."
                ),
            )
        if body.egress_tunnel_server_ip_id is not None:
            new_ip_row = await _resolve_ip(body.egress_tunnel_server_ip_id, attachment, db)
    elif body.egress_tunnel_server_ip_id is not None:
        raise HTTPException(
            status_code=400,
            detail="egress_tunnel_server_ip_id requires egress_attachment_id to be set",
        )

    migration = None
    if attachment is not None:
        migration = await migrate_port_forwards_to_pin(
            body.lan_ip,
            attachment.id,
            body.egress_tunnel_server_ip_id,
            db,
            runtime_lock_held=True,
        )

    lan_client = GatewayLanClient(
        tunnel_client_id=client_id,
        lan_ip=body.lan_ip,
        mac=body.mac,
        hostname=body.hostname,
        egress_attachment_id=body.egress_attachment_id,
        egress_tunnel_server_ip_id=body.egress_tunnel_server_ip_id,
        dns_record_ids=[r.model_dump() for r in body.dns_record_ids] if body.dns_record_ids else None,
    )
    db.add(lan_client)
    try:
        await db.commit()
    except IntegrityError:
        if migration is not None:
            await asyncio.shield(migration.abort(db))
        else:
            await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"LAN client {body.lan_ip} already registered on this gateway",
        )
    except BaseException:
        if migration is not None:
            await asyncio.shield(migration.abort(db))
        else:
            await db.rollback()
        raise
    if migration is not None:
        await asyncio.shield(migration.complete(db))
        if migration.count:
            emit_port_forward_changed()
            emit_tunnel_server_changed()
    await db.refresh(lan_client)

    if attachment is not None:
        await dispatch_set_lan_egress(client, lan_client.lan_ip, attachment, db)
        if new_ip_row is not None:
            server = await db.scalar(
                select(TunnelServer).where(TunnelServer.id == attachment.tunnel_server_id)
            )
            if server is not None:
                await dispatch_set_lan_snat(server, lan_client.lan_ip, new_ip_row.address, db)
        new_ip = await _resolve_new_ip_address(attachment, body.egress_tunnel_server_ip_id, db)
        if new_ip:
            await _run_dns_sync(lan_client, new_ip, db)
    emit_lan_client_changed()
    return lan_client


@router.patch(
    "/tunnel-clients/{client_id}/lan-clients/{lan_client_id}",
    response_model=GatewayLanClientRead,
)
async def update_lan_client(
    client_id: uuid.UUID,
    lan_client_id: uuid.UUID,
    body: GatewayLanClientUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    fields_set = body.model_fields_set
    if (
        "egress_attachment_id" in fields_set
        or "egress_tunnel_server_ip_id" in fields_set
    ):
        async with serialize_server_runtime_mutation(uuid.UUID(int=0), db):
            return await _update_lan_client_locked(client_id, lan_client_id, body, db)
    return await _update_lan_client_locked(client_id, lan_client_id, body, db)


async def _update_lan_client_locked(
    client_id: uuid.UUID,
    lan_client_id: uuid.UUID,
    body: GatewayLanClientUpdate,
    db: AsyncSession,
):
    lan_client = await db.scalar(
        select(GatewayLanClient).where(
            GatewayLanClient.id == lan_client_id,
            GatewayLanClient.tunnel_client_id == client_id,
        )
    )
    if lan_client is None:
        raise HTTPException(status_code=404, detail="LAN client not found")

    client = await db.scalar(
        select(TunnelClient).where(TunnelClient.id == client_id)
    )
    if client is None:
        raise HTTPException(status_code=404, detail="Gateway client not found")

    # Capture prior state for delta dispatch (clearing the old SNAT on the
    # old VPS before installing the new one on the new VPS).
    prev_attachment_id = lan_client.egress_attachment_id
    prev_ip_id = lan_client.egress_tunnel_server_ip_id
    prev_ip_row = (
        await db.scalar(select(TunnelServerIP).where(TunnelServerIP.id == prev_ip_id))
        if prev_ip_id is not None
        else None
    )
    prev_attachment = (
        await db.scalar(
            select(TunnelClientAttachment).where(
                TunnelClientAttachment.id == prev_attachment_id
            )
        )
        if prev_attachment_id is not None
        else None
    )

    attachment: TunnelClientAttachment | None = None
    new_ip_row: TunnelServerIP | None = None
    if body.egress_attachment_id is not None:
        attachment = await db.scalar(
            select(TunnelClientAttachment).where(
                TunnelClientAttachment.id == body.egress_attachment_id,
                TunnelClientAttachment.tunnel_client_id == client_id,
            )
        )
        if attachment is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "egress_attachment_id must reference an attachment owned "
                    "by this gateway client"
                ),
            )
        if body.egress_tunnel_server_ip_id is not None:
            new_ip_row = await _resolve_ip(body.egress_tunnel_server_ip_id, attachment, db)
    elif body.egress_tunnel_server_ip_id is not None:
        raise HTTPException(
            status_code=400,
            detail="egress_tunnel_server_ip_id requires egress_attachment_id to be set",
        )

    fields_set = body.model_fields_set
    # Only touch egress fields when the caller actually sent them — a
    # PATCH that just updates hostname/mac shouldn't accidentally clear
    # an existing egress pin.
    egress_touched = (
        "egress_attachment_id" in fields_set
        or "egress_tunnel_server_ip_id" in fields_set
    )
    if egress_touched and not client.is_gateway:
        raise HTTPException(
            status_code=409,
            detail="LAN egress can only be changed for a gateway client",
        )

    # The agent-online gate only matters when we're going to dispatch
    # routing/SNAT commands. Pure metadata edits (hostname, MAC, DNS
    # bindings) don't talk to the agent.
    if egress_touched and not manager.is_connected(str(client.agent_id)):
        raise HTTPException(
            status_code=503,
            detail=(
                f"Gateway agent (id={client.agent_id}) not connected — "
                "bring it back online and retry."
            ),
        )
    migration = None
    if egress_touched and attachment is not None:
        migration = await migrate_port_forwards_to_pin(
            lan_client.lan_ip,
            attachment.id,
            body.egress_tunnel_server_ip_id,
            db,
            runtime_lock_held=True,
        )
    if egress_touched:
        lan_client.egress_attachment_id = body.egress_attachment_id
        lan_client.egress_tunnel_server_ip_id = body.egress_tunnel_server_ip_id
    # dns_record_ids can be patched independently of the egress fields —
    # operator wires up which records track this host once, then changes
    # egress freely. None on the body means "leave as-is"; an explicit
    # empty list clears the binding.
    if body.dns_record_ids is not None:
        lan_client.dns_record_ids = (
            [r.model_dump() for r in body.dns_record_ids]
            if body.dns_record_ids
            else None
        )
    # Hostname / MAC: empty string clears (back to auto-discovery), any
    # other value pins the operator override. Heartbeat-upsert only fills
    # these when they're null/empty, so the override sticks.
    if "hostname" in fields_set:
        lan_client.hostname = body.hostname or None
    if "mac" in fields_set:
        lan_client.mac = body.mac or None
    try:
        await db.commit()
    except BaseException:
        if migration is not None:
            await asyncio.shield(migration.abort(db))
        else:
            await db.rollback()
        raise
    if migration is not None:
        await asyncio.shield(migration.complete(db))
        if migration.count:
            emit_port_forward_changed()
            emit_tunnel_server_changed()
    await db.refresh(lan_client)

    if egress_touched:
        # Routing pin: always re-issue (covers both set and clear).
        await dispatch_set_lan_egress(client, lan_client.lan_ip, attachment, db)

        # SNAT delta: clear the old VPS rule if the IP pin moved off it, then
        # set on the new VPS. Skipped when both old and new are None or when
        # the IP id didn't actually change.
        if prev_ip_id is not None and prev_ip_id != body.egress_tunnel_server_ip_id:
            if prev_attachment is not None:
                old_server = await db.scalar(
                    select(TunnelServer).where(TunnelServer.id == prev_attachment.tunnel_server_id)
                )
                if old_server is not None and prev_ip_row is not None:
                    await dispatch_set_lan_snat(old_server, lan_client.lan_ip, None, db)

        if new_ip_row is not None and attachment is not None:
            server = await db.scalar(
                select(TunnelServer).where(TunnelServer.id == attachment.tunnel_server_id)
            )
            if server is not None:
                await dispatch_set_lan_snat(server, lan_client.lan_ip, new_ip_row.address, db)

        # Auto-migrate matching port forwards so inbound (DNAT) follows the new
        # outbound pin. Skipped when egress is being cleared — operator may want
        # the forwards to keep working independently of the egress pin.
        if attachment is not None:
            new_ip = await _resolve_new_ip_address(attachment, body.egress_tunnel_server_ip_id, db)
            if new_ip:
                await _run_dns_sync(lan_client, new_ip, db)

    emit_lan_client_changed()
    return lan_client


@router.delete(
    "/tunnel-clients/{client_id}/lan-clients/{lan_client_id}",
    status_code=204,
)
async def delete_lan_client(
    client_id: uuid.UUID,
    lan_client_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator")),
):
    """Reject deletion until runtime pin removal has durable delivery."""
    lan_client = await db.scalar(
        select(GatewayLanClient).where(
            GatewayLanClient.id == lan_client_id,
            GatewayLanClient.tunnel_client_id == client_id,
        )
    )
    if lan_client is None:
        raise HTTPException(status_code=404, detail="LAN client not found")
    raise HTTPException(
        status_code=409,
        detail=(
            "LAN client deletion is blocked because egress and SNAT cleanup "
            "cannot be delivered durably while agents are offline. Clear its "
            "pins first and preserve the discovered row."
        ),
    )


# --- DNS provider helpers ---


@router.get("/lan-clients/dns/zones")
async def list_dns_zones(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """List zones the configured DNS provider knows about. Used by the
    LAN-client edit dialog to populate the zone picker before record
    discovery. 503 when no provider is configured.
    """
    settings = await db.get(SystemSettings, 1)
    provider = provider_from_settings(settings) if settings is not None else None
    if provider is None:
        raise HTTPException(status_code=503, detail="DNS sync provider not configured")
    return await provider.list_zones()


@router.get("/lan-clients/dns/discover")
async def discover_dns_records(
    zone_id: str,
    ip: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    """Return every A record in `zone_id` whose value is `ip`. Used by
    the "discover records" button so operators don't have to type FQDNs
    by hand for the common case of "track the records that already
    point here".
    """
    settings = await db.get(SystemSettings, 1)
    provider = provider_from_settings(settings) if settings is not None else None
    if provider is None:
        raise HTTPException(status_code=503, detail="DNS sync provider not configured")
    records = await provider.discover_a_records_for_ip(zone_id, ip)
    return [
        {
            "provider": "cloudflare",
            "zone_id": r.zone_id,
            "record_id": r.record_id,
            "name": r.name,
            "content": r.content,
        }
        for r in records
    ]

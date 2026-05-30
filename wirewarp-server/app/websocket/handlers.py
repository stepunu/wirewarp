import logging
import re
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select, func

from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.models.gateway_lan_client import GatewayLanClient
from app.models.heal_event import AgentHealEvent
from app.models.metric import Metric
from app.models.security_event import SecurityEvent
from app.models.traefik_snapshot import TraefikSnapshot
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.tunnel_server_ip import TunnelServerIP
from app.models.tunnel_client import TunnelClient
from app.models.vpn_endpoint import VpnEndpoint
from app.models.vpn_profile import VpnProfile
from app.models.wg_peer_snapshot import WgPeerSnapshot
from app.realtime.events import (
    emit_agent_changed,
    emit_audit_changed,
    emit_crowdsec_changed,
    emit_edge_changed,
    emit_heal_event_changed,
    emit_lan_client_changed,
    emit_security_changed,
    emit_traefik_changed,
    emit_tunnel_client_changed,
    emit_tunnel_server_changed,
    emit_wg_peer_changed,
)
from app.services.crowdsec_ops import build_whitelist, whitelist_hash
from app.services.edge_ops import component_phase, dispatch_edge_desired_state
from app.services.tunnel_server_ops import dispatch_add_peer_for_attachment, dispatch_wg_init

logger = logging.getLogger(__name__)

# How long an UNPINNED LAN client may stay in the discovery list without
# being seen again before it's evicted. Pinned rows
# (egress_attachment_id IS NOT NULL) ignore this — operator intent is
# sticky regardless of whether the host is currently active.
LAN_CLIENT_TTL = timedelta(minutes=30)


async def handle_heartbeat(agent_id: str, msg: dict, db: AsyncSession) -> None:
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        return

    agent.last_seen = datetime.now(timezone.utc)
    agent_dirty = False
    server_dirty = False
    lan_dirty = False

    if version := msg.get("version"):
        if version != agent.version:
            agent_dirty = True
        agent.version = version

    public_ip = msg.get("public_ip")
    if public_ip and public_ip != agent.public_ip:
        agent.public_ip = public_ip
        agent_dirty = True

    # For server agents, ensure every reported IP is in the tunnel_server_ips
    # pool. Heartbeat is additive only: never demote, never delete.
    server_for_init: TunnelServer | None = None
    seeded_primary = False
    if agent.type == "server":
        candidate_ips: list[str] = []
        seen: set[str] = set()
        if public_ip:
            candidate_ips.append(public_ip)
            seen.add(public_ip)
        for ip_addr in msg.get("public_ips") or []:
            if isinstance(ip_addr, str) and ip_addr and ip_addr not in seen:
                candidate_ips.append(ip_addr)
                seen.add(ip_addr)

        if candidate_ips:
            server = await db.scalar(
                select(TunnelServer).where(TunnelServer.agent_id == agent_id)
            )
            if server:
                for ip_addr in candidate_ips:
                    existing = await db.scalar(
                        select(TunnelServerIP).where(
                            TunnelServerIP.tunnel_server_id == server.id,
                            TunnelServerIP.address == ip_addr,
                        )
                    )
                    if existing is not None:
                        continue
                    pool_size = await db.scalar(
                        select(func.count(TunnelServerIP.id)).where(
                            TunnelServerIP.tunnel_server_id == server.id
                        )
                    )
                    db.add(
                        TunnelServerIP(
                            tunnel_server_id=server.id,
                            address=ip_addr,
                            is_primary=(pool_size == 0),
                        )
                    )
                    server_dirty = True
                    if pool_size == 0:
                        seeded_primary = True
                    logger.info(
                        "Added discovered IP %s to tunnel server %s pool (primary=%s)",
                        ip_addr, server.id, pool_size == 0,
                    )
                # If we just seeded the first IP and wg_init never succeeded
                # (wg_public_key still empty), fire wg_init now. Fixes the
                # first-connect race where dispatch_wg_init runs before the
                # initial heartbeat populates tunnel_server_ips.
                if seeded_primary and not (server.wg_public_key or ""):
                    server_for_init = server

                # Auto-detect WAN iface: the agent reports its default-route
                # iface. The column default is "eth0" as a placeholder; if it's
                # still that and the agent reports a different real iface,
                # adopt it and re-fire wg_init so SNAT/MASQUERADE rebind.
                # Operator overrides via PATCH win once public_iface != "eth0".
                reported_iface = msg.get("public_iface")
                if (
                    isinstance(reported_iface, str)
                    and reported_iface
                    and reported_iface != server.public_iface
                    and server.public_iface == "eth0"
                ):
                    logger.info(
                        "Auto-detected public_iface=%s for tunnel server %s (was %s)",
                        reported_iface, server.id, server.public_iface,
                    )
                    server.public_iface = reported_iface
                    server_dirty = True
                    server_for_init = server

    # Gateway client agents report observed LAN hosts via heartbeat. Upsert
    # them into gateway_lan_clients so the dashboard can display + offer
    # egress pinning. The agent only emits this list for clients that have
    # `is_gateway=true` and at least one active LAN-egress flow.
    lan_clients_report = msg.get("lan_clients")
    if isinstance(lan_clients_report, list):
        client_row = await db.scalar(
            select(TunnelClient).where(TunnelClient.agent_id == agent_id)
        )
        if client_row is not None:
            now = datetime.now(timezone.utc)
            for entry in lan_clients_report:
                if not isinstance(entry, dict):
                    continue
                ip = entry.get("lan_ip")
                if not ip:
                    continue
                existing = await db.scalar(
                    select(GatewayLanClient).where(
                        GatewayLanClient.tunnel_client_id == client_row.id,
                        GatewayLanClient.lan_ip == ip,
                    )
                )
                if existing is None:
                    db.add(
                        GatewayLanClient(
                            tunnel_client_id=client_row.id,
                            lan_ip=ip,
                            mac=entry.get("mac"),
                            hostname=entry.get("hostname"),
                            bytes_recent=int(entry.get("bytes_recent") or 0),
                            last_seen=now,
                        )
                    )
                    lan_dirty = True
                else:
                    existing.last_seen = now
                    # Heartbeat fills hostname/mac only when the operator
                    # hasn't already set them. Once stored, an explicit
                    # PATCH (or DELETE) is the only way to change them —
                    # otherwise auto-discovery would silently overwrite
                    # operator-curated names.
                    if entry.get("mac") and not existing.mac:
                        existing.mac = entry.get("mac")
                        lan_dirty = True
                    if entry.get("hostname") and not existing.hostname:
                        existing.hostname = entry.get("hostname")
                        lan_dirty = True
                    existing.bytes_recent = int(entry.get("bytes_recent") or 0)

            # TTL eviction: drop unpinned rows for this gateway whose
            # last_seen is older than LAN_CLIENT_TTL. Pinned rows
            # (egress_attachment_id IS NOT NULL) are sticky — operator
            # intent doesn't expire just because a host went quiet.
            cutoff = now - LAN_CLIENT_TTL
            evicted = await db.execute(
                delete(GatewayLanClient).where(
                    GatewayLanClient.tunnel_client_id == client_row.id,
                    GatewayLanClient.egress_attachment_id.is_(None),
                    GatewayLanClient.last_seen < cutoff,
                )
            )
            if evicted.rowcount:
                lan_dirty = True

    # Absorb VPN peer stats reported by gateway agents — update each
    # profile's `last_handshake_at` so the dashboard can show staleness.
    vpn_peers = msg.get("vpn_peers")
    if isinstance(vpn_peers, list):
        for entry in vpn_peers:
            if not isinstance(entry, dict):
                continue
            pubkey = entry.get("public_key")
            handshake_unix = entry.get("last_handshake_unix")
            if not pubkey or not handshake_unix:
                continue
            try:
                ts = datetime.fromtimestamp(int(handshake_unix), tz=timezone.utc)
            except (TypeError, ValueError, OSError):
                continue
            profile = await db.scalar(
                select(VpnProfile).where(VpnProfile.wg_public_key == pubkey)
            )
            if profile and (
                profile.last_handshake_at is None
                or ts > profile.last_handshake_at
            ):
                profile.last_handshake_at = ts

    # Reconcile the unified wg_peer_snapshots table. The agent ships one
    # entry per peer it can see across every WG interface it owns; we
    # UPSERT by (agent_id, interface, public_key). We do a SELECT+UPDATE
    # / INSERT pattern instead of pg-flavoured ON CONFLICT so the same
    # code works on SQLite in tests.
    all_peers = msg.get("all_peers")
    wg_peer_dirty = False
    if isinstance(all_peers, list):
        for entry in all_peers:
            if not isinstance(entry, dict):
                continue
            iface = entry.get("interface")
            pubkey = entry.get("public_key")
            if not iface or not pubkey:
                continue
            kind = "vpn" if iface.startswith("wg-vpn") else "mesh"
            existing = await db.scalar(
                select(WgPeerSnapshot).where(
                    WgPeerSnapshot.agent_id == agent_id,
                    WgPeerSnapshot.interface == iface,
                    WgPeerSnapshot.public_key == pubkey,
                )
            )
            handshake = entry.get("last_handshake_unix")
            try:
                handshake_int = int(handshake) if handshake else None
            except (TypeError, ValueError):
                handshake_int = None
            rx = int(entry.get("rx_bytes") or 0)
            tx = int(entry.get("tx_bytes") or 0)
            keepalive = entry.get("persistent_keepalive")
            try:
                keepalive_int = int(keepalive) if keepalive else None
            except (TypeError, ValueError):
                keepalive_int = None
            endpoint = entry.get("endpoint") or None
            allowed_ips = entry.get("allowed_ips") or None
            now = datetime.now(timezone.utc)
            if existing is not None:
                existing.kind = kind
                existing.endpoint = endpoint
                existing.allowed_ips = allowed_ips
                existing.last_handshake_unix = handshake_int
                existing.rx_bytes = rx
                existing.tx_bytes = tx
                existing.persistent_keepalive = keepalive_int
                existing.updated_at = now
            else:
                db.add(
                    WgPeerSnapshot(
                        agent_id=agent_id,
                        interface=iface,
                        kind=kind,
                        public_key=pubkey,
                        endpoint=endpoint,
                        allowed_ips=allowed_ips,
                        last_handshake_unix=handshake_int,
                        rx_bytes=rx,
                        tx_bytes=tx,
                        persistent_keepalive=keepalive_int,
                        updated_at=now,
                    )
                )
            wg_peer_dirty = True

    await db.commit()
    if agent_dirty:
        emit_agent_changed()
    if server_dirty:
        emit_tunnel_server_changed()
    if lan_dirty:
        emit_lan_client_changed()
    if wg_peer_dirty:
        emit_wg_peer_changed()
    # Re-dispatch wg_init after commit so get_primary_ip sees the newly
    # inserted TunnelServerIP row.
    if server_for_init is not None:
        await dispatch_wg_init(server_for_init, db)


async def handle_command_result(agent_id: str, msg: dict, db: AsyncSession) -> None:
    """Update the command_log entry, extract public keys, and trigger follow-up commands."""
    command_id = msg.get("command_id")
    success = msg.get("success", False)
    output = msg.get("output", "")

    command_type: str | None = None
    command_params: dict | None = None
    if command_id:
        # Bind the lookup to the authenticated agent so a malicious agent
        # can't ack — and (via wg_attach) inject a peer key into — another
        # agent's pending command. Without this filter the follow-up
        # dispatch below would happily run with attacker-supplied output.
        result = await db.execute(
            select(CommandLog).where(
                CommandLog.id == command_id,
                CommandLog.agent_id == agent_id,
            )
        )
        log = result.scalar_one_or_none()
        if log is None:
            logger.warning(
                "Agent %s sent command_result for command_id %s it does not own; ignoring",
                agent_id,
                command_id,
            )
        else:
            log.success = success
            log.output = output
            command_type = log.command_type
            command_params = log.params or {}
            await db.commit()
            emit_audit_changed()

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)
        await db.commit()

    if not success:
        return

    public_key = _extract_public_key(output)

    if command_type == "wg_init" and public_key:
        result = await db.execute(
            select(TunnelServer).where(TunnelServer.agent_id == agent_id)
        )
        server = result.scalar_one_or_none()
        if server:
            server.wg_public_key = public_key
            await db.commit()
            emit_tunnel_server_changed()
            logger.info("Stored server public key for agent %s", agent_id)

    elif command_type == "vpn_endpoint_up" and public_key:
        ep_id_raw = (command_params or {}).get("endpoint_id") if command_params else None
        if ep_id_raw:
            try:
                ep_uuid = uuid.UUID(ep_id_raw)
            except (TypeError, ValueError):
                ep_uuid = None
            if ep_uuid is not None:
                ep = await db.scalar(
                    select(VpnEndpoint).where(VpnEndpoint.id == ep_uuid)
                )
                if ep is not None:
                    ep.wg_public_key = public_key
                    await db.commit()
                    logger.info("Stored VPN endpoint public key for endpoint %s", ep_uuid)

    elif command_type == "wg_attach":
        # Resolve the attachment by id from the original command params, store
        # the agent's public key, mark the client connected, and chain
        # wg_add_peer to the matching server agent.
        att_id_raw = (command_params or {}).get("attachment_id") if command_params else None
        if att_id_raw:
            try:
                att_uuid = uuid.UUID(att_id_raw)
            except (TypeError, ValueError):
                att_uuid = None
            if att_uuid is not None:
                att = await db.scalar(
                    select(TunnelClientAttachment).where(TunnelClientAttachment.id == att_uuid)
                )
                if att is not None:
                    if public_key:
                        att.wg_public_key = public_key
                    client = await db.scalar(
                        select(TunnelClient).where(TunnelClient.id == att.tunnel_client_id)
                    )
                    if client is not None:
                        client.status = "connected"
                    await db.commit()
                    emit_tunnel_client_changed()
                    if att.wg_public_key:
                        await dispatch_add_peer_for_attachment(att, db)


def _extract_public_key(output: str) -> str | None:
    """Extract a WireGuard public key from command output like 'public key: abc123...'"""
    match = re.search(r"public key:\s*(\S+)", output, re.IGNORECASE)
    return match.group(1) if match else None


async def handle_metrics(agent_id: str, msg: dict, db: AsyncSession) -> None:
    timestamp_raw = msg.get("timestamp")
    try:
        timestamp = datetime.fromisoformat(timestamp_raw) if timestamp_raw else datetime.now(timezone.utc)
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    metric = Metric(
        agent_id=agent_id,
        timestamp=timestamp,
        data={k: v for k, v in msg.items() if k not in ("type", "timestamp")},
    )
    db.add(metric)

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)

    await db.commit()


async def handle_heal_event(agent_id: str, msg: dict, db: AsyncSession) -> None:
    """Persist one heal event emitted by an agent.

    The agent's 60s healer fires this whenever it re-installs missing
    routing state. We only store what the agent reports — we don't
    second-guess `healed` items because the catalogue of names is
    defined entirely in the agent's iptables / wireguard heal layer.
    """
    mode = msg.get("mode")
    if mode not in ("server", "client"):
        return
    healed_raw = msg.get("healed")
    if not isinstance(healed_raw, list):
        return
    healed = [str(x) for x in healed_raw if isinstance(x, str)]
    interface = msg.get("interface")
    if interface is not None and not isinstance(interface, str):
        interface = None

    event = AgentHealEvent(
        agent_id=agent_id,
        mode=mode,
        interface=interface,
        healed=healed,
    )
    db.add(event)

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)

    await db.commit()
    emit_heal_event_changed()


async def handle_crowdsec_status(agent_id: str, msg: dict, db: AsyncSession) -> None:
    """Upsert this agent's CrowdSec snapshot from a `crowdsec_status` frame.

    The agent always sends a status frame, even when cscli is missing —
    `running=False` is the explicit sentinel. We accept any frame as
    long as it has `running` set; everything else (version, counts,
    lists) is optional and stored as-is.
    """
    if "running" not in msg:
        return
    running = bool(msg.get("running"))
    # `installed` is newer than `running`; an older agent that doesn't
    # send it but reports running=True is, by definition, installed.
    installed = bool(msg.get("installed", running))
    version = msg.get("version") if isinstance(msg.get("version"), str) else None
    try:
        total_decisions = int(msg.get("total_decisions") or 0)
    except (TypeError, ValueError):
        total_decisions = 0
    top_scenarios = msg.get("top_scenarios")
    if not isinstance(top_scenarios, list):
        top_scenarios = None
    top_ips = msg.get("top_ips")
    if not isinstance(top_ips, list):
        top_ips = None
    err = msg.get("error") if isinstance(msg.get("error"), str) else None
    phase = msg.get("phase") if isinstance(msg.get("phase"), str) else component_phase(installed, running, err)
    appsec_enabled = bool(msg.get("appsec_enabled", False))
    bouncer_registered = bool(msg.get("bouncer_registered", False))

    existing = await db.scalar(
        select(CrowdSecSnapshot).where(CrowdSecSnapshot.agent_id == agent_id)
    )
    now = datetime.now(timezone.utc)
    if existing is not None:
        existing.installed = installed
        existing.running = running
        existing.version = version
        existing.total_decisions = total_decisions
        existing.top_scenarios = top_scenarios
        existing.top_ips = top_ips
        existing.error = err
        existing.phase = phase
        existing.last_error = err
        existing.appsec_enabled = appsec_enabled
        existing.bouncer_registered = bouncer_registered
        existing.updated_at = now
        snapshot = existing
    else:
        snapshot = CrowdSecSnapshot(
            agent_id=agent_id,
            installed=installed,
            running=running,
            version=version,
            total_decisions=total_decisions,
            top_scenarios=top_scenarios,
            top_ips=top_ips,
            error=err,
            phase=phase,
            last_error=err,
            appsec_enabled=appsec_enabled,
            bouncer_registered=bouncer_registered,
            updated_at=now,
        )
        db.add(snapshot)

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = now

    # When crowdsec is running, diff the expected auto-whitelist against
    # what the agent currently holds and dispatch a sync if drifted. We
    # piggyback on the 5-min heartbeat rather than spinning up a server-
    # side scheduler — see crowdsec_ops.build_whitelist for what's in
    # scope (other agents' public IPs, mesh + VPN subnets, gateway LAN
    # subnets + discovered LAN clients).
    if snapshot and snapshot.running:
        payload = await build_whitelist(agent_id, db)
        h = whitelist_hash(payload)
        if snapshot.whitelist_hash != h:
            sent, _ = await dispatch_edge_desired_state(agent_id, db)
            if sent:
                snapshot.whitelist_hash = h
                await db.commit()

    await db.commit()
    emit_crowdsec_changed()
    emit_edge_changed()


async def handle_traefik_status(agent_id: str, msg: dict, db: AsyncSession) -> None:
    """Upsert this agent's Traefik snapshot from a `traefik_status` frame.

    Mirrors handle_crowdsec_status: a frame without `running` is silently
    ignored, and `installed` defaults to `running` for older agents that
    may not send it separately.
    """
    if "running" not in msg:
        return
    running = bool(msg.get("running"))
    installed = bool(msg.get("installed", running))
    version = msg.get("version") if isinstance(msg.get("version"), str) else None
    try:
        routes_count = int(msg.get("routes_count") or 0)
    except (TypeError, ValueError):
        routes_count = 0
    err = msg.get("error") if isinstance(msg.get("error"), str) else None
    phase = msg.get("phase") if isinstance(msg.get("phase"), str) else component_phase(installed, running, err)

    existing = await db.scalar(
        select(TraefikSnapshot).where(TraefikSnapshot.agent_id == agent_id)
    )
    now = datetime.now(timezone.utc)
    if existing is not None:
        existing.installed = installed
        existing.running = running
        existing.version = version
        existing.routes_count = routes_count
        existing.error = err
        existing.phase = phase
        existing.last_error = err
        existing.updated_at = now
    else:
        db.add(
            TraefikSnapshot(
                agent_id=agent_id,
                installed=installed,
                running=running,
                version=version,
                routes_count=routes_count,
                error=err,
                phase=phase,
                last_error=err,
                updated_at=now,
            )
        )

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = now

    await db.commit()
    emit_traefik_changed()
    emit_edge_changed()


async def handle_security_events(agent_id: str, msg: dict, db: AsyncSession) -> None:
    """Persist a batch of security events from a `security_events` frame.

    The agent sends events as a list under `events`. Each entry has:
    source, kind, ip, value, action, occurred_at (ISO-8601), raw (dict).
    """
    events_raw = msg.get("events")
    if not isinstance(events_raw, list) or not events_raw:
        return

    now = datetime.now(timezone.utc)
    for entry in events_raw:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        kind = entry.get("kind")
        if not source or not kind:
            continue
        occurred_raw = entry.get("occurred_at")
        try:
            occurred_at = (
                datetime.fromisoformat(occurred_raw)
                if occurred_raw
                else now
            )
        except (TypeError, ValueError):
            occurred_at = now
        raw = entry.get("raw")
        if not isinstance(raw, dict):
            raw = None
        db.add(
            SecurityEvent(
                agent_id=agent_id,
                source=str(source),
                kind=str(kind),
                ip=entry.get("ip") or None,
                value=entry.get("value") or None,
                action=entry.get("action") or None,
                raw=raw,
                occurred_at=occurred_at,
            )
        )

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = now

    await db.commit()
    emit_security_changed()


async def dispatch(agent_id: str, msg: dict, db: AsyncSession) -> None:
    msg_type = msg.get("type")
    if msg_type == "heartbeat":
        await handle_heartbeat(agent_id, msg, db)
    elif msg_type == "command_result":
        await handle_command_result(agent_id, msg, db)
    elif msg_type == "metrics":
        await handle_metrics(agent_id, msg, db)
    elif msg_type == "heal_event":
        await handle_heal_event(agent_id, msg, db)
    elif msg_type == "crowdsec_status":
        await handle_crowdsec_status(agent_id, msg, db)
    elif msg_type == "traefik_status":
        await handle_traefik_status(agent_id, msg, db)
    elif msg_type == "security_events":
        await handle_security_events(agent_id, msg, db)
    # Unknown message types are silently ignored

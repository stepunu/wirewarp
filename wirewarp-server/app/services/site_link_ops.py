"""Validate site ownership and publish complete per-agent desired snapshots."""
import hashlib
import ipaddress
import json
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.site_link import SiteLink, SiteLinkAgentState, SiteLinkAgentGeneration
from app.models.command_log import CommandLog
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.vpn_endpoint import VpnEndpoint
from app.models.wg_peer_snapshot import WgPeerSnapshot
from app.schemas.site_link import SiteLinkCreate
from app.services.agent_commands import send_command


async def lock_site_links(db: AsyncSession) -> None:
    # Serialize topology mutations and aggregate revisions across server workers.
    if db.bind.dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(8731043)"))


TEARDOWN_PHASES = {"teardown_pending", "teardown_error", "teardown_applied"}


async def ensure_no_site_link_teardown(db: AsyncSession, *, agent_ids: set[uuid.UUID] | None = None) -> None:
    query = select(SiteLinkAgentState.agent_id).where(SiteLinkAgentState.phase.in_(TEARDOWN_PHASES))
    if agent_ids is not None:
        query = query.where(SiteLinkAgentState.agent_id.in_(agent_ids))
    if await db.scalar(query.limit(1)):
        raise HTTPException(409, "Finish managed Site Links teardown before changing links or tunnel topology")


def participants(link: SiteLink) -> set[uuid.UUID]:
    return {link.site_a_gateway_id, link.site_b_gateway_id, link.hub_agent_id}


def network(value: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(value, strict=True)
    except (ValueError, TypeError):
        raise HTTPException(409, "Topology contains an invalid IPv4 network")


async def validate_link(body: SiteLinkCreate, db: AsyncSession, *, link_id: uuid.UUID | None = None) -> None:
    if body.site_a_gateway_id == body.site_b_gateway_id:
        raise HTTPException(422, "Select two different gateways")
    hub = await db.get(Agent, body.hub_agent_id)
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == body.hub_agent_id))
    if hub is None or hub.type != "server" or server is None or not server.wg_public_key:
        raise HTTPException(409, "The hub must be an initialized tunnel server")
    selected = []
    for label in ("a", "b"):
        gateway_id = getattr(body, f"site_{label}_gateway_id")
        attachment_id = getattr(body, f"site_{label}_attachment_id")
        agent = await db.get(Agent, gateway_id)
        client = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == gateway_id))
        attachment = await db.get(TunnelClientAttachment, attachment_id)
        if agent is None or agent.type != "client" or client is None or not client.is_gateway:
            raise HTTPException(409, "Both sites must be gateway nodes")
        if attachment is None or attachment.tunnel_client_id != client.id or attachment.tunnel_server_id != server.id or not attachment.wg_public_key:
            raise HTTPException(409, "Both sites require initialized attachments to the selected hub")
        advertised = network(client.vm_network)
        try:
            lan_ip = ipaddress.IPv4Address(client.lan_ip)
            tunnel_ip = ipaddress.IPv4Address(attachment.tunnel_ip)
        except (ValueError, TypeError):
            raise HTTPException(409, "Gateway LAN and attachment tunnel addresses must be initialized")
        if lan_ip not in advertised or tunnel_ip not in network(server.tunnel_network):
            raise HTTPException(409, "Gateway addresses do not match the advertised topology")
        if any(not network(subnet).subnet_of(advertised) for subnet in getattr(body, f"site_{label}_subnets")):
            raise HTTPException(422, "Selected subnets must belong to the gateway advertised LAN")
        selected.append((client, attachment, advertised))
    if selected[0][2].overlaps(selected[1][2]):
        raise HTTPException(409, "Gateway advertised LANs overlap")

    all_peers = (await db.execute(select(TunnelClientAttachment, TunnelClient).join(TunnelClient, TunnelClient.id == TunnelClientAttachment.tunnel_client_id).where(TunnelClientAttachment.tunnel_server_id == server.id))).all()
    # Validate full AllowedIPs ownership, including peers outside this link.
    peer_networks = []
    peer_keys = set()
    for attachment, client in all_peers:
        if attachment.wg_public_key:
            if attachment.wg_public_key in peer_keys:
                raise HTTPException(409, "Hub peer public keys must be unique")
            peer_keys.add(attachment.wg_public_key)
        addresses = [network(f"{attachment.tunnel_ip}/32")]
        if client.is_gateway and client.vm_network:
            addresses.append(network(client.vm_network))
        for value in addresses:
            if any(value.overlaps(other) for _, other in peer_networks):
                raise HTTPException(409, "Hub peer AllowedIPs overlap")
            peer_networks.append((attachment.wg_public_key, value))
    for _, _, advertised in selected:
        if advertised.overlaps(network(server.tunnel_network)):
            raise HTTPException(409, "Site LAN overlaps the hub tunnel network")
    vpn_networks = list((await db.scalars(select(VpnEndpoint.vpn_network))).all())
    if any(advertised.overlaps(network(value)) for _, _, advertised in selected for value in vpn_networks):
        raise HTTPException(409, "Site LAN overlaps a VPN endpoint network")
    snapshots = (await db.scalars(select(WgPeerSnapshot).where(WgPeerSnapshot.agent_id == body.hub_agent_id, WgPeerSnapshot.kind == "mesh"))).all()
    for snapshot in snapshots:
        for value in (snapshot.allowed_ips or "").replace(" ", "").split(","):
            if not value:
                continue
            observed = network(value)
            if any(observed.overlaps(expected) and snapshot.public_key != key for key, expected in peer_networks):
                raise HTTPException(409, "Observed hub peer AllowedIPs conflict with managed ownership")
    other_links = (await db.scalars(select(SiteLink))).all()
    pair = {body.site_a_gateway_id, body.site_b_gateway_id}
    if any(link.id != link_id and {link.site_a_gateway_id, link.site_b_gateway_id} == pair for link in other_links):
        raise HTTPException(409, "A link between these gateways already exists")
    destinations = {body.site_a_gateway_id: (body.site_b_gateway_id, body.site_b_subnets), body.site_b_gateway_id: (body.site_a_gateway_id, body.site_a_subnets)}
    for link in other_links:
        if link.id == link_id:
            continue
        for source, remote, subnets in ((link.site_a_gateway_id, link.site_b_gateway_id, link.site_b_subnets), (link.site_b_gateway_id, link.site_a_gateway_id, link.site_a_subnets)):
            if source in destinations:
                owner, selected_subnets = destinations[source]
                if remote != owner and any(network(a).overlaps(network(b)) for a in subnets for b in selected_subnets):
                    raise HTTPException(409, "Remote site subnets overlap across this gateway's links")
    for rule in body.access_rules:
        if body.direction != "bidirectional" and rule.direction != body.direction:
            raise HTTPException(422, "Access rule direction is disabled by the link")
        destination = body.site_b_subnets if rule.direction == "a_to_b" else body.site_a_subnets
        if any(not any(network(cidr).subnet_of(network(subnet)) for subnet in destination) for cidr in rule.destination_cidrs):
            raise HTTPException(422, "Access rules must stay inside the destination site subnets")


def link_payload(link: SiteLink) -> dict:
    return {
        "id": str(link.id), "enabled": link.enabled, "hub_agent_id": str(link.hub_agent_id),
        "site_a": {"gateway_agent_id": str(link.site_a_gateway_id), "attachment_id": str(link.site_a_attachment_id), "subnets": link.site_a_subnets},
        "site_b": {"gateway_agent_id": str(link.site_b_gateway_id), "attachment_id": str(link.site_b_attachment_id), "subnets": link.site_b_subnets},
        "allow_new_a_to_b": link.direction in {"a_to_b", "bidirectional"},
        "allow_new_b_to_a": link.direction in {"b_to_a", "bidirectional"},
        "snat_at_a": "gateway_lan_ip" if link.snat_at_a else "preserve",
        "snat_at_b": "gateway_lan_ip" if link.snat_at_b else "preserve",
        "access_rules": link.access_rules,
    }


async def aggregate_payload(agent_id: uuid.UUID, db: AsyncSession) -> dict:
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(409, "Site link node no longer exists")
    all_links = list((await db.scalars(select(SiteLink).order_by(SiteLink.id))).all())
    links = [link for link in all_links if agent_id in participants(link)]
    managed_ids = set((await db.scalars(select(SiteLinkAgentState.agent_id))).all()) | {link.hub_agent_id for link in all_links}
    servers = (await db.scalars(select(TunnelServer).where(TunnelServer.agent_id.in_(managed_ids)))).all()
    server_ids = {server.id for server in servers}
    if agent.type == "server":
        server_ids = {server.id for server in servers if server.agent_id == agent_id}
    else:
        client = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == agent_id))
        if client is None or not client.is_gateway:
            raise HTTPException(409, "Managed site link node is no longer a gateway")
        attached = set((await db.scalars(select(TunnelClientAttachment.tunnel_server_id).where(TunnelClientAttachment.tunnel_client_id == client.id))).all())
        server_ids &= attached
    peers = (await db.execute(select(TunnelClientAttachment, TunnelClient).join(TunnelClient, TunnelClient.id == TunnelClientAttachment.tunnel_client_id).where(TunnelClientAttachment.tunnel_server_id.in_(server_ids), TunnelClient.is_gateway.is_(True)).order_by(TunnelClientAttachment.id))).all()
    transit_peers = [{"gateway_agent_id": str(client.agent_id), "attachment_id": str(attachment.id), "advertised_subnets": [str(network(client.vm_network))], "wireguard_public_key": attachment.wg_public_key or ""} for attachment, client in peers if client.vm_network]
    return {"schema_version": 1, "node_role": "hub" if agent.type == "server" else "gateway", "links": [link_payload(link) for link in links], "transit_peers": transit_peers}


async def prepare_snapshots(agent_ids: set[uuid.UUID], db: AsyncSession, *, include_managed: bool = True) -> list[tuple[uuid.UUID, dict]]:
    await lock_site_links(db)
    await ensure_no_site_link_teardown(db)
    # A changed hub inventory also changes guards on existing linked gateways.
    if include_managed:
        agent_ids = agent_ids | set((await db.scalars(select(SiteLinkAgentState.agent_id))).all())
    snapshots = []
    for agent_id in sorted(agent_ids, key=str):
        payload = await aggregate_payload(agent_id, db)
        desired_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        state = await db.get(SiteLinkAgentState, agent_id)
        generation = await db.get(SiteLinkAgentGeneration, agent_id)
        if generation is None:
            generation = SiteLinkAgentGeneration(agent_id=agent_id, revision=state.revision if state else 0)
            db.add(generation)
        if state is None:
            state = SiteLinkAgentState(agent_id=agent_id, revision=generation.revision)
            db.add(state)
        generation.revision = max(generation.revision, state.revision)
        if state.desired_hash != desired_hash:
            generation.revision = max(generation.revision, state.revision) + 1
            state.revision = generation.revision
            state.desired_hash = desired_hash
        state.phase = "pending"
        state.last_error = None
        snapshots.append((agent_id, {**payload, "revision": state.revision, "desired_hash": desired_hash}))
    await db.commit()
    return snapshots


async def send_snapshots(snapshots: list[tuple[uuid.UUID, dict]], db: AsyncSession, actor_user_id=None) -> None:
    for agent_id, payload in snapshots:
        await lock_site_links(db)
        await ensure_no_site_link_teardown(db)
        sent, command_id = await send_command(str(agent_id), "site_link_desired_state", payload, db, actor_user_id=actor_user_id)
        state = await db.scalar(select(SiteLinkAgentState).where(SiteLinkAgentState.agent_id == agent_id).with_for_update().execution_options(populate_existing=True))
        if state and state.phase not in TEARDOWN_PHASES and state.revision == payload["revision"] and state.desired_hash == payload["desired_hash"]:
            state.command_id = uuid.UUID(command_id)
            # An acknowledgment can arrive before this transaction resumes.
            if state.phase != "applied" or state.applied_revision != state.revision or state.applied_hash != state.desired_hash:
                state.phase = "pending" if sent else "disconnected"
        await db.commit()


async def dispatch_site_links_for_agent(agent_id: str, db: AsyncSession) -> None:
    agent_uuid = uuid.UUID(str(agent_id))
    await lock_site_links(db)
    state = await db.get(SiteLinkAgentState, agent_uuid)
    if state is None:
        return
    if state.phase in TEARDOWN_PHASES:
        await send_teardown_snapshots([(agent_uuid, teardown_payload(state))], db)
        return
    snapshots = await prepare_snapshots({agent_uuid}, db, include_managed=False)
    await send_snapshots(snapshots, db)


async def acknowledge_site_link_state(agent_id: str, msg: dict, db: AsyncSession) -> None:
    await lock_site_links(db)
    state = await db.scalar(select(SiteLinkAgentState).where(SiteLinkAgentState.agent_id == uuid.UUID(str(agent_id))).with_for_update().execution_options(populate_existing=True))
    revision = msg.get("revision")
    if state is None or state.phase in TEARDOWN_PHASES or type(revision) is not int or revision != state.revision or msg.get("desired_hash") != state.desired_hash:
        return
    phase = msg.get("phase")
    if phase not in {"applied", "error", "applying"}:
        return
    if phase == "applying" and state.phase == "applied":
        return
    state.phase = phase
    state.last_seen = datetime.now(timezone.utc)
    state.last_error = str(msg.get("error") or "Site link reconciliation failed")[:1000] if phase == "error" else None
    if phase == "applied":
        state.applied_revision = revision
        state.applied_hash = state.desired_hash
    await db.commit()


def teardown_payload(state):
    return {"schema_version": 1, "agent_id": str(state.agent_id), "revision": state.revision, "desired_hash": state.desired_hash}


async def retained_site_link_state(db):
    from app.websocket import hub
    has_links = await db.scalar(select(SiteLink.id).limit(1)) is not None
    rows = (await db.execute(select(SiteLinkAgentState, Agent).join(Agent, Agent.id == SiteLinkAgentState.agent_id).order_by(SiteLinkAgentState.agent_id))).all()
    pending = any(state.phase in TEARDOWN_PHASES for state, _ in rows)
    current = True
    states = []
    for state, agent in rows:
        states.append({"agent_id": str(agent.id), "name": agent.name, "node_role": "hub" if agent.type == "server" else "gateway", "connected": hub.manager.is_connected(str(agent.id)), "revision": state.revision, "desired_hash": state.desired_hash, "phase": state.phase, "last_error": state.last_error, "command_id": str(state.command_id) if state.command_id else None})
        if not pending:
            payload = await aggregate_payload(state.agent_id, db)
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            current = current and not payload["links"] and state.phase == "applied" and state.applied_revision == state.revision and state.applied_hash == state.desired_hash and digest == state.desired_hash
        else:
            current = current and state.phase in TEARDOWN_PHASES
    return {"states": states, "can_teardown": bool(states) and not has_links and current, "has_links": has_links}


async def teardown_site_links(body, db, actor_user_id=None):
    await lock_site_links(db)
    retained = await retained_site_link_state(db)
    reviewed = {(str(item.agent_id), item.revision, item.desired_hash) for item in body.expected_states}
    actual = {(item["agent_id"], item["revision"], item["desired_hash"]) for item in retained["states"]}
    if len(reviewed) != len(body.expected_states) or reviewed != actual:
        raise HTTPException(409, "Retained Site Links state changed. Review every node again before teardown")
    if not retained["can_teardown"]:
        raise HTTPException(409, "Remove every Site Link and apply all empty snapshots before managed teardown")
    snapshots = []
    for item in retained["states"]:
        state = await db.get(SiteLinkAgentState, uuid.UUID(item["agent_id"]))
        if state.phase not in TEARDOWN_PHASES:
            state.phase = "teardown_pending"
            state.last_error = None
        snapshots.append((state.agent_id, teardown_payload(state)))
    # Retain the whole reviewed cohort before any agent can acknowledge release.
    await db.commit()
    await send_teardown_snapshots(snapshots, db, actor_user_id)
    return await retained_site_link_state(db)


async def send_teardown_snapshots(snapshots, db, actor_user_id=None):
    for agent_id, payload in snapshots:
        sent, command_id = await send_command(str(agent_id), "site_link_teardown", payload, db, actor_user_id=actor_user_id)
        await lock_site_links(db)
        state = await db.scalar(select(SiteLinkAgentState).where(SiteLinkAgentState.agent_id == agent_id).with_for_update().execution_options(populate_existing=True))
        if state and state.phase in TEARDOWN_PHASES and state.revision == payload["revision"] and state.desired_hash == payload["desired_hash"]:
            state.command_id = uuid.UUID(command_id)
            if state.phase != "teardown_applied":
                state.phase = "teardown_pending" if sent else "teardown_error"
                state.last_error = None if sent else "Node disconnected. Retry teardown after reconnecting"
        await db.commit()


async def acknowledge_site_link_teardown(agent_id, command_id, db):
    await lock_site_links(db)
    log = await db.scalar(select(CommandLog).where(CommandLog.id == command_id, CommandLog.agent_id == uuid.UUID(str(agent_id))))
    if log is None or log.command_type != "site_link_teardown":
        return
    state = await db.scalar(select(SiteLinkAgentState).where(SiteLinkAgentState.agent_id == log.agent_id).with_for_update().execution_options(populate_existing=True))
    params = log.params or {}
    if state is None or state.phase not in TEARDOWN_PHASES or params != teardown_payload(state):
        return
    if await db.scalar(select(SiteLink.id).limit(1)):
        return
    try:
        result = json.loads(log.output or "")
    except (ValueError, TypeError):
        result = None
    matched = isinstance(result, dict) and result.get("released") is True and type(result.get("revision")) is int and result["revision"] == state.revision and result.get("desired_hash") == state.desired_hash
    if log.success is True and matched:
        state.phase = "teardown_applied"
        state.last_error = None
        state.last_seen = datetime.now(timezone.utc)
    elif state.phase != "teardown_applied":
        state.phase = "teardown_error"
        state.last_error = "Managed teardown did not return a valid release receipt. Retry teardown"
    await db.flush()
    cohort = list((await db.scalars(select(SiteLinkAgentState).with_for_update())).all())
    if cohort and all(item.phase == "teardown_applied" for item in cohort):
        for item in cohort:
            await db.delete(item)
    await db.commit()

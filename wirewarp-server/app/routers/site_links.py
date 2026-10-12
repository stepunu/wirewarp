import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.models.site_link import SiteLink, SiteLinkAgentState
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.schemas.site_link import SiteLinkCreate, SiteLinkUpdate, SiteLinkTest, SiteLinkTeardown
from app.services.agent_commands import send_command
from app.services.site_link_ops import (
    lock_site_links, network, participants, prepare_snapshots, send_snapshots, validate_link,
    ensure_no_site_link_teardown, retained_site_link_state, teardown_site_links,
)
from app.websocket import hub

router = APIRouter()


async def get_link(link_id: uuid.UUID, db: AsyncSession) -> SiteLink:
    link = await db.get(SiteLink, link_id)
    if link is None:
        raise HTTPException(404, "Site link not found")
    return link


def stored_body(link: SiteLink) -> dict:
    return {key: getattr(link, key) for key in SiteLinkCreate.model_fields}


async def read_link(link: SiteLink, db: AsyncSession) -> dict:
    states = []
    for agent_id in sorted(participants(link), key=str):
        state = await db.get(SiteLinkAgentState, agent_id)
        connected = hub.manager.is_connected(str(agent_id))
        states.append({
            "agent_id": str(agent_id), "connected": connected,
            "revision": state.revision if state else None,
            "desired_hash": state.desired_hash if state else None,
            "applied_revision": state.applied_revision if state else None,
            "applied_hash": state.applied_hash if state else None,
            "phase": state.phase if connected and state else "disconnected",
            "last_error": state.last_error if state else None,
            "last_seen": state.last_seen if state else None,
            "command_id": str(state.command_id) if state and state.command_id else None,
        })
    applied = all(state["connected"] and state["phase"] == "applied" and state["revision"] == state["applied_revision"] and state["desired_hash"] == state["applied_hash"] for state in states)
    return {
        "id": str(link.id), **stored_body(link), "revision": link.revision,
        "agent_states": states, "phase": "applied" if applied else "pending",
        "path": [str(link.site_a_gateway_id), str(link.hub_agent_id), str(link.site_b_gateway_id)],
        "lan_routing_prerequisite": {
            "status": "unverified",
            "detail": "Source devices need a route through the local WireWarp gateway or must use it as their default gateway. A gateway probe does not verify other LAN devices.",
        },
        "snat_tradeoff": "Destination SNAT avoids a return route on the destination router. Destination services see the gateway LAN address instead of the source device address.",
    }


@router.get("")
async def list_links(db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    links = (await db.scalars(select(SiteLink).order_by(SiteLink.created_at, SiteLink.id))).all()
    return [await read_link(link, db) for link in links]


@router.get("/options")
async def options(db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    gateways = []
    rows = (await db.execute(select(TunnelClient, Agent).join(Agent, Agent.id == TunnelClient.agent_id).where(TunnelClient.is_gateway.is_(True), Agent.type == "client"))).all()
    for client, agent in rows:
        attachments = (await db.execute(select(TunnelClientAttachment, TunnelServer, Agent).join(TunnelServer, TunnelServer.id == TunnelClientAttachment.tunnel_server_id).join(Agent, Agent.id == TunnelServer.agent_id).where(TunnelClientAttachment.tunnel_client_id == client.id))).all()
        gateways.append({"agent_id": str(agent.id), "name": agent.name, "advertised_subnets": [client.vm_network] if client.vm_network else [], "lan_ip": client.lan_ip, "connected": hub.manager.is_connected(str(agent.id)), "attachments": [{"attachment_id": str(attachment.id), "hub_agent_id": str(server.agent_id), "hub_name": hub_agent.name, "initialized": bool(attachment.wg_public_key and server.wg_public_key and client.vm_network and client.lan_ip), "hub_connected": hub.manager.is_connected(str(server.agent_id))} for attachment, server, hub_agent in attachments]})
    return {"gateways": gateways}


@router.get("/retained-state")
async def retained_state(db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    return await retained_site_link_state(db)


@router.post("/teardown")
async def teardown(body: SiteLinkTeardown, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    return await teardown_site_links(body, db, actor.id)


@router.get("/{link_id}")
async def detail(link_id: uuid.UUID, db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    return await read_link(await get_link(link_id, db), db)


@router.post("", status_code=201)
async def create(body: SiteLinkCreate, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    await lock_site_links(db)
    await ensure_no_site_link_teardown(db)
    await validate_link(body, db)
    link = SiteLink(**body.model_dump(mode="python", exclude={"access_rules"}), access_rules=[rule.model_dump() for rule in body.access_rules])
    db.add(link)
    await db.flush()
    snapshots = await prepare_snapshots(participants(link), db)
    await send_snapshots(snapshots, db, actor.id)
    return await read_link(link, db)


@router.patch("/{link_id}")
async def update(link_id: uuid.UUID, body: SiteLinkUpdate, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    await lock_site_links(db)
    await ensure_no_site_link_teardown(db)
    link = await get_link(link_id, db)
    values = {**stored_body(link), **body.model_dump(exclude_unset=True)}
    validated = SiteLinkCreate.model_validate(values)
    await validate_link(validated, db, link_id=link.id)
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(link, key, value)
    link.revision += 1
    await db.flush()
    snapshots = await prepare_snapshots(participants(link), db)
    await send_snapshots(snapshots, db, actor.id)
    return await read_link(link, db)


@router.delete("/{link_id}", status_code=204)
async def remove(link_id: uuid.UUID, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    await lock_site_links(db)
    await ensure_no_site_link_teardown(db)
    link = await get_link(link_id, db)
    agent_ids = participants(link)
    await db.delete(link)
    await db.flush()
    snapshots = await prepare_snapshots(agent_ids, db)
    await send_snapshots(snapshots, db, actor.id)


@router.post("/{link_id}/test", status_code=202)
async def test_link(link_id: uuid.UUID, body: SiteLinkTest, db: AsyncSession = Depends(get_db), actor: User = Depends(require_role("admin"))):
    await lock_site_links(db)
    link = await get_link(link_id, db)
    if not link.enabled or link.direction not in {"bidirectional", body.direction}:
        raise HTTPException(409, "The requested direction is disabled")
    destination_subnets = link.site_b_subnets if body.direction == "a_to_b" else link.site_a_subnets
    destination = ipaddress.IPv4Address(body.destination_ip)
    if not any(destination in network(subnet) for subnet in destination_subnets):
        raise HTTPException(422, "Test destination must be inside the destination site")
    if link.access_rules and not any(rule["direction"] == body.direction and rule["protocol"] in {"any", "tcp"} and any(destination in network(cidr) for cidr in rule["destination_cidrs"]) and (not rule["destination_ports"] or body.destination_port in rule["destination_ports"]) for rule in link.access_rules):
        raise HTTPException(422, "The service is outside the link access rules")
    for agent_id in participants(link):
        state = await db.get(SiteLinkAgentState, agent_id)
        if not hub.manager.is_connected(str(agent_id)) or state is None or state.phase != "applied" or state.revision != state.applied_revision or state.desired_hash != state.applied_hash:
            raise HTTPException(409, "All three nodes must apply the current site link state before a test")
    source_id = link.site_a_gateway_id if body.direction == "a_to_b" else link.site_b_gateway_id
    client = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == source_id))
    source_subnets = link.site_a_subnets if body.direction == "a_to_b" else link.site_b_subnets
    if client is None or not any(ipaddress.IPv4Address(client.lan_ip) in network(subnet) for subnet in source_subnets):
        raise HTTPException(409, "The source gateway LAN address is outside the selected source subnets")
    state = await db.get(SiteLinkAgentState, source_id)
    params = {"schema_version": 1, "link_id": str(link.id), "revision": state.revision, "desired_hash": state.desired_hash, "direction": body.direction, "destination_ip": body.destination_ip, "destination_port": body.destination_port, "protocol": "tcp", "timeout_seconds": 5}
    sent, command_id = await send_command(str(source_id), "site_link_test", params, db, actor_user_id=actor.id)
    return {"command_id": command_id, "sent": sent, "status": "pending" if sent else "disconnected", "scope": "source_gateway_only"}


@router.get("/{link_id}/test/{command_id}")
async def test_status(link_id: uuid.UUID, command_id: uuid.UUID, db: AsyncSession = Depends(get_db), _: User = Depends(require_ops_role)):
    link = await get_link(link_id, db)
    log = await db.get(CommandLog, command_id)
    if log is None or log.command_type != "site_link_test" or (log.params or {}).get("link_id") != str(link_id) or log.agent_id not in {link.site_a_gateway_id, link.site_b_gateway_id}:
        raise HTTPException(404, "Site link test not found")
    status = "pending"
    result = None
    if log.success is not None:
        try:
            result = json.loads(log.output or "")
        except (ValueError, TypeError):
            result = None
        status = "success" if log.success and isinstance(result, dict) and result.get("connected") is True else "failure"
    elif not hub.manager.is_connected(str(log.agent_id)):
        status = "disconnected"
    else:
        executed_at = log.executed_at.replace(tzinfo=timezone.utc) if log.executed_at.tzinfo is None else log.executed_at
        if datetime.now(timezone.utc) - executed_at > timedelta(seconds=15):
            status = "timeout"
    # Return the structured status only. Raw command output is not a probe result.
    safe_result = {key: result[key] for key in ("connected", "error", "duration_ms") if key in result} if isinstance(result, dict) else None
    return {"command_id": str(log.id), "status": status, "result": safe_result, "scope": "source_gateway_only", "lan_routing_prerequisite": "unverified"}

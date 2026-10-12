from __future__ import annotations

import ipaddress
import uuid

from fastapi import HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.edge_node import EdgeNode
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer


async def public_ingress_available(db: AsyncSession, agent_id: uuid.UUID | str) -> bool:
    gateway = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == agent_id))
    if gateway is None:
        return True
    return bool(await db.scalar(select(TunnelClientAttachment.id).join(TunnelServer).where(
        TunnelClientAttachment.tunnel_client_id == gateway.id,
        TunnelClientAttachment.wg_public_key.is_not(None), TunnelServer.wg_public_key.is_not(None),
    ).limit(1)))


async def validate_gateway_publication(db: AsyncSession, agent_id: uuid.UUID, attachment_id: uuid.UUID | None, domain: str, route_id: uuid.UUID | None) -> TunnelClientAttachment:
    attachment = await db.get(TunnelClientAttachment, attachment_id) if attachment_id else None
    gateway = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == agent_id))
    if attachment is None or gateway is None or attachment.tunnel_client_id != gateway.id:
        raise HTTPException(status_code=400, detail="Select an attachment belonging to this gateway")
    server = await db.get(TunnelServer, attachment.tunnel_server_id)
    if not attachment.wg_public_key or not server.wg_public_key:
        raise HTTPException(status_code=409, detail="The relay attachment must complete WireGuard setup before publication")
    try:
        listen = ipaddress.IPv4Address(attachment.tunnel_ip)
        network = ipaddress.IPv4Network(server.tunnel_network)
    except ValueError:
        raise HTTPException(status_code=409, detail="Gateway public relays require IPv4 WireGuard addresses") from None
    if listen not in network or listen in {network.network_address, network.network_address + 1, network.broadcast_address}:
        raise HTTPException(status_code=409, detail="Invalid gateway relay tunnel IP")
    owner = await db.get(EdgeNode, agent_id)
    if owner.public_bind_ip and owner.public_bind_ip != str(listen):
        raise HTTPException(status_code=409, detail="Public listener must match the relay attachment tunnel IP")
    if owner.lan_bind_ip == str(listen):
        raise HTTPException(status_code=409, detail="LAN and public relay listener IPs must differ")
    existing = select(HTTPRoute).join(HTTPPublicIngress).where(HTTPRoute.agent_id == agent_id, HTTPRoute.visibility.in_(["public_only", "both"]), HTTPPublicIngress.attachment_id != attachment.id)
    if route_id:
        existing = existing.where(HTTPRoute.id != route_id)
    if await db.scalar(existing.limit(1)):
        raise HTTPException(status_code=409, detail="Gateway public routes must use the same relay attachment")
    from app.services.edge_port_conflicts import find_active_raw_edge_forward_on_server
    if await find_active_raw_edge_forward_on_server(db, server.id):
        raise HTTPException(status_code=409, detail="An active raw TCP forward uses relay port 80 or 443")
    conflicts = select(HTTPRoute).outerjoin(HTTPPublicIngress).outerjoin(TunnelClientAttachment, TunnelClientAttachment.id == HTTPPublicIngress.attachment_id).where(
        func.lower(HTTPRoute.domain) == domain.lower(), HTTPRoute.visibility.in_(["public_only", "both"]),
        (HTTPRoute.agent_id == server.agent_id) | (TunnelClientAttachment.tunnel_server_id == server.id),
    )
    if route_id:
        conflicts = conflicts.where(HTTPRoute.id != route_id)
    if await db.scalar(conflicts.limit(1)):
        raise HTTPException(status_code=409, detail="This hostname already has a public route on the selected VPS")
    return attachment


async def gateway_ingress(db: AsyncSession, agent_id: uuid.UUID | str) -> list[dict]:
    gateway = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == agent_id))
    if gateway is None or not gateway.is_gateway:
        return []
    from app.models.edge_migration import EdgeMigration
    staged_ids = select(EdgeMigration.stage_route_id).where(
        EdgeMigration.target_agent_id == agent_id, EdgeMigration.phase == "provisioning",
    )
    query = select(TunnelClientAttachment, TunnelServer).join(
        HTTPPublicIngress, HTTPPublicIngress.attachment_id == TunnelClientAttachment.id,
    ).join(HTTPRoute, HTTPRoute.id == HTTPPublicIngress.route_id).join(
        TunnelServer, TunnelServer.id == TunnelClientAttachment.tunnel_server_id,
    ).where(
        HTTPRoute.agent_id == agent_id, HTTPRoute.active.is_(True),
        HTTPRoute.visibility.in_(["public_only", "both"]),
        HTTPPublicIngress.active.is_(True) | HTTPRoute.id.in_(staged_ids),
    )
    out = {}
    for attachment, server in (await db.execute(query)).all():
        if attachment.tunnel_client_id != gateway.id or not attachment.wg_public_key or not server.wg_public_key:
            raise HTTPException(status_code=409, detail="Gateway public ingress requires its own initialized attachment")
        try:
            listen = ipaddress.IPv4Address(attachment.tunnel_ip)
            network = ipaddress.IPv4Network(server.tunnel_network)
        except ValueError:
            raise HTTPException(status_code=409, detail="Gateway public relays require IPv4 WireGuard addresses") from None
        if listen not in network or listen in {network.network_address, network.broadcast_address}:
            raise HTTPException(status_code=409, detail="Gateway relay address is outside its tunnel network")
        out[attachment.id] = {"interface": attachment.wg_interface, "source_ip": str(network.network_address + 1), "listen_ip": str(listen)}
    if len(out) > 1:
        raise HTTPException(status_code=409, detail="Gateway public routes must use the same relay attachment")
    return list(out.values())


async def load_relay_routes(db: AsyncSession, agent_id: uuid.UUID | str) -> list[tuple[HTTPRoute, TunnelClientAttachment]]:
    query = select(HTTPRoute, TunnelClientAttachment).join(
        HTTPPublicIngress, HTTPPublicIngress.route_id == HTTPRoute.id,
    ).join(TunnelClientAttachment, TunnelClientAttachment.id == HTTPPublicIngress.attachment_id).join(
        TunnelServer, TunnelServer.id == TunnelClientAttachment.tunnel_server_id,
    ).join(TunnelClient, TunnelClient.agent_id == HTTPRoute.agent_id).join(
        EdgeNode, EdgeNode.agent_id == HTTPRoute.agent_id,
    ).where(
        TunnelServer.agent_id == agent_id, TunnelClient.is_gateway.is_(True),
        HTTPRoute.visibility.in_(["public_only", "both"]), HTTPRoute.active.is_(True),
        HTTPPublicIngress.active.is_(True), EdgeNode.edge_state == "enabled", EdgeNode.edge_mode == "security_edge",
    )
    return list((await db.execute(query)).all())


async def relay_dynamic_config(db: AsyncSession, agent_id: uuid.UUID | str) -> dict:
    routers, services = {}, {}
    for route, attachment in await load_relay_routes(db, agent_id):
        name = "relay-" + route.id.hex
        routers[name] = {"entryPoints": ["websecure"], "rule": f"HostSNI(`{route.domain}`)", "service": name, "tls": {"passthrough": True}}
        services[name] = {"loadBalancer": {"proxyProtocol": {"version": 2}, "servers": [{"address": f"{attachment.tunnel_ip}:443"}]}}
    return {"tcp": {"routers": routers, "services": services}} if routers else {}

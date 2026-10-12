from __future__ import annotations

import ipaddress
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.agent import Agent
from app.models.edge_node import EdgeNode
from app.models.http_route import HTTPRoute
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_server import TunnelServer


async def get_edge_owner(db: AsyncSession, agent_id: uuid.UUID | str) -> EdgeNode:
    agent_id = uuid.UUID(str(agent_id))
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Node not found")
    gateway = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == agent_id))
    if agent.type != "server" and not (gateway and gateway.is_gateway):
        raise HTTPException(status_code=409, detail="Security Edge requires a server or gateway node")
    node = await db.get(EdgeNode, agent_id)
    if node is None:
        node = EdgeNode(agent_id=agent_id)
        db.add(node)
        await db.flush()
    return node


async def is_gateway_edge(db: AsyncSession, agent_id: uuid.UUID | str) -> bool:
    gateway = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == agent_id))
    return bool(gateway and gateway.is_gateway)


async def load_http_routes(db: AsyncSession, agent_id: uuid.UUID | str, *, active_only: bool = False) -> list[HTTPRoute]:
    query = select(HTTPRoute).options(selectinload(HTTPRoute.edge_route_config), selectinload(HTTPRoute.public_ingress)).where(HTTPRoute.agent_id == agent_id).order_by(HTTPRoute.domain)
    if active_only:
        query = query.where(HTTPRoute.active.is_(True))
    return list((await db.scalars(query)).all())


def gateway_bind_address(value: str | None, listener: str) -> str:
    try:
        address = ipaddress.ip_address(value or "")
    except ValueError:
        raise HTTPException(status_code=409, detail=f"Configure a valid {listener} listener IP before enabling gateway Security Edge") from None
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise HTTPException(status_code=409, detail=f"The {listener} listener requires an explicit gateway interface IP")
    return f"[{address}]" if address.version == 6 else str(address)


async def edge_entrypoints(db: AsyncSession, agent_id: uuid.UUID | str) -> dict:
    if not await is_gateway_edge(db, agent_id):
        return {
            "web": {"address": ":80", "http": {"redirections": {"entryPoint": {"to": "websecure", "scheme": "https"}}}},
            "websecure": {"address": ":443"},
        }
    node = await get_edge_owner(db, agent_id)
    lan = gateway_bind_address(node.lan_bind_ip, "LAN")
    gateway = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == agent_id))
    if lan != gateway.lan_ip:
        raise HTTPException(status_code=409, detail="The LAN listener must use the gateway's configured LAN IP")
    points = {
        "lan": {"address": f"{lan}:80", "http": {"redirections": {"entryPoint": {"to": "lansecure", "scheme": "https"}}}},
        "lansecure": {"address": f"{lan}:443"},
    }
    for point in points.values():
        point["forwardedHeaders"] = {"trustedIPs": []}
        point.setdefault("http", {})["middlewares"] = ["wirewarp-strip-forwarded@file"]
    if node.public_bind_ip:
        public = gateway_bind_address(node.public_bind_ip, "public relay")
        if public == lan:
            raise HTTPException(status_code=409, detail="LAN and public relay listener IPs must differ")
    from app.services.edge_relay_ops import gateway_ingress
    ingress = await gateway_ingress(db, agent_id)
    if ingress:
        public = gateway_bind_address(node.public_bind_ip, "public relay")
        if public != ingress[0]["listen_ip"]:
            raise HTTPException(status_code=409, detail="Public listener must use the selected relay attachment tunnel IP")
        points.update({
            "web": {"address": f"{public}:80", "http": {"redirections": {"entryPoint": {"to": "websecure", "scheme": "https"}}}},
            "websecure": {"address": f"{public}:443"},
        })
        for name in ("web", "websecure"):
            points[name]["proxyProtocol"] = {"trustedIPs": [entry["source_ip"] + "/32" for entry in ingress]}
            points[name]["forwardedHeaders"] = {"trustedIPs": []}
            points[name].setdefault("http", {})["middlewares"] = ["wirewarp-strip-forwarded@file"]
    return points


async def route_entrypoints(db: AsyncSession, route: HTTPRoute) -> list[str]:
    if not await is_gateway_edge(db, route.agent_id):
        if route.visibility != "public_only":
            raise HTTPException(status_code=409, detail="VPS routes support public visibility only")
        return ["websecure"]
    points = await edge_entrypoints(db, route.agent_id)
    listeners = []
    if route.visibility in {"lan_only", "both"}:
        listeners.append("lansecure")
    if route.visibility in {"public_only", "both"}:
        if "websecure" not in points:
            raise HTTPException(status_code=409, detail="Configure a public relay listener before publishing this route")
        listeners.append("websecure")
    if not listeners:
        raise HTTPException(status_code=409, detail="Invalid route visibility")
    return listeners

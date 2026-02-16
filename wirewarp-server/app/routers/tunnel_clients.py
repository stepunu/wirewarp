import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.schemas.tunnel_client import TunnelClientRead, TunnelClientUpdate
from app.auth import get_current_user
from app.services.agent_commands import send_command

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("", response_model=list[TunnelClientRead])
async def list_tunnel_clients(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(TunnelClient).order_by(TunnelClient.created_at.desc()))
    return result.scalars().all()


@router.get("/{client_id}", response_model=TunnelClientRead)
async def get_tunnel_client(client_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(TunnelClient).where(TunnelClient.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    return client


@router.patch("/{client_id}", response_model=TunnelClientRead)
async def update_tunnel_client(
    client_id: str,
    body: TunnelClientUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(TunnelClient).where(TunnelClient.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(client, field, value)
    await db.commit()
    await db.refresh(client)

    # If a tunnel server is assigned and we have a tunnel IP, push config to both agents
    if client.tunnel_server_id and client.tunnel_ip:
        result = await db.execute(
            select(TunnelServer).where(TunnelServer.id == client.tunnel_server_id)
        )
        server = result.scalar_one_or_none()
        if server:
            await _configure_tunnel(client, server, db)

    return client


async def _configure_tunnel(client: TunnelClient, server: TunnelServer, db: AsyncSession):
    """Send wg_add_peer to the server agent and wg_configure to the client agent."""

    # Build allowed IPs for this peer on the server side
    allowed_ips = [client.tunnel_ip + "/32"]
    if client.is_gateway and client.vm_network:
        allowed_ips.append(client.vm_network)

    # 1. Tell the server to add this client as a peer
    #    (the client's public key may not be available yet — the client agent
    #     will report it after wg_configure runs. We send the peer anyway;
    #     the server handler will get the key from the wg_configure result.)
    if client.wg_public_key:
        sent, cmd_id = await send_command(
            agent_id=str(server.agent_id),
            command_type="wg_add_peer",
            params={
                "peer_name": f"client-{client.tunnel_ip}",
                "public_key": client.wg_public_key,
                "tunnel_ip": client.tunnel_ip,
                "allowed_ips": allowed_ips,
            },
            db=db,
        )
        if sent:
            logger.info("Sent wg_add_peer to server agent %s (cmd=%s)", server.agent_id, cmd_id)
        else:
            logger.warning("Server agent %s not connected — wg_add_peer queued", server.agent_id)

    # 2. Tell the client to configure WireGuard and gateway routing
    server_endpoint = f"{server.public_ip}:{server.wg_port}" if server.public_ip else ""
    vps_tunnel_ip = server.tunnel_network.rsplit(".", 1)[0] + ".1"

    sent, cmd_id = await send_command(
        agent_id=str(client.agent_id),
        command_type="wg_configure",
        params={
            "wg_interface": "wg0",
            "tunnel_ip": client.tunnel_ip,
            "server_public_key": server.wg_public_key or "",
            "server_endpoint": server_endpoint,
            "vps_tunnel_ip": vps_tunnel_ip,
            "lan_iface": "eth0",
            "lan_network": client.vm_network or "",
            "lan_ip": client.lan_ip or "",
            "is_gateway": client.is_gateway,
        },
        db=db,
    )
    if sent:
        logger.info("Sent wg_configure to client agent %s (cmd=%s)", client.agent_id, cmd_id)
    else:
        logger.warning("Client agent %s not connected — wg_configure queued", client.agent_id)


@router.delete("/{client_id}", status_code=204)
async def delete_tunnel_client(
    client_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(TunnelClient).where(TunnelClient.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Tunnel client not found")
    await db.delete(client)
    await db.commit()

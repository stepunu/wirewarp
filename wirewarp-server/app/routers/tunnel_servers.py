import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.schemas.tunnel_server import TunnelServerRead, TunnelServerUpdate
from app.auth import get_current_user
from app.services.agent_commands import send_command

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("", response_model=list[TunnelServerRead])
async def list_tunnel_servers(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(TunnelServer).order_by(TunnelServer.created_at.desc()))
    return result.scalars().all()


@router.get("/{server_id}", response_model=TunnelServerRead)
async def get_tunnel_server(server_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(TunnelServer).where(TunnelServer.id == server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    return server


@router.patch("/{server_id}", response_model=TunnelServerRead)
async def update_tunnel_server(
    server_id: str,
    body: TunnelServerUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(TunnelServer).where(TunnelServer.id == server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Tunnel server not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(server, field, value)
    await db.commit()
    await db.refresh(server)

    # Derive the server's tunnel IP (first usable in the network, e.g. 10.0.0.1)
    tunnel_ip = server.tunnel_network.rsplit(".", 1)[0] + ".1"

    sent, cmd_id = await send_command(
        agent_id=str(server.agent_id),
        command_type="wg_init",
        params={
            "wg_interface": server.wg_interface,
            "wg_port": server.wg_port,
            "tunnel_network": server.tunnel_network,
            "tunnel_ip": tunnel_ip,
            "public_iface": server.public_iface,
            "public_ip": server.public_ip or "",
        },
        db=db,
    )
    if not sent:
        logger.warning("Agent %s not connected — wg_init queued (cmd=%s)", server.agent_id, cmd_id)

    return server

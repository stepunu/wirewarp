import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.port_forward import PortForward
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.schemas.port_forward import PortForwardCreate, PortForwardRead, PortForwardUpdate
from app.auth import get_current_user
from app.services.agent_commands import send_command

router = APIRouter()
logger = logging.getLogger(__name__)


async def _push_forward(pf: PortForward, command_type: str, db: AsyncSession) -> None:
    """Send iptables_add_forward or iptables_remove_forward to the tunnel server agent."""
    result = await db.execute(select(TunnelServer).where(TunnelServer.id == pf.tunnel_server_id))
    server = result.scalar_one_or_none()
    if not server:
        return
    sent, _ = await send_command(
        agent_id=str(server.agent_id),
        command_type=command_type,
        params={
            "protocol": pf.protocol,
            "public_port": pf.public_port,
            "destination_ip": pf.destination_ip,
            "destination_port": pf.destination_port,
        },
        db=db,
    )
    if not sent:
        logger.warning(
            "Server agent %s not connected — %s not delivered for port %s",
            server.agent_id, command_type, pf.public_port,
        )


@router.get("", response_model=list[PortForwardRead])
async def list_port_forwards(
    tunnel_server_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = select(PortForward).order_by(PortForward.created_at.desc())
    if tunnel_server_id:
        q = q.where(PortForward.tunnel_server_id == tunnel_server_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=PortForwardRead, status_code=201)
async def create_port_forward(
    body: PortForwardCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    pf = PortForward(**body.model_dump())
    db.add(pf)
    await db.commit()
    await db.refresh(pf)
    if pf.active:
        await _push_forward(pf, "iptables_add_forward", db)
    return pf


@router.patch("/{pf_id}", response_model=PortForwardRead)
async def update_port_forward(
    pf_id: str,
    body: PortForwardUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(PortForward).where(PortForward.id == pf_id))
    pf = result.scalar_one_or_none()
    if not pf:
        raise HTTPException(status_code=404, detail="Port forward not found")
    old_active = pf.active
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(pf, field, value)
    await db.commit()
    await db.refresh(pf)
    if not old_active and pf.active:
        await _push_forward(pf, "iptables_add_forward", db)
    elif old_active and not pf.active:
        await _push_forward(pf, "iptables_remove_forward", db)
    return pf


@router.delete("/{pf_id}", status_code=204)
async def delete_port_forward(
    pf_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(PortForward).where(PortForward.id == pf_id))
    pf = result.scalar_one_or_none()
    if not pf:
        raise HTTPException(status_code=404, detail="Port forward not found")
    if pf.active:
        await _push_forward(pf, "iptables_remove_forward", db)
    await db.delete(pf)
    await db.commit()

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.tunnel_client import TunnelClient
from app.models.user import User
from app.schemas.tunnel_client import TunnelClientRead, TunnelClientUpdate
from app.auth import get_current_user

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
    return client

import secrets
import string
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.agent import Agent
from app.models.user import User
from app.models.registration_token import RegistrationToken
from app.schemas.agent import AgentRead, AgentJWTRead
from app.schemas.registration_token import TokenCreate, TokenRead
from app.auth import get_current_user
from app.config import settings

router = APIRouter()


def _generate_token() -> str:
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "-".join(parts)


@router.get("", response_model=list[AgentRead])
async def list_agents(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Agent).order_by(Agent.created_at.desc()))
    return result.scalars().all()


@router.get("/{agent_id}", response_model=AgentRead)
async def get_agent(agent_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(agent_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.delete(agent)
    await db.commit()


@router.post("/{agent_id}/issue-jwt", response_model=AgentJWTRead)
async def issue_agent_jwt(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    from app.auth import create_access_token
    jwt = create_access_token(str(agent.id), expires_delta=timedelta(days=3650))
    return AgentJWTRead(agent_id=agent.id, jwt=jwt)


@router.post("/tokens", response_model=TokenRead, status_code=201)
async def generate_token(body: TokenCreate, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    token = RegistrationToken(
        token=_generate_token(),
        agent_type=body.agent_type,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.AGENT_TOKEN_EXPIRY_HOURS),
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return token

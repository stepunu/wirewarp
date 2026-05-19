import secrets
import string
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.agent import Agent
from app.models.heal_event import AgentHealEvent
from app.models.user import User
from app.models.registration_token import RegistrationToken
from app.schemas.agent import AgentRead, AgentJWTRead
from app.schemas.heal_event import HealEventRead
from app.schemas.registration_token import TokenCreate, TokenIssueResponse
from app.auth import create_agent_token, log_auth_event, require_role
from app.models.system_settings import SystemSettings
from app.realtime.events import emit_agent_changed
from app.services.secrets import hash_token

router = APIRouter()


def _generate_token() -> str:
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "-".join(parts)


@router.get("", response_model=list[AgentRead])
async def list_agents(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator", "viewer")),
):
    result = await db.execute(select(Agent).order_by(Agent.created_at.desc()))
    return result.scalars().all()


@router.get("/{agent_id}", response_model=AgentRead)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator", "viewer")),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("/{agent_id}/heal-events", response_model=list[HealEventRead])
async def list_agent_heal_events(
    agent_id: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator", "viewer")),
):
    """List the agent's most recent heal events, newest first.

    The healer runs every 60s and only emits when it actually re-installs
    something, so the natural cardinality on a healthy lab is near-zero.
    Cap the page size at 100 regardless of caller request so a misbehaving
    client can't drag the dashboard down.
    """
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100
    result = await db.execute(
        select(AgentHealEvent)
        .where(AgentHealEvent.agent_id == agent_id)
        .order_by(AgentHealEvent.occurred_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.delete(agent)
    await db.commit()
    emit_agent_changed()


@router.post("/{agent_id}/issue-jwt", response_model=AgentJWTRead)
async def issue_agent_jwt(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    jwt = create_agent_token(str(agent.id), expires_delta=timedelta(days=3650))
    return AgentJWTRead(agent_id=agent.id, jwt=jwt)


@router.post("/{agent_id}/update", status_code=202)
async def update_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin", "operator")),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    from app.services.agent_commands import send_command
    sent, cmd_id = await send_command(
        agent_id=str(agent.id),
        command_type="agent_update",
        params={},
        db=db,
        actor_user_id=actor.id,
    )
    if not sent:
        raise HTTPException(status_code=503, detail="Agent not connected")
    return {"command_id": cmd_id}


@router.post("/tokens", response_model=TokenIssueResponse, status_code=201)
async def generate_token(
    body: TokenCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    sys_settings = await db.get(SystemSettings, 1)
    expiry_hours = sys_settings.agent_token_expiry_hours if sys_settings else 24
    plaintext = _generate_token()
    token = RegistrationToken(
        token_hash=hash_token(plaintext),
        agent_type=body.agent_type,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=expiry_hours),
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    emit_agent_changed()
    await log_auth_event(
        db,
        "agent.token.issue",
        actor_user_id=actor.id,
        details={"agent_type": body.agent_type, "token_id": str(token.id)},
    )
    return TokenIssueResponse(
        id=token.id,
        agent_type=token.agent_type,
        used=token.used,
        expires_at=token.expires_at,
        created_at=token.created_at,
        token=plaintext,
    )

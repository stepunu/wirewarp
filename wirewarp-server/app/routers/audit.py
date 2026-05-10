from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_role
from app.database import get_db
from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.models.user import User
from app.schemas.audit import AuditEntryRead

router = APIRouter()


@router.get("", response_model=list[AuditEntryRead])
async def list_audit(
    limit: int = Query(50, ge=1, le=500),
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin", "operator", "viewer")),
):
    actor = aliased(User)
    q = (
        select(CommandLog, Agent.name, actor.username)
        .outerjoin(Agent, Agent.id == CommandLog.agent_id)
        .outerjoin(actor, actor.id == CommandLog.actor_user_id)
        .order_by(CommandLog.executed_at.desc())
        .limit(limit)
    )
    if agent_id:
        q = q.where(CommandLog.agent_id == agent_id)
    if event_type:
        q = q.where(CommandLog.event_type == event_type)
    rows = (await db.execute(q)).all()
    return [
        AuditEntryRead(
            id=log.id,
            agent_id=log.agent_id,
            agent_name=name,
            actor_user_id=log.actor_user_id,
            actor_username=actor_name,
            command_type=log.command_type,
            event_type=log.event_type,
            success=log.success,
            output=log.output,
            details_json=log.details_json,
            executed_at=log.executed_at,
        )
        for log, name, actor_name in rows
    ]

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.models.metric import Metric


async def handle_heartbeat(agent_id: str, msg: dict, db: AsyncSession) -> None:
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)
        await db.commit()


async def handle_command_result(agent_id: str, msg: dict, db: AsyncSession) -> None:
    """Update the command_log entry and mark success/failure."""
    command_id = msg.get("command_id")
    success = msg.get("success", False)
    output = msg.get("output", "")

    if command_id:
        result = await db.execute(select(CommandLog).where(CommandLog.id == command_id))
        log = result.scalar_one_or_none()
        if log:
            log.success = success
            log.output = output
            await db.commit()

    # Always update last_seen
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)
        await db.commit()


async def handle_metrics(agent_id: str, msg: dict, db: AsyncSession) -> None:
    timestamp_raw = msg.get("timestamp")
    try:
        timestamp = datetime.fromisoformat(timestamp_raw) if timestamp_raw else datetime.now(timezone.utc)
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    metric = Metric(
        agent_id=agent_id,
        timestamp=timestamp,
        data={k: v for k, v in msg.items() if k not in ("type", "timestamp")},
    )
    db.add(metric)

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent:
        agent.last_seen = datetime.now(timezone.utc)

    await db.commit()


async def dispatch(agent_id: str, msg: dict, db: AsyncSession) -> None:
    msg_type = msg.get("type")
    if msg_type == "heartbeat":
        await handle_heartbeat(agent_id, msg, db)
    elif msg_type == "command_result":
        await handle_command_result(agent_id, msg, db)
    elif msg_type == "metrics":
        await handle_metrics(agent_id, msg, db)
    # Unknown message types are silently ignored

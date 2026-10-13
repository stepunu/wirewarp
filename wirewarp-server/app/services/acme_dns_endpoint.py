from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.edge_node import EdgeNode
from app.models.system_settings import SystemSettings


async def effective_rfc2136_nameserver(
    db: AsyncSession,
    agent_id: uuid.UUID | str | None = None,
    settings: SystemSettings | None = None,
) -> str | None:
    if agent_id is not None:
        node = await db.get(EdgeNode, uuid.UUID(str(agent_id)))
        if node is not None and node.rfc2136_nameserver_override:
            return node.rfc2136_nameserver_override
    if settings is None:
        settings = await db.get(SystemSettings, 1)
    return settings.letsencrypt_rfc2136_nameserver if settings is not None else None

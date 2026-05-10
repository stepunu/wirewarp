import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEntryRead(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID | None
    agent_name: str | None
    actor_user_id: uuid.UUID | None = None
    actor_username: str | None = None
    command_type: str
    event_type: str | None = None
    success: bool | None
    output: str | None
    details_json: dict[str, Any] | None = None
    executed_at: datetime

    model_config = ConfigDict(from_attributes=True)

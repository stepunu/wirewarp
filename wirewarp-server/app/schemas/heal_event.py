import uuid
from datetime import datetime

from pydantic import BaseModel


class HealEventRead(BaseModel):
    id: int
    agent_id: uuid.UUID
    mode: str
    interface: str | None
    healed: list[str]
    occurred_at: datetime

    model_config = {"from_attributes": True}

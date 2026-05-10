import uuid
from datetime import datetime

from pydantic import BaseModel


class AgentCreate(BaseModel):
    name: str
    type: str  # 'server' | 'client'


class AgentRead(BaseModel):
    id: uuid.UUID
    name: str
    type: str
    hostname: str | None
    public_ip: str | None
    status: str
    version: str | None
    last_seen: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AgentJWTRead(BaseModel):
    agent_id: uuid.UUID
    jwt: str

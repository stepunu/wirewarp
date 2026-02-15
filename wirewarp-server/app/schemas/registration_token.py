from datetime import datetime

from pydantic import BaseModel


class TokenCreate(BaseModel):
    agent_type: str  # 'server' | 'client'


class TokenRead(BaseModel):
    token: str
    agent_type: str
    used: bool
    expires_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}

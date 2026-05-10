import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TokenCreate(BaseModel):
    agent_type: str  # 'server' | 'client'


class TokenRead(BaseModel):
    """List/get response — never includes the plaintext."""

    id: uuid.UUID
    agent_type: str
    used: bool
    expires_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenIssueResponse(TokenRead):
    """Returned exactly once on POST /api/agents/tokens. The plaintext
    is shown to the admin so they can paste it into the agent install
    command; the server only persists the SHA-256 hash and can never
    reproduce this value again.
    """

    token: str

import uuid
from datetime import datetime

from pydantic import BaseModel


class ServiceTemplateCreate(BaseModel):
    name: str
    protocol: str  # 'tcp' | 'udp' | 'both'
    ports: str  # e.g. "2302-2305,27016"


class ServiceTemplateRead(BaseModel):
    id: uuid.UUID
    name: str
    protocol: str
    ports: str
    is_builtin: bool
    created_at: datetime

    model_config = {"from_attributes": True}

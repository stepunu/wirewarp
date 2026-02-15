import uuid
from datetime import datetime

from pydantic import BaseModel


class PortForwardCreate(BaseModel):
    tunnel_server_id: uuid.UUID
    tunnel_client_id: uuid.UUID
    protocol: str  # 'tcp' | 'udp'
    public_port: int
    destination_ip: str
    destination_port: int
    description: str | None = None


class PortForwardRead(BaseModel):
    id: uuid.UUID
    tunnel_server_id: uuid.UUID
    tunnel_client_id: uuid.UUID
    protocol: str
    public_port: int
    destination_ip: str
    destination_port: int
    description: str | None
    active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class PortForwardUpdate(BaseModel):
    active: bool | None = None
    description: str | None = None

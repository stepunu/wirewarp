import uuid
from datetime import datetime

from pydantic import BaseModel


class TunnelClientCreate(BaseModel):
    agent_id: uuid.UUID
    tunnel_server_id: uuid.UUID | None = None
    tunnel_ip: str | None = None
    vm_network: str | None = None
    lan_ip: str | None = None
    is_gateway: bool = False


class TunnelClientRead(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    tunnel_server_id: uuid.UUID | None
    tunnel_ip: str | None
    vm_network: str | None
    lan_ip: str | None
    is_gateway: bool
    wg_public_key: str | None
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TunnelClientUpdate(BaseModel):
    tunnel_server_id: uuid.UUID | None = None
    tunnel_ip: str | None = None
    vm_network: str | None = None
    lan_ip: str | None = None
    is_gateway: bool | None = None

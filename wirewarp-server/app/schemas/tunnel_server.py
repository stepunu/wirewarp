import uuid
from datetime import datetime

from pydantic import BaseModel


class TunnelServerRead(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    wg_port: int
    wg_interface: str
    public_ip: str | None
    public_iface: str
    wg_public_key: str | None
    tunnel_network: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TunnelServerUpdate(BaseModel):
    wg_port: int | None = None
    public_iface: str | None = None
    tunnel_network: str | None = None

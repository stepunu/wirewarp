import uuid
from datetime import datetime

from pydantic import BaseModel


class TunnelClientAttachmentCreate(BaseModel):
    tunnel_client_id: uuid.UUID
    tunnel_server_id: uuid.UUID
    tunnel_ip: str | None = None  # auto-allocated if omitted


class TunnelClientAttachmentRead(BaseModel):
    id: uuid.UUID
    tunnel_client_id: uuid.UUID
    tunnel_server_id: uuid.UUID
    tunnel_ip: str
    wg_interface: str
    wg_public_key: str | None
    fwmark: int
    route_table_id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class TunnelClientAttachmentUpdate(BaseModel):
    tunnel_ip: str | None = None

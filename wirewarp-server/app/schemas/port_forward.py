import uuid
from datetime import datetime

from pydantic import BaseModel


class PortForwardCreate(BaseModel):
    attachment_id: uuid.UUID
    tunnel_server_ip_id: uuid.UUID | None = None
    protocol: str  # 'tcp' | 'udp'
    public_port: int
    public_port_end: int | None = None
    destination_ip: str
    destination_port: int
    destination_port_end: int | None = None
    description: str | None = None


class PortForwardRead(BaseModel):
    id: uuid.UUID
    attachment_id: uuid.UUID
    tunnel_server_ip_id: uuid.UUID | None
    protocol: str
    public_port: int
    public_port_end: int | None
    destination_ip: str
    destination_port: int
    destination_port_end: int | None
    description: str | None
    active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class PortForwardUpdate(BaseModel):
    # attachment_id can be patched to migrate a forward to a different
    # (server, client) peering — used by the LAN-client egress pin
    # auto-migration so inbound + outbound stay symmetric.
    attachment_id: uuid.UUID | None = None
    tunnel_server_ip_id: uuid.UUID | None = None
    protocol: str | None = None
    public_port: int | None = None
    public_port_end: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    destination_port_end: int | None = None
    description: str | None = None
    active: bool | None = None

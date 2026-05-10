import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.tunnel_server_ip import TunnelServerIPRead


class TunnelServerRead(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    wg_port: int
    wg_interface: str
    primary_ip: str | None = None
    public_iface: str
    wg_public_key: str | None
    tunnel_network: str
    created_at: datetime
    ips: list[TunnelServerIPRead] = []

    model_config = {"from_attributes": True}


class TunnelServerUpdate(BaseModel):
    wg_port: int | None = None
    public_iface: str | None = None
    # tunnel_network is intentionally NOT editable here — use POST
    # /tunnel-servers/{id}/rebase, which also renumbers clients & forwards.

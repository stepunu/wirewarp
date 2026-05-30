from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.crowdsec import CrowdSecSnapshotRead
from app.schemas.security import SiteRead, TraefikStatusRead


class NodeRead(BaseModel):
    agent_id: uuid.UUID
    name: str
    role: str
    status: str
    hostname: str | None = None
    public_ip: str | None = None
    version: str | None = None
    last_seen: datetime | None = None
    tunnel_server_id: uuid.UUID | None = None
    tunnel_client_id: uuid.UUID | None = None
    is_gateway: bool = False
    edge_phase: str | None = None


class NodeEdgeRead(BaseModel):
    agent_id: uuid.UUID
    phase: str
    crowdsec: CrowdSecSnapshotRead
    traefik: TraefikStatusRead
    sites: list[SiteRead] = []

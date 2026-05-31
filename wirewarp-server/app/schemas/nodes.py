from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.crowdsec import CrowdSecSnapshotRead
from app.schemas.security import ServerEdgePolicyRead, SiteRead, TraefikStatusRead


class EdgeComponentRead(BaseModel):
    component: str
    desired: str = "disabled"
    installed: bool = False
    running: bool = False
    phase: str = "disabled"
    version: str | None = None
    last_error: str | None = None
    updated_at: datetime | None = None


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
    edge_mode: str | None = None
    edge_state: str | None = None
    edge_install_phase: str | None = None
    edge_components: dict[str, EdgeComponentRead] = Field(default_factory=dict)


class NodeEdgeCapabilitiesRead(BaseModel):
    agent_id: uuid.UUID
    mode: str = "tcp_udp_only"
    state: str = "disabled"
    install_phase: str = "disabled"
    last_error: str | None = None
    components: dict[str, EdgeComponentRead]
    unavailable_reason: str | None = None


class NodeEdgeCapabilitiesUpdate(BaseModel):
    mode: str | None = None
    state: str | None = None
    components: dict[str, str] | None = None


class NodeEdgeActionResult(BaseModel):
    sent: bool
    command_id: str | None = None
    edge: NodeEdgeCapabilitiesRead


class NodeEdgeRead(BaseModel):
    agent_id: uuid.UUID
    mode: str = "tcp_udp_only"
    state: str = "disabled"
    phase: str
    install_phase: str = "disabled"
    last_error: str | None = None
    unavailable_reason: str | None = None
    components: dict[str, EdgeComponentRead]
    policy: ServerEdgePolicyRead
    crowdsec: CrowdSecSnapshotRead
    traefik: TraefikStatusRead
    sites: list[SiteRead] = []

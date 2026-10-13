from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints, field_validator

from app.schemas.crowdsec import CrowdSecSnapshotRead
from app.schemas.security import ServerEdgePolicyRead, SiteRead, TraefikStatusRead
from app.schemas.system_settings import SystemSettingsUpdate


class EdgeComponentRead(BaseModel):
    component: str
    desired: str = "disabled"
    installed: bool = False
    running: bool = False
    phase: str = "disabled"
    version: str | None = None
    last_error: str | None = None
    updated_at: datetime | None = None


class NodeRename(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]


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
    lan_bind_ip: str | None = None
    public_bind_ip: str | None = None
    relay_enabled: bool = False
    runtime_mode: str = "disabled"


class NodeEdgeCapabilitiesRead(BaseModel):
    agent_id: uuid.UUID
    mode: str = "tcp_udp_only"
    state: str = "disabled"
    install_phase: str = "disabled"
    last_error: str | None = None
    components: dict[str, EdgeComponentRead]
    unavailable_reason: str | None = None
    lan_bind_ip: str | None = None
    public_bind_ip: str | None = None
    public_ingress_available: bool = True
    relay_enabled: bool = False
    runtime_mode: str = "disabled"
    rfc2136_nameserver_override: str | None = None
    rfc2136_effective_nameserver: str | None = None


class NodeEdgeCapabilitiesUpdate(BaseModel):
    mode: str | None = None
    state: str | None = None
    components: dict[str, str] | None = None
    lan_bind_ip: str | None = None
    public_bind_ip: str | None = None
    rfc2136_nameserver_override: str | None = None

    @field_validator("rfc2136_nameserver_override")
    @classmethod
    def validate_rfc2136_nameserver_override(cls, value: str | None) -> str | None:
        return SystemSettingsUpdate.validate_nameserver(value)


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
    lan_bind_ip: str | None = None
    public_bind_ip: str | None = None
    public_ingress_available: bool = True
    relay_enabled: bool = False
    runtime_mode: str = "disabled"
    policy: ServerEdgePolicyRead
    crowdsec: CrowdSecSnapshotRead
    traefik: TraefikStatusRead
    sites: list[SiteRead] = []

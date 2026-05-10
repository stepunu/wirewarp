"""Pydantic schemas for VPN endpoints, profiles, permissions."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Protocol = Literal["tcp", "udp", "icmp", "any"]
TunnelMode = Literal["split", "full"]


# ---- permissions ----


class VpnPermissionRead(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    vpn_endpoint_id: uuid.UUID
    destination: str
    protocol: Protocol
    port_range_start: int | None = None
    port_range_end: int | None = None

    model_config = ConfigDict(from_attributes=True)


class VpnPermissionInput(BaseModel):
    """One rule in a permission set replacement payload."""

    destination: str
    protocol: Protocol = "any"
    port_range_start: int | None = Field(default=None, ge=1, le=65535)
    port_range_end: int | None = Field(default=None, ge=1, le=65535)


class VpnUserPermissionsRead(BaseModel):
    """The admin-facing per-user, per-endpoint summary used by the
    permissions sheet. Always present whether or not the user has
    created any profiles yet."""

    user_id: uuid.UUID
    username: str
    auth_provider: str
    profile_count: int
    permissions: list[VpnPermissionRead] = []


# ---- endpoint ----


class VpnEndpointRead(BaseModel):
    id: uuid.UUID
    tunnel_client_id: uuid.UUID
    wg_interface: str
    listen_port: int
    vpn_network: str
    public_endpoint: str
    wg_public_key: str | None
    dns_servers: list[str] | None
    enabled: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VpnEndpointCreate(BaseModel):
    tunnel_client_id: uuid.UUID
    public_endpoint: str
    listen_port: int = 51821
    wg_interface: str = "wg-vpn0"
    dns_servers: list[str] | None = None
    # vpn_network omitted — server allocates from the pool


class VpnEndpointUpdate(BaseModel):
    public_endpoint: str | None = None
    listen_port: int | None = None
    dns_servers: list[str] | None = None
    enabled: bool | None = None


# ---- profile ----


class VpnProfileRead(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    vpn_endpoint_id: uuid.UUID
    label: str
    tunnel_ip: str
    wg_public_key: str
    tunnel_mode: TunnelMode
    last_handshake_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VpnProfileSelfCreate(BaseModel):
    """Body for POST /api/vpn-profiles/me."""

    vpn_endpoint_id: uuid.UUID
    label: str = Field(min_length=1, max_length=64)
    # Default `full` to mirror wg-easy: AllowedIPs = 0.0.0.0/0, ::/0 means
    # iOS reliably uses the WG-side DNS (no split-DNS race) and all
    # internal hostnames resolve correctly. Operators who want narrower
    # split-tunnel scope can pass tunnel_mode="split" explicitly.
    tunnel_mode: TunnelMode = "full"


class VpnProfileAdminCreate(VpnProfileSelfCreate):
    """Admin can create on behalf of a user."""

    user_id: uuid.UUID


class VpnProfileUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=64)
    tunnel_mode: TunnelMode | None = None


class VpnProfileIssued(VpnProfileRead):
    """Returned exactly once on create / regenerate. Carries the rendered
    `.conf` text and the plaintext private key — neither is persisted on
    the server."""

    config_text: str
    wg_private_key: str
    permissions: list[VpnPermissionRead] = []

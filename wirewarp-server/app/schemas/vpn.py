"""Pydantic schemas for VPN endpoints, profiles, permissions."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services.vpn_routes import normalize_remote_subnets


Protocol = Literal["tcp", "udp", "icmp", "any"]
TunnelMode = Literal["split", "full"]
ConfigRouteStatus = Literal["current", "stale", "legacy", "not_applicable"]
GatewaySyncStatus = Literal["not_required", "dispatched", "pending"]


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

    @field_validator("destination")
    @classmethod
    def _one_ipv4_host_or_cidr(cls, v: str) -> str:
        # Each row holds exactly one CIDR. Comma/whitespace-joined values
        # were silently stored as a single destination string, which the
        # agent's IPv4CIDR validator rejects — the peer never reaches
        # wg-vpn0. Reject at the API boundary so server and agent agree
        # on what's acceptable. The UI splits multi-host input client-side
        # before submit; this is the safety net.
        s = v.strip() if isinstance(v, str) else v
        if not isinstance(s, str) or not s:
            raise ValueError("destination must be a non-empty string")
        if any(ch in s for ch in ",; \t"):
            raise ValueError(
                "Each permission row holds one CIDR; "
                "submit multiple rows for multiple destinations.",
            )
        try:
            ipaddress.IPv4Network(s, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
            raise ValueError(
                f"destination must be an IPv4 host or CIDR (got {s!r})",
            ) from exc
        return s


class VpnUserPermissionsRead(BaseModel):
    """The admin-facing per-user, per-endpoint summary used by the
    permissions sheet. Always present whether or not the user has
    created any profiles yet."""

    user_id: uuid.UUID
    username: str
    auth_provider: str
    profile_count: int
    permissions: list[VpnPermissionRead] = []


class VpnPermissionsUpdateRead(BaseModel):
    permissions: list[VpnPermissionRead]
    gateway_sync: GatewaySyncStatus
    command_ids: list[str]


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
    remote_subnets: list[str]
    route_revision: int
    enabled: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VpnEndpointCreate(BaseModel):
    tunnel_client_id: uuid.UUID
    public_endpoint: str
    listen_port: int = 51821
    wg_interface: str = "wg-vpn0"
    dns_servers: list[str] | None = None
    remote_subnets: list[str] = Field(default_factory=list)
    # vpn_network omitted — server allocates from the pool

    @field_validator("remote_subnets")
    @classmethod
    def _valid_remote_subnets(cls, values: list[str]) -> list[str]:
        return normalize_remote_subnets(values)


class VpnEndpointUpdate(BaseModel):
    public_endpoint: str | None = None
    listen_port: int | None = None
    dns_servers: list[str] | None = None
    enabled: bool | None = None
    remote_subnets: list[str] | None = None

    @field_validator("remote_subnets")
    @classmethod
    def _valid_remote_subnets(cls, values: list[str] | None) -> list[str] | None:
        return None if values is None else normalize_remote_subnets(values)


# ---- profile ----


class VpnProfileRead(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    vpn_endpoint_id: uuid.UUID
    label: str
    tunnel_ip: str
    wg_public_key: str
    tunnel_mode: TunnelMode
    issued_route_revision: int | None
    config_route_status: ConfigRouteStatus
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

    model_config = ConfigDict(extra="forbid")


class VpnProfileIssued(VpnProfileRead):
    """Returned exactly once on create / regenerate. Carries the rendered
    `.conf` text and the plaintext private key — neither is persisted on
    the server."""

    config_text: str
    wg_private_key: str
    permissions: list[VpnPermissionRead] = []

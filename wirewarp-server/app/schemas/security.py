"""Pydantic schemas for the Security Edge Console API."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Security Events
# ---------------------------------------------------------------------------

class SecurityEventRead(BaseModel):
    id: int
    agent_id: uuid.UUID
    source: str
    kind: str
    ip: str | None = None
    value: str | None = None
    action: str | None = None
    raw: dict | None = None
    occurred_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Security Overview
# ---------------------------------------------------------------------------

class TimePoint(BaseModel):
    t: datetime
    value: int


class TopItem(BaseModel):
    name: str
    count: int


class TopAttacker(BaseModel):
    ip: str
    count: int


class ServerStatus(BaseModel):
    server_id: uuid.UUID
    agent_id: uuid.UUID | None = None
    name: str
    crowdsec_running: bool
    traefik_running: bool


class SecurityKPIs(BaseModel):
    access: int
    visitors: int
    blocked: int
    attack_ips: int
    err_4xx: int
    err_5xx: int


class SecurityOverview(BaseModel):
    kpis: SecurityKPIs
    access_series: list[TimePoint]
    block_series: list[TimePoint]
    top_attackers: list[TopAttacker]
    top_scenarios: list[TopItem]
    servers: list[ServerStatus]


# ---------------------------------------------------------------------------
# Edge Route Config
# ---------------------------------------------------------------------------

class EdgeRouteConfigRead(BaseModel):
    id: uuid.UUID
    port_forward_id: uuid.UUID
    waf_mode: str
    rate_limit_rps: int | None = None
    rate_limit_burst: int | None = None
    antibot: bool
    auth_mode: str
    auth_config: dict | None = None
    ip_allow: list | None = None
    ip_deny: list | None = None
    geo_block: list | None = None
    tls_source: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EdgeRouteConfigUpdate(BaseModel):
    waf_mode: str | None = None
    rate_limit_rps: int | None = None
    rate_limit_burst: int | None = None
    antibot: bool | None = None
    auth_mode: str | None = None
    auth_config: dict | None = None
    ip_allow: list | None = None
    ip_deny: list | None = None
    geo_block: list | None = None
    tls_source: str | None = None


# ---------------------------------------------------------------------------
# Sites (HTTP port_forwards + edge_route_config)
# ---------------------------------------------------------------------------

class SiteRead(BaseModel):
    id: uuid.UUID
    attachment_id: uuid.UUID
    tunnel_server_ip_id: uuid.UUID | None = None
    server_id: uuid.UUID | None = None
    agent_id: uuid.UUID | None = None
    protocol: str = "tcp"
    public_port: int = 443
    public_port_end: int | None = None
    domain: str | None
    destination_ip: str
    destination_port: int
    destination_port_end: int | None = None
    active: bool
    description: str | None = None
    service_kind: str = "http"
    edge_config: EdgeRouteConfigRead | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class SiteCreate(BaseModel):
    attachment_id: uuid.UUID
    domain: str | None = None
    destination_ip: str
    destination_port: int
    description: str | None = None
    tunnel_server_ip_id: uuid.UUID | None = None
    # Initial edge config values (optional)
    waf_mode: str = "observe"
    rate_limit_rps: int | None = None
    rate_limit_burst: int | None = None
    antibot: bool = False
    auth_mode: str = "none"
    auth_config: dict | None = None
    ip_allow: list | None = None
    ip_deny: list | None = None
    geo_block: list | None = None
    tls_source: str = "letsencrypt"


class SiteUpdate(BaseModel):
    domain: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    description: str | None = None
    active: bool | None = None
    waf_mode: str | None = None
    rate_limit_rps: int | None = None
    rate_limit_burst: int | None = None
    antibot: bool | None = None
    auth_mode: str | None = None
    auth_config: dict | None = None
    ip_allow: list | None = None
    ip_deny: list | None = None
    geo_block: list | None = None
    tls_source: str | None = None


# ---------------------------------------------------------------------------
# Traefik Status
# ---------------------------------------------------------------------------

class TraefikStatusRead(BaseModel):
    installed: bool = False
    running: bool = False
    version: str | None = None
    routes_count: int = 0
    error: str | None = None
    phase: str = "unknown"
    last_error: str | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Ban (read-only derived view)
# ---------------------------------------------------------------------------

class BanRead(BaseModel):
    ip: str
    count: int
    source: str  # 'crowdsec' or 'security_event'


# ---------------------------------------------------------------------------
# Cert (read-only placeholder)
# ---------------------------------------------------------------------------

class CertRead(BaseModel):
    domain: str
    port_forward_id: uuid.UUID
    status: str  # 'managed' placeholder; real ACME status is a later enhancement

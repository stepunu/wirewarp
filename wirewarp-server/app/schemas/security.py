"""Pydantic schemas for the Security Edge Console API."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


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


class SecurityEventGroupRead(BaseModel):
    agent_id: uuid.UUID
    source: str
    kind: str
    ip: str | None = None
    value: str | None = None
    action: str | None = None
    count: int
    first_seen_at: datetime
    last_seen_at: datetime


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
    upstream_scheme: str = "http"
    upstream_insecure_skip_verify: bool = False
    imported_router_name: str | None = None
    imported_service_name: str | None = None
    imported_middlewares: list | None = None
    import_warnings: list | None = None
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
    upstream_scheme: str | None = None
    upstream_insecure_skip_verify: bool | None = None


class EffectiveRateLimitValue(BaseModel):
    rps: int | None = None
    burst: int | None = None


class EffectiveRateLimit(BaseModel):
    global_: EffectiveRateLimitValue | None = Field(default=None, alias="global")
    site: EffectiveRateLimitValue | None = None
    model_config = {"populate_by_name": True}


class SiteEffectivePolicy(BaseModel):
    rate_limit: EffectiveRateLimit
    middleware_chain: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ServerEdgePolicyRead(BaseModel):
    server_id: uuid.UUID
    agent_id: uuid.UUID
    rate_limit_rps: int | None = None
    rate_limit_burst: int | None = None


class ServerEdgePolicyUpdate(BaseModel):
    rate_limit_rps: int | None = None
    rate_limit_burst: int | None = None


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
    effective_policy: SiteEffectivePolicy | None = None
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
    upstream_scheme: str = "http"
    upstream_insecure_skip_verify: bool = False


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
    upstream_scheme: str | None = None
    upstream_insecure_skip_verify: bool | None = None


# ---------------------------------------------------------------------------
# Traefik Import
# ---------------------------------------------------------------------------

class TraefikImportRequest(BaseModel):
    server_id: uuid.UUID
    attachment_id: uuid.UUID
    content: str
    content_format: str = "auto"
    domain_suffix: str | None = None
    activate: bool = False
    overwrite: bool = False


class TraefikImportRoutePreview(BaseModel):
    router_name: str
    domain: str | None = None
    service_name: str | None = None
    upstream_url: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    upstream_scheme: str = "http"
    upstream_insecure_skip_verify: bool = False
    tls_source: str = "letsencrypt"
    middlewares: list[str] = Field(default_factory=list)
    mapped_policy: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    importable: bool = False
    existing_site_id: uuid.UUID | None = None


class TraefikImportSummary(BaseModel):
    routers: int
    importable: int
    skipped: int
    existing: int


class TraefikImportPreview(BaseModel):
    summary: TraefikImportSummary
    routes: list[TraefikImportRoutePreview]


class TraefikImportResult(TraefikImportPreview):
    created: int
    updated: int
    skipped: int


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

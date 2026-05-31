from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EdgeProfileUpsert(BaseModel):
    name: str
    slug: str | None = None
    description: str | None = None
    scope: str = "global"
    agent_id: uuid.UUID | None = None
    policy: dict[str, Any] = Field(default_factory=dict)


class EdgeProfileRead(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str | None = None
    scope: str
    agent_id: uuid.UUID | None = None
    policy: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class EdgeNodePolicyUpdate(BaseModel):
    default_profile_id: uuid.UUID | None = None
    client_ip_strategy: str | None = None
    trusted_proxy_cidrs: list[str] | None = None
    cloudflare_mode: str | None = None
    access_log_retention_hours: int | None = None
    security_event_retention_days: int | None = None
    policy: dict[str, Any] | None = None


class EdgeNodePolicyRead(BaseModel):
    agent_id: uuid.UUID
    default_profile_id: uuid.UUID | None = None
    client_ip_strategy: str
    trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    cloudflare_mode: str
    access_log_retention_hours: int
    security_event_retention_days: int
    policy: dict[str, Any] = Field(default_factory=dict)
    effective: dict[str, Any] = Field(default_factory=dict)


class EdgeRouteUpsert(BaseModel):
    attachment_id: uuid.UUID | None = None
    enabled: bool | None = None
    priority: int | None = None
    profile_id: uuid.UUID | None = None
    profile: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    description: str | None = None
    policy: dict[str, Any] | None = None
    upstream_scheme: str | None = None
    upstream_insecure_skip_verify: bool | None = None


class EdgeRouteRead(BaseModel):
    id: uuid.UUID
    node_id: uuid.UUID
    server_id: uuid.UUID
    attachment_id: uuid.UUID
    domain: str | None = None
    enabled: bool
    priority: int = 0
    profile_id: uuid.UUID | None = None
    destination_ip: str
    destination_port: int
    description: str | None = None
    policy: dict[str, Any] = Field(default_factory=dict)
    effective: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class EdgeEffectivePolicyRead(BaseModel):
    route_id: uuid.UUID
    desired: dict[str, Any] = Field(default_factory=dict)
    effective: dict[str, Any] = Field(default_factory=dict)
    sources: dict[str, dict[str, Any]] = Field(default_factory=dict)


class EdgePathRuleCreate(BaseModel):
    name: str
    match: dict[str, Any]
    priority: int = 0
    enabled: bool = True
    policy: dict[str, Any] = Field(default_factory=dict)


class EdgePathRuleRead(BaseModel):
    id: uuid.UUID
    route_id: uuid.UUID
    name: str
    match: dict[str, Any]
    priority: int
    enabled: bool
    policy: dict[str, Any] = Field(default_factory=dict)
    effective: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class EdgeAccessEventRead(BaseModel):
    id: int
    agent_id: uuid.UUID
    route_id: uuid.UUID | None = None
    request_id: str | None = None
    occurred_at: datetime
    host: str | None = None
    path: str | None = None
    method: str | None = None
    status_code: int | None = None
    client_ip: str | None = None
    client_country: str | None = None
    client_asn: str | None = None
    user_agent: str | None = None
    referer: str | None = None
    action: str
    source: str
    latency_ms: int | None = None
    cache_status: str | None = None
    upstream_url: str | None = None
    upstream_status: int | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    matched_rule: str | None = None
    sampled: bool = False

    model_config = {"from_attributes": True}


class EdgeAccessEventList(BaseModel):
    items: list[EdgeAccessEventRead]
    next_cursor: int | None = None


class EdgeCachePatch(BaseModel):
    mode: str
    browser_ttl_seconds: int | None = None
    edge_ttl_seconds: int | None = None
    cache_status_header: bool | None = None


class EdgeCacheRead(BaseModel):
    available: bool
    reason: str | None = None
    backend: dict[str, Any] | None = None
    policy: dict[str, Any] = Field(default_factory=dict)


class EdgeCachePurgeRequest(BaseModel):
    scope: str = "node"
    route_id: uuid.UUID | None = None
    host: str | None = None
    path: str | None = None
    prefix: str | None = None


class EdgeFragmentCreate(BaseModel):
    name: str
    fragment_type: str
    content: dict[str, Any]
    route_id: uuid.UUID | None = None
    enabled: bool = True


class EdgeFragmentRead(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    route_id: uuid.UUID | None = None
    name: str
    fragment_type: str
    content: dict[str, Any]
    enabled: bool
    validation_state: str
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EdgeRenderedRead(BaseModel):
    desired_hash: str
    static_hash: str | None = None
    dynamic_hash: str | None = None
    cache_hash: str | None = None
    dynamic: dict[str, Any] = Field(default_factory=dict)


class EdgeConfigVersionRead(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    desired_hash: str
    rendered_static_hash: str | None = None
    rendered_dynamic_hash: str | None = None
    rendered_cache_hash: str | None = None
    created_at: datetime
    applied_at: datetime | None = None
    agent_result: str | None = None

    model_config = {"from_attributes": True}


class EdgeDesiredStateResponse(BaseModel):
    dry_run: bool = False
    changed: bool = False
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)
    diff: str | None = None
    profiles: list[dict[str, Any]] = Field(default_factory=list)
    routes: list[dict[str, Any]] = Field(default_factory=list)
    effective: dict[str, Any] = Field(default_factory=dict)
    reconcile_sent: bool = False

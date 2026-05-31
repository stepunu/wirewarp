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

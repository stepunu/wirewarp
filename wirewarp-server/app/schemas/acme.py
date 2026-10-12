from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.system_settings import valid_dns_name


class DNSChallengeTestRequest(BaseModel):
    agent_id: uuid.UUID
    domain: str = Field(min_length=1, max_length=253)

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        value = value.strip().lower()
        if value.startswith("*."):
            value = value[2:]
        if not valid_dns_name(value) or "_" in value or "." not in value.rstrip("."):
            raise ValueError("Use a fully qualified service domain")
        return value.rstrip(".")


class DNSAuthoritativeResult(BaseModel):
    server: str
    ok: bool
    detail: str


class DNSChallengeResult(BaseModel):
    ok: bool
    stage: str
    detail: str
    record_name: str
    cleanup_ok: bool
    authoritative_results: list[DNSAuthoritativeResult]


class DNSChallengeTestStarted(BaseModel):
    status: Literal["running"] = "running"
    sent: Literal[True] = True
    command_id: str


class DNSChallengeTestRead(BaseModel):
    status: Literal["pending", "success", "failure"]
    command_id: str
    result: DNSChallengeResult | None = None

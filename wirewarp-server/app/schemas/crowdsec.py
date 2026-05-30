from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class CrowdSecScenarioCount(BaseModel):
    name: str
    count: int


class CrowdSecTopIp(BaseModel):
    ip: str
    count: int


class CrowdSecSnapshotRead(BaseModel):
    installed: bool = False
    running: bool
    version: str | None = None
    total_decisions: int = 0
    top_scenarios: list[CrowdSecScenarioCount] = Field(default_factory=list)
    top_ips: list[CrowdSecTopIp] = Field(default_factory=list)
    error: str | None = None
    phase: str = "unknown"
    last_error: str | None = None
    appsec_enabled: bool = False
    bouncer_registered: bool = False
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}

    @field_validator("top_scenarios", "top_ips", mode="before")
    @classmethod
    def _empty_list_for_missing_snapshot_json(cls, value):
        return [] if value is None else value

from datetime import datetime

from pydantic import BaseModel


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
    top_scenarios: list[CrowdSecScenarioCount] = []
    top_ips: list[CrowdSecTopIp] = []
    error: str | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}

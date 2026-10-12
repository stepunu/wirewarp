from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EdgeMigrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_route_id: uuid.UUID
    target_agent_id: uuid.UUID
    target_attachment_id: uuid.UUID
    visibility: Literal["public_only", "both"] = "both"


class EdgeMigrationAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=1)


class EdgeMigrationStageRequest(EdgeMigrationRequest):
    expected_source_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

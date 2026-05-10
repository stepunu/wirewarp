import uuid
from datetime import datetime

from pydantic import BaseModel, model_validator

from app.schemas.tunnel_client_attachment import TunnelClientAttachmentRead


class TunnelClientCreate(BaseModel):
    agent_id: uuid.UUID
    vm_network: str | None = None
    lan_ip: str | None = None
    is_gateway: bool = False


class TunnelClientRead(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    vm_network: str | None
    lan_ip: str | None
    is_gateway: bool
    status: str
    created_at: datetime
    attachments: list[TunnelClientAttachmentRead] = []

    model_config = {"from_attributes": True}


class TunnelClientUpdate(BaseModel):
    vm_network: str | None = None
    lan_ip: str | None = None
    is_gateway: bool | None = None

    # Reject legacy fields explicitly so callers see a useful error rather
    # than silently dropping their input.
    model_config = {"extra": "forbid"}

    @model_validator(mode="before")
    @classmethod
    def _reject_legacy(cls, values):
        if isinstance(values, dict):
            for legacy in ("tunnel_server_id", "tunnel_ip", "wg_public_key"):
                if legacy in values:
                    raise ValueError(
                        f"'{legacy}' is no longer a tunnel-client field; "
                        "manage attachments via /api/tunnel-client-attachments"
                    )
        return values

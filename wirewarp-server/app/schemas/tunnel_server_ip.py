import ipaddress
import uuid
from datetime import datetime

from pydantic import BaseModel, field_validator


def _validate_ipv4(value: str) -> str:
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid IPv4 address") from exc
    return str(addr)


class TunnelServerIPCreate(BaseModel):
    tunnel_server_id: uuid.UUID
    address: str
    label: str | None = None
    is_primary: bool = False

    @field_validator("address")
    @classmethod
    def _check_address(cls, value: str) -> str:
        return _validate_ipv4(value)


class TunnelServerIPRead(BaseModel):
    id: uuid.UUID
    tunnel_server_id: uuid.UUID
    address: str
    label: str | None
    is_primary: bool
    port_forward_count: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}


class TunnelServerIPUpdate(BaseModel):
    label: str | None = None
    is_primary: bool | None = None
    address: str | None = None

    @field_validator("address")
    @classmethod
    def _check_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_ipv4(value)

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


Role = Literal["admin", "operator", "viewer"]


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: Role = "admin"


class UserAdminUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    vpn_enabled: bool | None = None


class UserRead(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    role: str
    is_active: bool = True
    auth_provider: str = "local"
    last_login_at: datetime | None = None
    vpn_enabled: bool = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProvidersRead(BaseModel):
    active_provider: Literal["local", "oidc", "ldap"]

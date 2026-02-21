from pydantic import BaseModel


class SystemSettingsRead(BaseModel):
    public_url: str | None
    internal_url: str | None
    instance_name: str
    agent_token_expiry_hours: int

    model_config = {"from_attributes": True}


class SystemSettingsUpdate(BaseModel):
    public_url: str | None = None
    internal_url: str | None = None
    instance_name: str | None = None
    agent_token_expiry_hours: int | None = None

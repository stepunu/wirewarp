from pydantic import BaseModel, ConfigDict, model_validator
from typing import Any, Literal


AuthProvider = Literal["local", "oidc", "ldap"]


class SystemSettingsRead(BaseModel):
    public_url: str | None
    internal_url: str | None
    instance_name: str
    agent_token_expiry_hours: int
    dns_provider: str | None
    cloudflare_token_set: bool = False

    auth_provider: AuthProvider = "local"
    # Public-shape config — secrets stripped server-side. The UI reads
    # the rest of the OIDC/LDAP fields from these dicts to populate the
    # config form; the *_secret_set booleans tell it whether to render
    # "secret already saved" vs an empty input.
    oidc_config: dict[str, Any] | None = None
    ldap_config: dict[str, Any] | None = None
    oidc_secret_set: bool = False
    ldap_secret_set: bool = False

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="before")
    @classmethod
    def _shape(cls, data: Any) -> Any:
        if not hasattr(data, "cloudflare_api_token"):
            return data

        oidc_raw = getattr(data, "oidc_config", None) or None
        ldap_raw = getattr(data, "ldap_config", None) or None

        oidc_view = None
        oidc_secret_set = False
        if oidc_raw:
            oidc_view = {k: v for k, v in oidc_raw.items() if k != "client_secret"}
            oidc_secret_set = bool(oidc_raw.get("client_secret"))

        ldap_view = None
        ldap_secret_set = False
        if ldap_raw:
            ldap_view = {k: v for k, v in ldap_raw.items() if k != "bind_password"}
            ldap_secret_set = bool(ldap_raw.get("bind_password"))

        return {
            "public_url": data.public_url,
            "internal_url": data.internal_url,
            "instance_name": data.instance_name,
            "agent_token_expiry_hours": data.agent_token_expiry_hours,
            "dns_provider": data.dns_provider,
            "cloudflare_token_set": bool(data.cloudflare_api_token),
            "auth_provider": getattr(data, "auth_provider", "local") or "local",
            "oidc_config": oidc_view,
            "ldap_config": ldap_view,
            "oidc_secret_set": oidc_secret_set,
            "ldap_secret_set": ldap_secret_set,
        }


class SystemSettingsUpdate(BaseModel):
    public_url: str | None = None
    internal_url: str | None = None
    instance_name: str | None = None
    agent_token_expiry_hours: int | None = None
    dns_provider: str | None = None
    cloudflare_api_token: str | None = None

    auth_provider: AuthProvider | None = None
    # Whole-config replace. The router merges `*_config` over what's
    # already in the DB so the UI can omit `client_secret` / `bind_password`
    # to keep the existing encrypted value.
    oidc_config: dict[str, Any] | None = None
    ldap_config: dict[str, Any] | None = None


class AuthTestRequest(BaseModel):
    provider: AuthProvider
    config: dict[str, Any] | None = None


class AuthTestResponse(BaseModel):
    ok: bool
    detail: str

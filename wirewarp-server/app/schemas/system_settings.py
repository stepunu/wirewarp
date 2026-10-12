import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from typing import Any, Literal


AuthProvider = Literal["local", "oidc", "ldap"]
LetsEncryptChallenge = Literal["dns-01", "tls-alpn-01", "http-01"]
TSIGAlgorithm = Literal["hmac-sha256", "hmac-sha384", "hmac-sha512"]


def valid_dns_name(value: str) -> bool:
    name = value.removesuffix(".")
    return len(name) <= 253 and bool(name) and all(
        re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", label)
        for label in name.split(".")
    )


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
    captcha_provider: str | None = None
    captcha_site_key: str | None = None
    captcha_site_key_set: bool = False
    captcha_secret_key_set: bool = False
    letsencrypt_enabled: bool = False
    letsencrypt_email: str | None = None
    letsencrypt_challenge: LetsEncryptChallenge = "dns-01"
    letsencrypt_dns_provider: str | None = "cloudflare"
    letsencrypt_dns_resolvers: list[str] = Field(default_factory=lambda: ["1.1.1.1:53"])
    letsencrypt_use_staging: bool = False
    letsencrypt_cloudflare_token_set: bool = False
    letsencrypt_rfc2136_nameserver: str | None = None
    letsencrypt_rfc2136_tsig_key: str | None = None
    letsencrypt_rfc2136_tsig_algorithm: TSIGAlgorithm = "hmac-sha256"
    letsencrypt_rfc2136_secret_set: bool = False
    letsencrypt_dns_delay_seconds: int = 30

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
            "letsencrypt_rfc2136_nameserver": getattr(data, "letsencrypt_rfc2136_nameserver", None),
            "letsencrypt_rfc2136_tsig_key": getattr(data, "letsencrypt_rfc2136_tsig_key", None),
            "letsencrypt_rfc2136_tsig_algorithm": getattr(data, "letsencrypt_rfc2136_tsig_algorithm", None) or "hmac-sha256",
            "letsencrypt_rfc2136_secret_set": bool(getattr(data, "letsencrypt_rfc2136_tsig_secret", None)),
            "letsencrypt_dns_delay_seconds": getattr(data, "letsencrypt_dns_delay_seconds", 30),
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
            "captcha_provider": getattr(data, "captcha_provider", None),
            "captcha_site_key": getattr(data, "captcha_site_key", None),
            "captcha_site_key_set": bool(getattr(data, "captcha_site_key", None)),
            "captcha_secret_key_set": bool(getattr(data, "captcha_secret_key", None)),
            "letsencrypt_enabled": bool(getattr(data, "letsencrypt_enabled", False)),
            "letsencrypt_email": getattr(data, "letsencrypt_email", None),
            "letsencrypt_challenge": getattr(data, "letsencrypt_challenge", None) or "dns-01",
            "letsencrypt_dns_provider": getattr(data, "letsencrypt_dns_provider", None) or "cloudflare",
            "letsencrypt_dns_resolvers": getattr(data, "letsencrypt_dns_resolvers", None)
            or ["1.1.1.1:53"],
            "letsencrypt_use_staging": bool(getattr(data, "letsencrypt_use_staging", False)),
            "letsencrypt_cloudflare_token_set": bool(
                getattr(data, "letsencrypt_cloudflare_api_token", None)
            ),
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
    captcha_provider: str | None = None
    captcha_site_key: str | None = None
    captcha_secret_key: str | None = None
    letsencrypt_enabled: bool | None = None
    letsencrypt_email: str | None = None
    letsencrypt_challenge: LetsEncryptChallenge | None = None
    letsencrypt_dns_provider: str | None = None
    letsencrypt_dns_resolvers: list[str] | None = None
    letsencrypt_use_staging: bool | None = None
    letsencrypt_cloudflare_api_token: str | None = None
    letsencrypt_rfc2136_nameserver: str | None = None
    letsencrypt_rfc2136_tsig_key: str | None = None
    letsencrypt_rfc2136_tsig_algorithm: TSIGAlgorithm = "hmac-sha256"
    letsencrypt_rfc2136_tsig_secret: SecretStr | None = None
    letsencrypt_dns_delay_seconds: int = Field(default=30, ge=0, le=600, strict=True)

    @field_validator("letsencrypt_rfc2136_tsig_secret", mode="before")
    @classmethod
    def validate_secret_type(cls, value: Any) -> Any:
        if value is not None and not isinstance(value, (str, SecretStr)):
            # FastAPI's default validation errors include the submitted input.
            from fastapi import HTTPException

            raise HTTPException(status_code=422, detail="TSIG secret must be a base64 string")
        return value

    @field_validator("letsencrypt_rfc2136_tsig_algorithm", mode="before")
    @classmethod
    def normalize_tsig_algorithm(cls, value: Any) -> Any:
        return value.lower().rstrip(".") if isinstance(value, str) else value

    @field_validator("letsencrypt_rfc2136_tsig_key")
    @classmethod
    def validate_tsig_key(cls, value: str | None) -> str | None:
        if value is not None and not valid_dns_name(value):
            raise ValueError("TSIG key must be a DNS name")
        return value

    @field_validator("letsencrypt_rfc2136_nameserver")
    @classmethod
    def validate_nameserver(cls, value: str | None) -> str | None:
        if value is None:
            return value
        host = value
        port = None
        if value.startswith("["):
            match = re.fullmatch(r"\[([^]]+)\](?::([0-9]+))?", value)
            if not match:
                raise ValueError("Invalid DNS update endpoint")
            host, port = match.groups()
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                raise ValueError("Invalid DNS update endpoint") from None
        elif ":" in value:
            host, port = value.rsplit(":", 1)
            if ":" in host:
                raise ValueError("IPv6 endpoints must use brackets")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not valid_dns_name(host):
                raise ValueError("Invalid DNS update endpoint") from None
        if port is not None and (not port.isdecimal() or not 1 <= int(port) <= 65535):
            raise ValueError("DNS update port must be between 1 and 65535")
        return value if port is not None else f"{value}:53"


class AuthTestRequest(BaseModel):
    provider: AuthProvider
    config: dict[str, Any] | None = None


class AuthTestResponse(BaseModel):
    ok: bool
    detail: str

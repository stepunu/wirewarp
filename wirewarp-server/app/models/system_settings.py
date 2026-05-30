from typing import Any

from sqlalchemy import Boolean, String, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB

from app.database import Base


class SystemSettings(Base):
    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    public_url: Mapped[str | None] = mapped_column(String, nullable=True)
    internal_url: Mapped[str | None] = mapped_column(String, nullable=True)
    instance_name: Mapped[str] = mapped_column(String, default="WireWarp")
    agent_token_expiry_hours: Mapped[int] = mapped_column(Integer, default=24)

    # DNS sync — see migration 0015. Token now stored Fernet-encrypted; the
    # 0016 migration re-encrypts any pre-existing plaintext value in place.
    dns_provider: Mapped[str | None] = mapped_column(String, nullable=True)
    cloudflare_api_token: Mapped[str | None] = mapped_column(String, nullable=True)

    # Auth provider config — local|oidc|ldap. Provider-specific JSONB blobs
    # carry their settings; secrets inside (client_secret, bind_password) are
    # Fernet-encrypted via app.services.secrets.
    auth_provider: Mapped[str] = mapped_column(
        String, nullable=False, default="local", server_default="local"
    )
    oidc_config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    ldap_config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Anti-bot CAPTCHA provider used by the CrowdSec Traefik plugin.
    # The secret key is Fernet-encrypted by app.services.secrets.
    captcha_provider: Mapped[str | None] = mapped_column(String, nullable=True)
    captcha_site_key: Mapped[str | None] = mapped_column(String, nullable=True)
    captcha_secret_key: Mapped[str | None] = mapped_column(String, nullable=True)

    # Let's Encrypt / ACME settings for managed Traefik certificates. The
    # Cloudflare token is separate from DNS sync and is Fernet-encrypted.
    letsencrypt_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    letsencrypt_email: Mapped[str | None] = mapped_column(String, nullable=True)
    letsencrypt_challenge: Mapped[str] = mapped_column(
        String, nullable=False, default="dns-01", server_default="dns-01"
    )
    letsencrypt_dns_provider: Mapped[str | None] = mapped_column(
        String, nullable=True, default="cloudflare", server_default="cloudflare"
    )
    letsencrypt_dns_resolvers: Mapped[list[str] | None] = mapped_column(
        JSONB, nullable=True, default=lambda: ["1.1.1.1:53"]
    )
    letsencrypt_use_staging: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    letsencrypt_cloudflare_api_token: Mapped[str | None] = mapped_column(String, nullable=True)

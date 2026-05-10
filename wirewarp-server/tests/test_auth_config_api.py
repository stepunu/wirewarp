"""Settings PATCH for auth provider config + secrets-at-rest behavior."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.system_settings import SystemSettings
from app.services.secrets import (
    FERNET_PREFIX,
    decrypt_ldap_config,
    decrypt_oidc_config,
    decrypt_secret,
    looks_like_fernet,
)


@pytest.mark.asyncio
async def test_get_settings_initial_shape(client):
    resp = await client.get("/api/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["auth_provider"] == "local"
    assert body["oidc_secret_set"] is False
    assert body["ldap_secret_set"] is False


@pytest.mark.asyncio
async def test_patch_oidc_config_encrypts_secret(client, db):
    cfg = {
        "issuer": "https://idp.example/realms/main",
        "client_id": "wirewarp",
        "client_secret": "supersecret",
        "redirect_url": "https://wirewarp.example/api/auth/oidc/callback",
        "claim_role_map": {"wg-admins": "admin"},
    }
    resp = await client.patch(
        "/api/settings", json={"auth_provider": "oidc", "oidc_config": cfg}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["auth_provider"] == "oidc"
    assert body["oidc_secret_set"] is True
    assert body["oidc_config"]["issuer"] == cfg["issuer"]
    # Read schema strips the secret entirely.
    assert "client_secret" not in body["oidc_config"]

    row = await db.scalar(select(SystemSettings).where(SystemSettings.id == 1))
    raw = row.oidc_config
    assert raw["issuer"] == cfg["issuer"]
    assert looks_like_fernet(raw["client_secret"])
    assert decrypt_secret(raw["client_secret"]) == "supersecret"


@pytest.mark.asyncio
async def test_patch_ldap_config_encrypts_bind_password(client, db):
    cfg = {
        "url": "ldaps://ldap.example",
        "bind_dn": "cn=svc,dc=example,dc=com",
        "bind_password": "shh-bind",
        "user_dn_template": "uid={username},ou=people,dc=example,dc=com",
        "group_role_map": {"wg-ops": "operator"},
    }
    resp = await client.patch(
        "/api/settings", json={"auth_provider": "ldap", "ldap_config": cfg}
    )
    assert resp.status_code == 200
    assert resp.json()["ldap_secret_set"] is True

    row = await db.scalar(select(SystemSettings).where(SystemSettings.id == 1))
    raw = row.ldap_config
    assert looks_like_fernet(raw["bind_password"])
    assert decrypt_secret(raw["bind_password"]) == "shh-bind"


@pytest.mark.asyncio
async def test_patch_oidc_config_keeps_existing_secret_when_omitted(client, db):
    """The UI sends back the public config without the secret when the
    operator hasn't typed a new one. The server must keep the existing
    encrypted value, not blank it out."""
    first = {
        "issuer": "https://idp.example",
        "client_id": "wirewarp",
        "client_secret": "first-secret",
        "redirect_url": "https://x/cb",
    }
    await client.patch(
        "/api/settings", json={"auth_provider": "oidc", "oidc_config": first}
    )

    # Round 2 — operator only changes the issuer; UI omits client_secret.
    second_payload = {
        "issuer": "https://idp.example/v2",
        "client_id": "wirewarp",
        "redirect_url": "https://x/cb",
    }
    await client.patch("/api/settings", json={"oidc_config": second_payload})

    row = await db.scalar(select(SystemSettings).where(SystemSettings.id == 1))
    assert row.oidc_config["issuer"] == "https://idp.example/v2"
    assert decrypt_secret(row.oidc_config["client_secret"]) == "first-secret"


@pytest.mark.asyncio
async def test_patch_cloudflare_token_encrypts(client, db):
    resp = await client.patch(
        "/api/settings",
        json={"dns_provider": "cloudflare", "cloudflare_api_token": "cf-plain"},
    )
    assert resp.status_code == 200
    assert resp.json()["cloudflare_token_set"] is True

    row = await db.scalar(select(SystemSettings).where(SystemSettings.id == 1))
    assert looks_like_fernet(row.cloudflare_api_token)
    assert decrypt_secret(row.cloudflare_api_token) == "cf-plain"


@pytest.mark.asyncio
async def test_patch_cloudflare_token_idempotent_when_already_encrypted(client, db):
    """Passing back a Fernet ciphertext should not double-wrap it. (The
    UI doesn't do this today, but it's a regression worth pinning.)"""
    await client.patch(
        "/api/settings",
        json={"dns_provider": "cloudflare", "cloudflare_api_token": "raw"},
    )
    row = await db.scalar(select(SystemSettings).where(SystemSettings.id == 1))
    ct = row.cloudflare_api_token
    assert ct.startswith(FERNET_PREFIX)

    await client.patch(
        "/api/settings", json={"cloudflare_api_token": ct}
    )
    row = await db.scalar(select(SystemSettings).where(SystemSettings.id == 1))
    assert decrypt_secret(row.cloudflare_api_token) == "raw"


@pytest.mark.asyncio
async def test_dns_sync_provider_decrypts_token():
    """provider_from_settings must accept either an encrypted or a raw
    legacy token — the latter happens transiently during a partial
    deploy. Both yield a working CloudflareProvider."""
    from app.services.dns_sync import provider_from_settings
    from app.services.secrets import encrypt_secret

    class S:
        dns_provider = "cloudflare"
        cloudflare_api_token = encrypt_secret("real-token")

    p = provider_from_settings(S())
    assert p is not None
    assert p._token == "real-token"  # noqa: SLF001 — internal but cheap to inspect

    class L:
        dns_provider = "cloudflare"
        cloudflare_api_token = "legacy-plain"

    p = provider_from_settings(L())
    assert p._token == "legacy-plain"  # noqa: SLF001

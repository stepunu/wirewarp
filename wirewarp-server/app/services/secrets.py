"""Secrets-at-rest helpers shared across the app.

Two distinct primitives:

* `encrypt_secret` / `decrypt_secret` — Fernet symmetric encryption for
  reversible secrets the server later reads back in plaintext (third-party
  API tokens, OIDC client secrets, LDAP bind passwords). Key is derived
  from `settings.SECRET_KEY` so there's a single secret to rotate.

* `hash_token` / `verify_token` — SHA-256 + constant-time compare for
  lookup-only secrets where we never need the plaintext server-side
  (registration tokens). Cheaper, no key management, and removes the
  decryption code path entirely.

`SECRET_KEY` rotation invalidates every Fernet-encrypted column. The
operator runbook is: stop the container, set the new key, re-enter
encrypted config (Cloudflare token, OIDC/LDAP) via the UI, restart.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings


# Fernet ciphertext envelope always starts with this prefix (base64 of
# version byte 0x80). Used for idempotent migrations: re-running a
# data migration that re-encrypts a column should not double-wrap a
# value that's already a valid ciphertext.
FERNET_PREFIX = "gAAAAA"


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plaintext: str) -> str:
    if plaintext is None:
        raise ValueError("encrypt_secret called with None")
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    if ciphertext is None:
        raise ValueError("decrypt_secret called with None")
    return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")


def looks_like_fernet(value: str | None) -> bool:
    return bool(value) and value.startswith(FERNET_PREFIX)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(presented: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(presented), stored_hash)


# ---- domain-specific helpers ----


async def get_cloudflare_api_token(db: AsyncSession) -> str | None:
    """Load and decrypt the Cloudflare API token from system_settings."""
    from app.models.system_settings import SystemSettings

    row = await db.get(SystemSettings, 1)
    if row is None or not row.cloudflare_api_token:
        return None
    raw = row.cloudflare_api_token
    try:
        return decrypt_secret(raw)
    except InvalidToken:
        # Pre-encryption value still in the column (defensive — the 0016
        # migration converts existing rows). Return as-is so DNS sync
        # doesn't break during a partial deploy.
        return raw


# Keys inside the OIDC / LDAP JSONB blobs that hold secrets and must be
# encrypted on save / decrypted on read. Anything not listed is stored as
# plaintext (issuer URL, group mappings, etc).
OIDC_SECRET_KEYS = ("client_secret",)
LDAP_SECRET_KEYS = ("bind_password",)


def _encrypt_blob(blob: dict[str, Any] | None, secret_keys: tuple[str, ...]) -> dict[str, Any] | None:
    if blob is None:
        return None
    out = dict(blob)
    for k in secret_keys:
        v = out.get(k)
        if v and not looks_like_fernet(v):
            out[k] = encrypt_secret(v)
    return out


def _decrypt_blob(blob: dict[str, Any] | None, secret_keys: tuple[str, ...]) -> dict[str, Any] | None:
    if blob is None:
        return None
    out = dict(blob)
    for k in secret_keys:
        v = out.get(k)
        if looks_like_fernet(v):
            try:
                out[k] = decrypt_secret(v)
            except InvalidToken:
                out[k] = None
    return out


def encrypt_oidc_config(cfg: dict[str, Any] | None) -> dict[str, Any] | None:
    return _encrypt_blob(cfg, OIDC_SECRET_KEYS)


def decrypt_oidc_config(cfg: dict[str, Any] | None) -> dict[str, Any] | None:
    return _decrypt_blob(cfg, OIDC_SECRET_KEYS)


def encrypt_ldap_config(cfg: dict[str, Any] | None) -> dict[str, Any] | None:
    return _encrypt_blob(cfg, LDAP_SECRET_KEYS)


def decrypt_ldap_config(cfg: dict[str, Any] | None) -> dict[str, Any] | None:
    return _decrypt_blob(cfg, LDAP_SECRET_KEYS)

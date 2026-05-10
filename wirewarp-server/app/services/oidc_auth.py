"""OIDC client helpers used by app/routers/oidc.py.

`authlib` carries the heavy lifting (JWKS cache, ID-token verification,
PKCE if needed). This module is a thin layer that:

* Loads OIDC discovery metadata for the configured issuer (cached
  process-locally for 10 minutes).
* Maps ID-token / userinfo claims to a WireWarp role.

OIDC config shape (DB-stored, JSONB on `system_settings.oidc_config`):

    {
      "issuer": "https://idp.example.com/realms/main",
      "client_id": "wirewarp",
      "client_secret": "...",                  # encrypted at rest
      "scopes": ["openid", "email", "profile", "groups"],
      "redirect_url": "https://wirewarp.example.com/api/auth/oidc/callback",
      "username_claim": "preferred_username",  # default
      "email_claim": "email",                  # default
      "role_claim": "groups",                  # default
      "claim_role_map": {"wirewarp-admins": "admin", "wirewarp-ops": "operator"},
      "default_role": "viewer"
    }
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


_DISCOVERY_TTL = 600
_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}


ROLE_PRIORITY = {"admin": 3, "operator": 2, "viewer": 1, "vpn_user": 0}


async def discover(issuer: str) -> dict[str, Any]:
    now = time.time()
    cached = _discovery_cache.get(issuer)
    if cached and cached[0] > now:
        return cached[1]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
    if resp.status_code >= 400:
        raise RuntimeError(
            f"OIDC discovery {url} failed: {resp.status_code} {resp.text[:200]}"
        )
    body = resp.json()
    _discovery_cache[issuer] = (now + _DISCOVERY_TTL, body)
    return body


def _claim_values(claims: dict[str, Any], claim_name: str) -> list[str]:
    val = claims.get(claim_name)
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def map_claims_to_role(
    claims: dict[str, Any],
    role_claim: str,
    mapping: dict[str, str],
    default_role: str,
) -> str:
    values = _claim_values(claims, role_claim)
    chosen: str | None = None
    chosen_priority = -1
    for v in values:
        role = (mapping or {}).get(v)
        if role:
            p = ROLE_PRIORITY.get(role, 0)
            if p > chosen_priority:
                chosen = role
                chosen_priority = p
    return chosen or default_role


def claims_grant_vpn(
    claims: dict[str, Any], role_claim: str, vpn_group: str | None
) -> bool:
    """Determine VPN portal access from a single configured group/claim
    value. The operator picks the value (e.g. an LDAP group CN or an
    OIDC `groups` claim value); membership in that group flips
    `vpn_enabled` on the user row during JIT login. Empty/missing config
    means VPN access is admin-toggled only."""
    if not vpn_group:
        return False
    target = vpn_group.strip()
    if not target:
        return False
    target_lower = target.lower()
    for v in _claim_values(claims, role_claim):
        if v.lower() == target_lower:
            return True
    return False


async def exchange_code_for_userinfo(
    config: dict[str, Any], code: str, state: str, expected_nonce: str
) -> dict[str, Any]:
    """Run the auth-code exchange and return a merged claims dict
    (id_token claims overlaid with /userinfo).

    Raises RuntimeError on any failure: code reuse, signature mismatch,
    nonce mismatch, etc. The caller surfaces those as 400.
    """
    issuer = config["issuer"]
    client_id = config["client_id"]
    client_secret = config.get("client_secret") or ""
    redirect_url = config["redirect_url"]
    meta = await discover(issuer)

    token_endpoint = meta["token_endpoint"]
    userinfo_endpoint = meta.get("userinfo_endpoint")
    jwks_uri = meta["jwks_uri"]

    async with httpx.AsyncClient(timeout=10.0) as http:
        resp = await http.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_url,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Accept": "application/json"},
        )
    if resp.status_code >= 400:
        raise RuntimeError(
            f"OIDC token exchange failed: {resp.status_code} {resp.text[:300]}"
        )
    token_resp = resp.json()
    id_token = token_resp.get("id_token")
    access_token = token_resp.get("access_token")
    if not id_token:
        raise RuntimeError("OIDC token response missing id_token")

    claims = await _verify_id_token(
        id_token,
        jwks_uri=jwks_uri,
        issuer=issuer,
        client_id=client_id,
        expected_nonce=expected_nonce,
    )

    if userinfo_endpoint and access_token:
        try:
            async with httpx.AsyncClient(timeout=10.0) as http:
                ui_resp = await http.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
            if ui_resp.status_code < 400:
                ui = ui_resp.json()
                # /userinfo wins for human-facing fields (email, name) but
                # never overrides 'sub' or signed claims.
                for k, v in ui.items():
                    if k not in {"sub"}:
                        claims.setdefault(k, v)
        except Exception as exc:  # noqa: BLE001
            logger.warning("OIDC userinfo fetch failed: %s", exc)

    return claims


async def _verify_id_token(
    id_token: str, *, jwks_uri: str, issuer: str, client_id: str, expected_nonce: str
) -> dict[str, Any]:
    from authlib.jose import JsonWebKey, JsonWebToken

    async with httpx.AsyncClient(timeout=10.0) as http:
        jwks_resp = await http.get(jwks_uri)
    if jwks_resp.status_code >= 400:
        raise RuntimeError(f"JWKS fetch failed: {jwks_resp.status_code}")
    jwks = JsonWebKey.import_key_set(jwks_resp.json())

    jwt = JsonWebToken(["RS256", "ES256", "RS512", "PS256", "HS256"])
    claims = jwt.decode(
        id_token,
        jwks,
        claims_options={
            "iss": {"essential": True, "value": issuer},
            "aud": {"essential": True, "value": client_id},
            "exp": {"essential": True},
        },
    )
    claims.validate()
    if expected_nonce and claims.get("nonce") != expected_nonce:
        raise RuntimeError("OIDC nonce mismatch")
    return dict(claims)

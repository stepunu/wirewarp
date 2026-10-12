import base64
import binascii
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
import uuid

from fastapi import APIRouter, Depends, HTTPException
from cryptography.fernet import InvalidToken
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import log_auth_event, require_role
from app.database import get_db
from app.models.system_settings import SystemSettings
from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.models.tunnel_client import TunnelClient
from app.realtime.events import emit_edge_changed, emit_security_changed
from app.models.user import User
from app.schemas.acme import (
    DNSChallengeResult,
    DNSChallengeTestRead,
    DNSChallengeTestRequest,
    DNSChallengeTestStarted,
)
from app.schemas.system_settings import (
    AuthTestRequest,
    AuthTestResponse,
    SystemSettingsRead,
    SystemSettingsUpdate,
)
from app.services.ldap_auth import ldap_test_bind
from app.services.oidc_auth import discover
from app.services.secrets import (
    encrypt_ldap_config,
    encrypt_oidc_config,
    encrypt_secret,
    looks_like_fernet,
    get_letsencrypt_rfc2136_tsig_secret,
)
from app.services.agent_commands import send_command
from app.services.edge_ops import redact_edge_desired_state
from app.websocket.hub import manager


router = APIRouter()
dns_test_lock = asyncio.Lock()


LET_ENCRYPT_FIELDS = {
    "letsencrypt_enabled",
    "letsencrypt_email",
    "letsencrypt_challenge",
    "letsencrypt_dns_provider",
    "letsencrypt_dns_resolvers",
    "letsencrypt_use_staging",
    "letsencrypt_cloudflare_api_token",
    "letsencrypt_rfc2136_nameserver",
    "letsencrypt_rfc2136_tsig_key",
    "letsencrypt_rfc2136_tsig_algorithm",
    "letsencrypt_rfc2136_tsig_secret",
    "letsencrypt_dns_delay_seconds",
}


async def _get_or_create(db: AsyncSession) -> SystemSettings:
    row = await db.get(SystemSettings, 1)
    if not row:
        row = SystemSettings(id=1)
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


@router.get("", response_model=SystemSettingsRead)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    return await _get_or_create(db)


def _merge_provider_config(
    existing: dict[str, Any] | None,
    incoming: dict[str, Any] | None,
    secret_keys: tuple[str, ...],
) -> dict[str, Any] | None:
    """Merge a UI-submitted config over what's already in the DB.

    Empty/missing secret fields keep the existing encrypted value (lets
    the UI omit the secret unless the operator wants to rotate it). The
    rest of the config is fully replaced by the incoming dict.
    """
    if incoming is None:
        return existing
    out = dict(incoming)
    if existing:
        for k in secret_keys:
            if not out.get(k) and existing.get(k):
                out[k] = existing[k]
    return out


@router.patch("", response_model=SystemSettingsRead)
async def update_settings(
    body: SystemSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await _get_or_create(db)
    payload = body.model_dump(exclude_unset=True)
    if "letsencrypt_rfc2136_tsig_secret" in payload:
        secret = body.letsencrypt_rfc2136_tsig_secret
        value = secret.get_secret_value() if secret is not None else None
        if value:
            try:
                if not base64.b64decode(value, validate=True):
                    raise ValueError
            except (ValueError, binascii.Error):
                raise HTTPException(status_code=422, detail="TSIG secret must be valid base64") from None
        payload["letsencrypt_rfc2136_tsig_secret"] = encrypt_secret(value) if value else None

    auth_provider_changed = False
    config_changed = False
    letsencrypt_changed = bool(LET_ENCRYPT_FIELDS.intersection(payload))

    for field, val in payload.items():
        if field == "cloudflare_api_token":
            if val is None or val == "":
                row.cloudflare_api_token = None
            elif looks_like_fernet(val):
                row.cloudflare_api_token = val
            else:
                row.cloudflare_api_token = encrypt_secret(val)
        elif field == "captcha_secret_key":
            if val is None or val == "":
                row.captcha_secret_key = None
            elif looks_like_fernet(val):
                row.captcha_secret_key = val
            else:
                row.captcha_secret_key = encrypt_secret(val)
        elif field == "letsencrypt_cloudflare_api_token":
            if val is None or val == "":
                row.letsencrypt_cloudflare_api_token = None
            elif looks_like_fernet(val):
                row.letsencrypt_cloudflare_api_token = val
            else:
                row.letsencrypt_cloudflare_api_token = encrypt_secret(val)
        elif field == "oidc_config":
            merged = _merge_provider_config(row.oidc_config, val, ("client_secret",))
            row.oidc_config = encrypt_oidc_config(merged)
            config_changed = True
        elif field == "ldap_config":
            merged = _merge_provider_config(row.ldap_config, val, ("bind_password",))
            row.ldap_config = encrypt_ldap_config(merged)
            config_changed = True
        elif field == "auth_provider":
            if val != row.auth_provider:
                auth_provider_changed = True
            row.auth_provider = val
        else:
            setattr(row, field, val)

    if letsencrypt_changed:
        from app.models.edge_node import EdgeNode
        from app.services.edge_ops import build_edge_desired_state
        gateways = (await db.scalars(select(TunnelClient.agent_id).join(EdgeNode, EdgeNode.agent_id == TunnelClient.agent_id).where(TunnelClient.is_gateway.is_(True), EdgeNode.edge_mode == "security_edge", EdgeNode.edge_state == "enabled"))).all()
        for agent_id in gateways:
            await build_edge_desired_state(agent_id, db)
    await db.commit()
    await db.refresh(row)

    if auth_provider_changed or config_changed:
        await log_auth_event(
            db,
            "auth.provider_config_change",
            actor_user_id=actor.id,
            details={
                "active_provider": row.auth_provider,
                "oidc_set": bool(row.oidc_config),
                "ldap_set": bool(row.ldap_config),
            },
        )

    if letsencrypt_changed:
        from app.services.edge_ops import dispatch_all_server_edges

        await dispatch_all_server_edges(db, actor_user_id=actor.id)
        emit_edge_changed()
        emit_security_changed()

    return row


@router.post("/acme/test", response_model=DNSChallengeTestStarted)
async def test_dns_challenge(
    body: DNSChallengeTestRequest,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await _get_or_create(db)
    if row.letsencrypt_challenge != "dns-01" or row.letsencrypt_dns_provider != "rfc2136":
        raise HTTPException(status_code=409, detail="Save Knot / RFC2136 DNS-01 settings before testing")
    if row.letsencrypt_dns_delay_seconds > 90:
        raise HTTPException(status_code=409, detail="The DNS test supports delays up to 90 seconds. Save a shorter delay before testing")
    try:
        secret = await get_letsencrypt_rfc2136_tsig_secret(db)
    except InvalidToken:
        raise HTTPException(status_code=409, detail="The saved TSIG secret could not be decrypted. Re-enter and save it before testing") from None
    if not row.letsencrypt_rfc2136_nameserver or not row.letsencrypt_rfc2136_tsig_key or not secret:
        raise HTTPException(status_code=409, detail="Save the update server, TSIG key, and TSIG secret before testing")
    agent = await db.get(Agent, body.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Node not found")
    gateway = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == body.agent_id))
    if agent.type != "server" and not (gateway and gateway.is_gateway):
        raise HTTPException(status_code=409, detail="Select a server or gateway node for the DNS test")
    if not manager.is_connected(str(agent.id)):
        raise HTTPException(status_code=409, detail="Selected node is disconnected")
    params = {
        "domain": body.domain,
        "dns_delay_seconds": row.letsencrypt_dns_delay_seconds,
        "credentials": {
            "rfc2136_nameserver": row.letsencrypt_rfc2136_nameserver,
            "rfc2136_tsig_key": row.letsencrypt_rfc2136_tsig_key,
            "rfc2136_tsig_algorithm": row.letsencrypt_rfc2136_tsig_algorithm,
            "rfc2136_tsig_secret": secret,
        },
    }
    # Serialize admission in this single-process control server. A recent
    # unacknowledged command prevents overlapping tests at the same owner.
    async with dns_test_lock:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=150)
        recent = (await db.scalars(select(CommandLog).where(
            CommandLog.command_type == "acme_dns_test",
            CommandLog.success.is_(None),
            CommandLog.executed_at >= cutoff,
        ))).all()
        if any((log.params or {}).get("domain") == body.domain for log in recent):
            raise HTTPException(status_code=409, detail="A DNS test for this domain is already running")
        sent, command_id = await send_command(
            agent_id=str(agent.id), command_type="acme_dns_test", params=params,
            db=db, actor_user_id=actor.id, log_params=redact_edge_desired_state(params),
        )
    if not sent:
        log = await db.get(CommandLog, uuid.UUID(command_id))
        log.success = False
        log.output = "Node disconnected before the DNS test was sent"
        await db.commit()
        raise HTTPException(status_code=409, detail=log.output)
    return DNSChallengeTestStarted(command_id=command_id)


@router.get("/acme/test/{command_id}", response_model=DNSChallengeTestRead)
async def dns_challenge_test_result(
    command_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    log = await db.get(CommandLog, command_id)
    if log is None or log.command_type != "acme_dns_test":
        raise HTTPException(status_code=404, detail="DNS test not found")
    if log.success is None:
        started_at = log.executed_at
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        if started_at < datetime.now(timezone.utc) - timedelta(seconds=150):
            return DNSChallengeTestRead(
                status="failure", command_id=str(log.id),
                result=DNSChallengeResult(
                    ok=False, stage="timeout",
                    detail="No final result from the node. Cleanup is unconfirmed. Check the TXT record before retrying.",
                    record_name="_acme-challenge." + (log.params or {}).get("domain", ""),
                    cleanup_ok=False, authoritative_results=[],
                ),
            )
        return DNSChallengeTestRead(status="pending", command_id=str(log.id))
    try:
        result = DNSChallengeResult.model_validate_json(log.output or "")
    except ValidationError:
        result = DNSChallengeResult(
            ok=False, stage="agent", detail=log.output or "Node returned no DNS test result",
            record_name="_acme-challenge." + (log.params or {}).get("domain", ""),
            cleanup_ok=False, authoritative_results=[],
        )
    status = "success" if log.success and result.ok and result.cleanup_ok else "failure"
    return DNSChallengeTestRead(status=status, command_id=str(log.id), result=result)


@router.post("/auth/test", response_model=AuthTestResponse)
async def test_auth_provider(
    body: AuthTestRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    """Probe the configured (or supplied) IdP. Used by the Settings UI's
    'Test connection' button. For OIDC: fetch the discovery document.
    For LDAP: do a bind probe (anonymous or service-account)."""
    row = await _get_or_create(db)
    if body.provider == "oidc":
        cfg = body.config or row.oidc_config or {}
        issuer = cfg.get("issuer")
        if not issuer:
            return AuthTestResponse(ok=False, detail="missing issuer")
        try:
            meta = await discover(issuer)
            return AuthTestResponse(
                ok=True,
                detail=f"issuer ok — token_endpoint={meta.get('token_endpoint','?')}",
            )
        except Exception as exc:  # noqa: BLE001
            return AuthTestResponse(ok=False, detail=str(exc))
    if body.provider == "ldap":
        cfg = body.config or row.ldap_config or {}
        if not cfg.get("url"):
            return AuthTestResponse(ok=False, detail="missing url")
        ok, detail = await ldap_test_bind(cfg)
        return AuthTestResponse(ok=ok, detail=detail)
    raise HTTPException(status_code=400, detail="Unknown provider")

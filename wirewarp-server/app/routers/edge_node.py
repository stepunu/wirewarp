from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.edge_access_event import EdgeAccessEvent
from app.models.edge_cache_snapshot import EdgeCacheSnapshot
from app.models.edge_config_version import EdgeConfigVersion
from app.models.edge_fragment import EdgeFragment
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_profile import EdgeProfile
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.models.user import User
from app.realtime.events import emit_edge_changed
from app.schemas.edge import (
    EdgeAccessEventList,
    EdgeAccessEventRead,
    EdgeCachePatch,
    EdgeCachePurgeRequest,
    EdgeCacheRead,
    EdgeConfigVersionRead,
    EdgeDesiredStateResponse,
    EdgeFragmentCreate,
    EdgeFragmentRead,
    EdgeRenderedRead,
    EdgeUpstreamPoolRead,
    EdgeUpstreamPoolUpsert,
)
from app.schemas.security import TraefikImportRequest
from app.services.edge_ops import (
    dispatch_edge_desired_state,
    edge_feature_disabled_detail,
    edge_unavailable_reason,
)
from app.services.agent_commands import send_command
from app.services.edge_resources import (
    apply_policy_to_edge_config,
    get_profile_by_id_or_slug,
    route_edge_config,
    slugify,
)
from app.services.edge_runtime import desired_state_snapshot, rendered_edge_config, stable_json

router = APIRouter()


async def _server_for_agent(agent_id: uuid.UUID, db: AsyncSession) -> TunnelServer:
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    if server is None:
        raise HTTPException(status_code=404, detail="Server node not found")
    return server


def _ensure_enabled(server: TunnelServer) -> None:
    if edge_unavailable_reason(server):
        raise HTTPException(status_code=409, detail=edge_feature_disabled_detail(server))


def _cache_backend_read(snapshot: EdgeCacheSnapshot | None) -> dict | None:
    if snapshot is None:
        return None
    return {
        "backend": snapshot.backend,
        "installed": snapshot.installed,
        "running": snapshot.running,
        "phase": snapshot.phase,
        "version": snapshot.version,
        "cache_path": snapshot.cache_path,
        "current_size_bytes": snapshot.current_size_bytes,
        "max_size_bytes": snapshot.max_size_bytes,
        "last_test_status": snapshot.last_test_status,
        "last_error": snapshot.last_error,
    }


def _upstream_pool_read(row: EdgeUpstreamPool) -> EdgeUpstreamPoolRead:
    return EdgeUpstreamPoolRead(
        id=row.id,
        agent_id=row.agent_id,
        name=row.name,
        description=row.description,
        servers=list(row.servers or []),
        health_check=dict(row.health_check or {}),
        policy=dict(row.policy_json or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _node_cache_policy(agent_id: uuid.UUID, db: AsyncSession) -> dict:
    row = await db.get(EdgeNodePolicy, agent_id)
    policy = dict(row.policy_json or {}) if row is not None else {}
    cache = policy.get("cache")
    return cache if isinstance(cache, dict) else {"mode": "off"}


async def _cache_read(agent_id: uuid.UUID, db: AsyncSession) -> EdgeCacheRead:
    snapshot = await db.scalar(
        select(EdgeCacheSnapshot).where(
            EdgeCacheSnapshot.agent_id == agent_id,
            EdgeCacheSnapshot.backend == "nginx_proxy_cache",
        )
    )
    policy = await _node_cache_policy(agent_id, db)
    real_cache = policy.get("mode") not in {"off", "headers_only"}
    available = policy.get("mode") == "headers_only" or not real_cache
    reason = None
    if real_cache:
        available = bool(snapshot and snapshot.installed and snapshot.running and snapshot.phase == "healthy")
        reason = None if available else "nginx_cache_unavailable"
    return EdgeCacheRead(
        available=available,
        reason=reason,
        backend=_cache_backend_read(snapshot),
        policy=policy,
    )


@router.get("/{agent_id}/edge/access-events", response_model=EdgeAccessEventList)
async def node_access_events(
    agent_id: uuid.UUID,
    route_id: uuid.UUID | None = None,
    host: str | None = None,
    status: int | None = None,
    action: str | None = None,
    client_ip: str | None = None,
    country: str | None = None,
    method: str | None = None,
    path_prefix: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    q = select(EdgeAccessEvent).where(EdgeAccessEvent.agent_id == agent_id)
    if route_id:
        q = q.where(EdgeAccessEvent.route_id == route_id)
    if host:
        q = q.where(EdgeAccessEvent.host == host)
    if status is not None:
        q = q.where(EdgeAccessEvent.status_code == status)
    if action:
        q = q.where(EdgeAccessEvent.action == action)
    if client_ip:
        q = q.where(EdgeAccessEvent.client_ip == client_ip)
    if country:
        q = q.where(EdgeAccessEvent.client_country == country.upper())
    if method:
        q = q.where(EdgeAccessEvent.method == method.upper())
    if path_prefix:
        q = q.where(EdgeAccessEvent.path.startswith(path_prefix))
    if since:
        q = q.where(EdgeAccessEvent.occurred_at >= since)
    if until:
        q = q.where(EdgeAccessEvent.occurred_at <= until)
    rows = (
        await db.execute(q.order_by(EdgeAccessEvent.occurred_at.desc(), EdgeAccessEvent.id.desc()).limit(limit + 1))
    ).scalars().all()
    next_cursor = rows[-1].id if len(rows) > limit else None
    return EdgeAccessEventList(items=[EdgeAccessEventRead.model_validate(row) for row in rows[:limit]], next_cursor=next_cursor)


@router.get("/{agent_id}/edge/cache", response_model=EdgeCacheRead)
async def get_node_cache(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    return await _cache_read(agent_id, db)


@router.patch("/{agent_id}/edge/cache", response_model=EdgeCacheRead)
async def patch_node_cache(
    agent_id: uuid.UUID,
    body: EdgeCachePatch,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    if body.mode not in {"off", "headers_only"}:
        snapshot = await db.scalar(select(EdgeCacheSnapshot).where(EdgeCacheSnapshot.agent_id == agent_id))
        if not (snapshot and snapshot.installed and snapshot.running and snapshot.phase == "healthy"):
            raise HTTPException(status_code=409, detail={"code": "edge_cache_unavailable", "reason": "nginx_cache_unavailable"})
    policy = await db.get(EdgeNodePolicy, agent_id)
    if policy is None:
        policy = EdgeNodePolicy(agent_id=agent_id)
        db.add(policy)
    node_policy = dict(policy.policy_json or {})
    node_policy["cache"] = body.model_dump(exclude_none=True)
    policy.policy_json = node_policy
    await db.commit()
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return await _cache_read(agent_id, db)


@router.post("/{agent_id}/edge/cache/purge")
async def purge_node_cache(
    agent_id: uuid.UUID,
    body: EdgeCachePurgeRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    snapshot = await db.scalar(select(EdgeCacheSnapshot).where(EdgeCacheSnapshot.agent_id == agent_id))
    if not (snapshot and snapshot.installed and snapshot.running and snapshot.phase == "healthy"):
        raise HTTPException(status_code=409, detail={"code": "edge_cache_unavailable", "reason": "purge_requires_healthy_backend"})
    sent, command_id = await send_command(
        agent_id=str(agent_id),
        command_type="edge_cache_purge",
        params=body.model_dump(exclude_none=True),
        db=db,
    )
    return {"status": "queued", "scope": body.scope, "sent": sent, "command_id": command_id}


@router.post("/{agent_id}/edge/cache/install", status_code=202)
@router.post("/{agent_id}/edge/cache/reconcile", status_code=202)
async def reconcile_node_cache(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    sent, command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    return {"sent": sent, "command_id": command_id}


@router.get("/{agent_id}/edge/cache/stats")
async def cache_stats(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    cache = await _cache_read(agent_id, db)
    return {"backend": cache.backend, "available": cache.available, "policy": cache.policy}


@router.post("/{agent_id}/edge/cache/test")
async def cache_test(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    cache = await _cache_read(agent_id, db)
    if not cache.available:
        raise HTTPException(status_code=409, detail={"code": "edge_cache_unavailable", "reason": cache.reason})
    return {"status": "headers_only" if cache.policy.get("mode") == "headers_only" else "queued"}


@router.get("/{agent_id}/edge/upstream-pools", response_model=list[EdgeUpstreamPoolRead])
async def list_node_upstream_pools(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    rows = (
        await db.execute(
            select(EdgeUpstreamPool)
            .where(EdgeUpstreamPool.agent_id == agent_id)
            .order_by(EdgeUpstreamPool.name)
        )
    ).scalars().all()
    return [_upstream_pool_read(row) for row in rows]


@router.post("/{agent_id}/edge/upstream-pools", response_model=EdgeUpstreamPoolRead, status_code=201)
async def create_node_upstream_pool(
    agent_id: uuid.UUID,
    body: EdgeUpstreamPoolUpsert,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    existing = await db.scalar(
        select(EdgeUpstreamPool).where(
            EdgeUpstreamPool.agent_id == agent_id,
            EdgeUpstreamPool.name == body.name,
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail={"code": "edge_upstream_pool_exists", "field": "name"})
    row = EdgeUpstreamPool(
        id=uuid.uuid4(),
        agent_id=agent_id,
        name=body.name,
        description=body.description,
        servers=body.servers,
        health_check=body.health_check,
        policy_json=body.policy,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return _upstream_pool_read(row)


@router.get("/{agent_id}/edge/rendered", response_model=EdgeRenderedRead)
async def get_rendered(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    rendered, _version = await rendered_edge_config(agent_id, db)
    return EdgeRenderedRead(**rendered)


@router.post("/{agent_id}/edge/validate")
async def validate_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    return {"valid": True, "errors": [], "warnings": []}


@router.get("/{agent_id}/edge/versions", response_model=list[EdgeConfigVersionRead])
async def list_versions(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    rows = (
        await db.execute(
            select(EdgeConfigVersion)
            .where(EdgeConfigVersion.agent_id == agent_id)
            .order_by(EdgeConfigVersion.created_at.desc())
        )
    ).scalars().all()
    return [EdgeConfigVersionRead.model_validate(row) for row in rows]


@router.post("/{agent_id}/edge/versions/{version_id}/rollback")
async def rollback_version(
    agent_id: uuid.UUID,
    version_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    version = await db.get(EdgeConfigVersion, version_id)
    if version is None or version.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Config version not found")
    sent, command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    return {"sent": sent, "command_id": command_id, "version_id": version_id}


@router.get("/{agent_id}/edge/fragments", response_model=list[EdgeFragmentRead])
async def list_fragments(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    rows = (
        await db.execute(select(EdgeFragment).where(EdgeFragment.agent_id == agent_id).order_by(EdgeFragment.name))
    ).scalars().all()
    return [EdgeFragmentRead.model_validate(row) for row in rows]


@router.post("/{agent_id}/edge/fragments", response_model=EdgeFragmentRead, status_code=201)
async def create_fragment(
    agent_id: uuid.UUID,
    body: EdgeFragmentCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    state = "valid" if isinstance(body.content, dict) and body.fragment_type in {"middleware", "service", "router", "tls", "transport"} else "invalid"
    row = EdgeFragment(
        id=uuid.uuid4(),
        agent_id=agent_id,
        route_id=body.route_id,
        name=body.name,
        fragment_type=body.fragment_type,
        content=body.content,
        enabled=body.enabled,
        validation_state=state,
        last_error=None if state == "valid" else "Unsupported fragment type or content.",
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return EdgeFragmentRead.model_validate(row)


async def _apply_desired_state_body(
    agent_id: uuid.UUID,
    body: dict,
    db: AsyncSession,
) -> None:
    profiles = body.get("profiles")
    if isinstance(profiles, list):
        for item in profiles:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("slug") or "Edge profile")
            slug = str(item.get("slug") or slugify(name))
            profile = await get_profile_by_id_or_slug(db, item.get("id") or slug)
            if profile is None:
                profile = EdgeProfile(id=uuid.uuid4(), name=name, slug=slug)
                db.add(profile)
            profile.name = name
            profile.slug = slug
            profile.description = item.get("description")
            profile.scope = str(item.get("scope") or "global")
            profile.agent_id = uuid.UUID(str(item["agent_id"])) if item.get("agent_id") else None
            profile.policy_json = item.get("policy") if isinstance(item.get("policy"), dict) else {}

    server = await _server_for_agent(agent_id, db)
    att_ids = (
        await db.execute(
            select(TunnelClientAttachment.id).where(TunnelClientAttachment.tunnel_server_id == server.id)
        )
    ).scalars().all()
    routes = body.get("routes")
    if not isinstance(routes, list):
        return
    for item in routes:
        if not isinstance(item, dict):
            continue
        route = None
        if item.get("id"):
            try:
                route_id = uuid.UUID(str(item["id"]))
            except ValueError:
                route_id = None
            if route_id is not None:
                route = await db.get(PortForward, route_id)
                if route is not None and route.attachment_id not in att_ids:
                    raise HTTPException(status_code=400, detail={"code": "route_node_mismatch", "field": "id"})
        if route is None and item.get("domain") and att_ids:
            route = await db.scalar(
                select(PortForward).where(
                    PortForward.attachment_id.in_(att_ids),
                    PortForward.service_kind == "http",
                    PortForward.domain == str(item["domain"]),
                )
            )
        if route is None:
            attachment_id = item.get("attachment_id")
            if not attachment_id:
                continue
            route = PortForward(
                id=uuid.uuid4(),
                attachment_id=uuid.UUID(str(attachment_id)),
                protocol="tcp",
                public_port=int(item.get("public_port") or 443),
                destination_ip=str(item.get("destination_ip") or "127.0.0.1"),
                destination_port=int(item.get("destination_port") or 80),
                active=bool(item.get("enabled", True)),
                service_kind="http",
                domain=item.get("domain"),
                description=item.get("description"),
            )
            db.add(route)
            await db.flush()
        if "domain" in item:
            route.domain = item.get("domain")
        if "enabled" in item:
            route.active = bool(item.get("enabled"))
        if "destination_ip" in item and item.get("destination_ip") is not None:
            route.destination_ip = str(item["destination_ip"])
        if "destination_port" in item and item.get("destination_port") is not None:
            route.destination_port = int(item["destination_port"])
        if "description" in item:
            route.description = item.get("description")
        ec = await route_edge_config(db, route)
        if item.get("profile_id"):
            profile = await db.get(EdgeProfile, uuid.UUID(str(item["profile_id"])))
            if profile is None:
                raise HTTPException(status_code=404, detail="Edge profile not found")
            ec.profile_id = profile.id
        elif item.get("profile"):
            profile = await get_profile_by_id_or_slug(db, str(item["profile"]))
            if profile is None:
                raise HTTPException(status_code=404, detail="Edge profile not found")
            ec.profile_id = profile.id
        if "priority" in item and item.get("priority") is not None:
            ec.priority = int(item["priority"])
        if "upstream_scheme" in item and item.get("upstream_scheme"):
            ec.upstream_scheme = str(item["upstream_scheme"])
        if "upstream_insecure_skip_verify" in item:
            ec.upstream_insecure_skip_verify = bool(item.get("upstream_insecure_skip_verify"))
        if isinstance(item.get("policy"), dict):
            apply_policy_to_edge_config(ec, item["policy"])


@router.get("/{agent_id}/edge/desired-state", response_model=EdgeDesiredStateResponse)
async def get_desired_state(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    snapshot = await desired_state_snapshot(agent_id, db)
    return EdgeDesiredStateResponse(**snapshot)


@router.put("/{agent_id}/edge/desired-state", response_model=EdgeDesiredStateResponse)
async def put_desired_state(
    agent_id: uuid.UUID,
    body: dict,
    dry_run: bool = False,
    apply: bool = True,
    prune: bool = False,
    return_diff: bool = False,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    before = await desired_state_snapshot(agent_id, db)
    diff = None
    if return_diff:
        diff = stable_json({"before": before, "after": body, "prune": prune})
    if dry_run or not apply:
        return EdgeDesiredStateResponse(
            dry_run=dry_run,
            changed=stable_json(before) != stable_json(body),
            diff=diff,
            **before,
        )
    await _apply_desired_state_body(agent_id, body, db)
    await db.commit()
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=_.id)
    emit_edge_changed()
    after = await desired_state_snapshot(agent_id, db)
    return EdgeDesiredStateResponse(
        dry_run=False,
        changed=stable_json(before) != stable_json(after),
        diff=diff,
        reconcile_sent=True,
        **after,
    )


@router.post("/{agent_id}/edge/import/traefik/preview")
async def preview_import(
    agent_id: uuid.UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_ops_role),
):
    from app.routers.security import preview_traefik_routes

    server = await _server_for_agent(agent_id, db)
    body = dict(body)
    body.setdefault("server_id", str(server.id))
    return await preview_traefik_routes(TraefikImportRequest(**body), db, user)


@router.post("/{agent_id}/edge/import/traefik/apply")
@router.post("/{agent_id}/edge/import/traefik/upsert")
async def apply_import(
    agent_id: uuid.UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    from app.routers.security import import_traefik_routes

    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    body = dict(body)
    body.setdefault("server_id", str(server.id))
    return await import_traefik_routes(TraefikImportRequest(**body), db, user)

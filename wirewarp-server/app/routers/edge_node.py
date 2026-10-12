from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.edge_access_event import EdgeAccessEvent
from app.models.edge_cache_snapshot import EdgeCacheSnapshot
from app.models.edge_config_version import EdgeConfigVersion
from app.models.edge_fragment import EdgeFragment
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_profile import EdgeProfile
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.edge_node import EdgeNode
from app.models.http_route import HTTPRoute
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
    NodeTraefikImportRequest,
)
from app.services.edge_ops import (
    dispatch_edge_desired_state,
    edge_feature_disabled_detail,
    edge_unavailable_reason,
    set_component_desired,
    redact_edge_desired_state,
)
from app.services.agent_commands import send_command
from app.services.edge_ownership import get_edge_owner, is_gateway_edge
from app.services.edge_resources import (
    get_profile_by_id_or_slug,
    slugify,
)
from app.services.edge_cache_ops import nginx_cache_backend_available
from app.services.edge_runtime import desired_state_snapshot, rendered_edge_config, stable_json
from app.services.edge_render import validate_edge_configuration

router = APIRouter()


async def _server_for_agent(agent_id: uuid.UUID, db: AsyncSession) -> EdgeNode:
    return await get_edge_owner(db, agent_id)


def _ensure_enabled(server: EdgeNode) -> None:
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
        available = await nginx_cache_backend_available(agent_id, db)
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
    if body.mode not in {"off", "headers_only", "proxy_cache"}:
        raise HTTPException(status_code=400, detail={"code": "invalid_edge_cache_mode", "field": "mode"})
    policy = await db.get(EdgeNodePolicy, agent_id)
    if policy is None:
        policy = EdgeNodePolicy(agent_id=agent_id)
        db.add(policy)
    node_policy = dict(policy.policy_json or {})
    node_policy["cache"] = body.model_dump(exclude_none=True)
    policy.policy_json = node_policy
    await set_component_desired(
        agent_id,
        db,
        {"nginx_cache": "enabled" if body.mode == "proxy_cache" else "disabled"},
    )
    await validate_edge_configuration(agent_id, db)
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
    if cache.policy.get("mode") == "headers_only":
        return {"status": "headers_only"}
    sent, command_id = await send_command(
        agent_id=str(agent_id),
        command_type="edge_cache_test",
        params={},
        db=db,
    )
    return {"status": "queued", "sent": sent, "command_id": command_id}


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
    await validate_edge_configuration(agent_id, db)
    await db.commit()
    await db.refresh(row)
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return _upstream_pool_read(row)


@router.get("/{agent_id}/edge/rendered", response_model=EdgeRenderedRead)
async def get_rendered(
    agent_id: uuid.UUID,
    include_sensitive: bool = False,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    rendered, _version = await rendered_edge_config(agent_id, db)
    if include_sensitive and _.role != "admin":
        raise HTTPException(403, "Sensitive configuration export requires an administrator")
    return EdgeRenderedRead(**(rendered if include_sensitive else redact_edge_desired_state(rendered)))


@router.post("/{agent_id}/edge/validate")
async def validate_node_edge(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    await validate_edge_configuration(agent_id, db)
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
    from app.services.edge_config_snapshots import restore_edge_source
    await restore_edge_source(version, db)
    await db.commit()
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
    if await is_gateway_edge(db, agent_id) and body.fragment_type == "router":
        raise HTTPException(status_code=409, detail={"code": "gateway_router_fragment_unavailable", "detail": "Use managed routes to enforce LAN and public visibility on gateway edges."})
    if body.route_id is not None:
        route = await db.get(HTTPRoute, body.route_id)
        if route is None or route.agent_id != agent_id:
            raise HTTPException(status_code=400, detail={"code": "route_node_mismatch", "field": "route_id"})
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
    await validate_edge_configuration(agent_id, db)
    await db.commit()
    await db.refresh(row)
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return EdgeFragmentRead.model_validate(row)


async def _apply_desired_state_body(
    agent_id: uuid.UUID,
    body: dict,
    db: AsyncSession,
    *,
    prune: bool = False,
) -> None:
    await _server_for_agent(agent_id, db)
    gateway = await is_gateway_edge(db, agent_id)
    profiles = body.get("profiles")
    if profiles is not None and not isinstance(profiles, list):
        raise HTTPException(422, "Profiles must be a list")
    if isinstance(profiles, list):
        for item in profiles:
            if not isinstance(item, dict):
                raise HTTPException(422, "Each profile must be an object")
            name = str(item.get("name") or item.get("slug") or "Edge profile")
            slug = str(item.get("slug") or slugify(name))
            profile = await get_profile_by_id_or_slug(db, item.get("id") or slug)
            if profile is not None and profile.agent_id != agent_id:
                if profile.name != name or profile.slug != slug or (profile.policy_json or {}) != item.get("policy", {}):
                    raise HTTPException(409, "Edit shared or other-node profiles through the profile API")
                continue
            if item.get("agent_id") not in {None, str(agent_id)} or item.get("scope", "node") != "node":
                raise HTTPException(422, "Imported profiles must belong to the node in the request URL")
            if profile is None:
                try:
                    profile_id = uuid.UUID(str(item["id"])) if item.get("id") else uuid.uuid4()
                except ValueError:
                    raise HTTPException(422, "Invalid profile ID") from None
                profile = EdgeProfile(id=profile_id, name=name, slug=slug)
                db.add(profile)
            profile.name = name
            profile.slug = slug
            profile.description = item.get("description")
            profile.scope = "node"
            profile.agent_id = agent_id
            profile.policy_json = item.get("policy") if isinstance(item.get("policy"), dict) else {}
            from app.services.edge_render import validate_render_policy
            try:
                validate_render_policy(profile.policy_json)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc

    routes = body.get("routes")
    if routes is None:
        routes = []
    if not isinstance(routes, list):
        raise HTTPException(status_code=422, detail="Routes must be a list of managed route objects")
    from app.routers.nodes import _upsert_node_route
    from app.schemas.edge import EdgeRouteUpsert
    from pydantic import ValidationError
    for item in routes:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="Each route must be a managed route object")
        route = None
        new_route_id = None
        if item.get("id"):
            try:
                route_id = uuid.UUID(str(item["id"]))
            except ValueError:
                raise HTTPException(status_code=422, detail="Invalid route ID") from None
            route = await db.get(HTTPRoute, route_id)
            if route is None:
                new_route_id = route_id
            elif route.agent_id != agent_id:
                raise HTTPException(status_code=400, detail={"code": "route_node_mismatch", "field": "id"})
        if route is None and item.get("domain"):
            route = await db.scalar(
                select(HTTPRoute).where(
                    HTTPRoute.agent_id == agent_id,
                    HTTPRoute.domain == str(item["domain"]),
                )
            )
        if route is not None and item.get("domain") and item["domain"] != route.domain:
            raise HTTPException(status_code=400, detail={"code": "route_domain_mismatch", "field": "domain"})
        if new_route_id and route is not None:
            raise HTTPException(409, "The imported route ID conflicts with an existing hostname")
        try:
            upsert = EdgeRouteUpsert.model_validate(item)
        except ValidationError:
            raise HTTPException(status_code=422, detail="Invalid managed route configuration") from None
        await _upsert_node_route(agent_id, route.domain if route else item.get("domain"), upsert, db, actor=None, commit=False, route_id=route.id if route else None, validate_config=False, new_route_id=new_route_id)
    from app.schemas.edge import EdgeFragmentCreate, EdgePathRuleCreate, EdgeNodePolicyUpdate
    from app.routers.edge import _fragment_error
    for key, model, schema in (
        ("upstream_pools", EdgeUpstreamPool, EdgeUpstreamPoolUpsert),
        ("path_rules", EdgePathRule, EdgePathRuleCreate),
        ("fragments", EdgeFragment, EdgeFragmentCreate),
    ):
        if key not in body:
            continue
        if not isinstance(body[key], list):
            raise HTTPException(422, f"{key} must be a list")
        wanted = set()
        for item in body[key]:
            if not isinstance(item, dict):
                raise HTTPException(422, f"Each {key} item must be an object")
            try:
                parsed = schema.model_validate(item)
                resource_id = uuid.UUID(str(item["id"])) if item.get("id") else uuid.uuid4()
            except (ValueError, ValidationError):
                raise HTTPException(422, f"Invalid {key} resource") from None
            row = await db.get(model, resource_id)
            if row is not None:
                if model is EdgePathRule:
                    owner = await db.get(HTTPRoute, row.route_id)
                    owns = owner is not None and owner.agent_id == agent_id
                else:
                    owns = row.agent_id == agent_id
                if not owns:
                    raise HTTPException(409, "Imported resource belongs to another node")
            route_id = None
            if model is EdgePathRule or model is EdgeFragment and parsed.route_id:
                try:
                    route_id = uuid.UUID(str(item.get("route_id")))
                except ValueError:
                    raise HTTPException(422, "A valid route_id is required") from None
                route = await db.get(HTTPRoute, route_id)
                if route is None or route.agent_id != agent_id:
                    raise HTTPException(409, "Imported resource route belongs to another node")
            if model is EdgeFragment:
                error = await _fragment_error(db, agent_id, parsed.fragment_type, parsed.route_id)
                if error:
                    raise HTTPException(409, error)
            if row is None:
                row = model(id=resource_id)
                if model is not EdgePathRule:
                    row.agent_id = agent_id
                db.add(row)
            for field, value in parsed.model_dump().items():
                if field == "policy":
                    row.policy_json = value
                else:
                    setattr(row, field, value)
            if model is EdgePathRule:
                row.route_id = route_id
            if model is EdgeFragment:
                row.validation_state = "valid"
                row.last_error = None
            wanted.add(resource_id)
        await db.flush()
        if prune:
            selector = model.route_id.in_(select(HTTPRoute.id).where(HTTPRoute.agent_id == agent_id)) if model is EdgePathRule else model.agent_id == agent_id
            for row in (await db.scalars(select(model).where(selector))).all():
                if row.id not in wanted:
                    await db.delete(row)
    if "node_policy" in body and body["node_policy"] is None:
        policy = await db.get(EdgeNodePolicy, agent_id)
        if policy is not None:
            await db.delete(policy)
    elif "node_policy" in body:
        try:
            update = EdgeNodePolicyUpdate.model_validate(body["node_policy"])
        except ValidationError:
            raise HTTPException(422, "Invalid node policy") from None
        policy = await db.get(EdgeNodePolicy, agent_id)
        if policy is None:
            policy = EdgeNodePolicy(agent_id=agent_id)
            db.add(policy)
        for field, value in update.model_dump(exclude_unset=True).items():
            setattr(policy, "policy_json" if field == "policy" else field, value)
    if prune and "routes" in body:
        ids = {str(item["id"]) for item in routes if item.get("id")}
        domains = {str(item.get("domain", "")).lower().rstrip(".") for item in routes}
        from app.services.edge_migration import ensure_route_not_referenced
        for row in (await db.scalars(select(HTTPRoute).where(HTTPRoute.agent_id == agent_id))).all():
            if str(row.id) not in ids and row.domain.lower().rstrip(".") not in domains:
                await ensure_route_not_referenced(db, row.id)
                await db.delete(row)


@router.get("/{agent_id}/edge/desired-state", response_model=EdgeDesiredStateResponse)
async def get_desired_state(
    agent_id: uuid.UUID,
    include_sensitive: bool = False,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    await _server_for_agent(agent_id, db)
    snapshot = await desired_state_snapshot(agent_id, db)
    redacted = redact_edge_desired_state(snapshot)
    contains_credentials = redacted != snapshot
    if include_sensitive and _.role != "admin":
        raise HTTPException(403, "Sensitive configuration export requires an administrator")
    return EdgeDesiredStateResponse(contains_credentials=contains_credentials,
                                   sensitive_values_redacted=contains_credentials and not include_sensitive,
                                   **(snapshot if include_sensitive else redacted))


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
    def has_redacted(value):
        if isinstance(value, dict):
            return any(has_redacted(item) for item in value.values())
        if isinstance(value, list):
            return any(has_redacted(item) for item in value)
        return value == "[redacted]"
    if has_redacted(body):
        raise HTTPException(422, "A masked configuration cannot be imported. Use an administrator sensitive export or supply the credentials")
    before = await desired_state_snapshot(agent_id, db)
    diff = None
    if return_diff:
        diff = stable_json(redact_edge_desired_state({"before": before, "after": body, "prune": prune}))
    savepoint = await db.begin_nested()
    try:
        await _apply_desired_state_body(agent_id, body, db, prune=prune)
        await validate_edge_configuration(agent_id, db)
        after = await desired_state_snapshot(agent_id, db)
    except (HTTPException, IntegrityError) as exc:
        await savepoint.rollback()
        if dry_run or not apply:
            detail = exc.detail if isinstance(exc, HTTPException) else "Conflicting resource IDs or names"
            return EdgeDesiredStateResponse(dry_run=True, changed=stable_json(before) != stable_json(body),
                                            diff=diff, validation_errors=[{"detail":detail}], **before)
        if isinstance(exc, IntegrityError):
            raise HTTPException(409, "Conflicting resource IDs or names") from exc
        raise
    if dry_run or not apply:
        await savepoint.rollback()
        return EdgeDesiredStateResponse(dry_run=True, changed=stable_json(before) != stable_json(after),
                                        diff=stable_json(redact_edge_desired_state({"before":before, "after":after, "prune":prune})) if return_diff else None,
                                        **after)
    await savepoint.commit()
    await db.commit()
    sent, _command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=_.id)
    emit_edge_changed()
    after = await desired_state_snapshot(agent_id, db)
    return EdgeDesiredStateResponse(
        dry_run=False,
        changed=stable_json(before) != stable_json(after),
        diff=stable_json(redact_edge_desired_state({"before":before, "after":after, "prune":prune})) if return_diff else None,
        reconcile_sent=sent,
        **after,
    )


@router.post("/{agent_id}/edge/import/traefik/preview")
async def preview_import(
    agent_id: uuid.UUID,
    body: NodeTraefikImportRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_ops_role),
):
    from app.services.node_traefik_import import preview_node_import

    return await preview_node_import(agent_id, body, db)


@router.post("/{agent_id}/edge/import/traefik/apply")
@router.post("/{agent_id}/edge/import/traefik/upsert")
async def apply_import(
    agent_id: uuid.UUID,
    body: NodeTraefikImportRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    from app.services.node_traefik_import import apply_node_import

    server = await _server_for_agent(agent_id, db)
    _ensure_enabled(server)
    return await apply_node_import(agent_id, body, db, user)

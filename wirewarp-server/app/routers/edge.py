from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.edge_access_event import EdgeAccessEvent
from app.models.edge_fragment import EdgeFragment
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_profile import EdgeProfile
from app.models.edge_route_config import EdgeRouteConfig
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.port_forward import PortForward
from app.models.user import User
from app.realtime.events import emit_edge_changed, emit_security_changed
from app.schemas.edge import (
    EdgeAccessEventList,
    EdgeAccessEventRead,
    EdgeEffectivePolicyRead,
    EdgeFragmentCreate,
    EdgeFragmentRead,
    EdgePathRuleCreate,
    EdgePathRuleRead,
    EdgeProfileRead,
    EdgeProfileUpsert,
    EdgeRouteRead,
    EdgeRouteUpsert,
    EdgeUpstreamPoolRead,
    EdgeUpstreamPoolUpsert,
)
from app.services.edge_ops import dispatch_edge_desired_state, dispatch_edge_for_attachment
from app.services.edge_resources import (
    apply_policy_to_edge_config,
    get_profile_by_id_or_slug,
    profile_read,
    route_edge_config,
    route_effective_policy,
    route_read,
    slugify,
)

router = APIRouter()


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


@router.get("/access-events", response_model=EdgeAccessEventList)
async def list_access_events(
    node_id: uuid.UUID | None = None,
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
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    q = select(EdgeAccessEvent)
    if node_id:
        q = q.where(EdgeAccessEvent.agent_id == node_id)
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


@router.get("/access-events/{event_id}", response_model=EdgeAccessEventRead)
async def get_access_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    row = await db.get(EdgeAccessEvent, event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Access event not found")
    return EdgeAccessEventRead.model_validate(row)


@router.get("/profiles", response_model=list[EdgeProfileRead])
async def list_profiles(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    rows = (await db.execute(select(EdgeProfile).order_by(EdgeProfile.slug))).scalars().all()
    return [profile_read(row) for row in rows]


@router.post("/profiles", response_model=EdgeProfileRead, status_code=201)
async def create_profile(
    body: EdgeProfileUpsert,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    slug = body.slug or slugify(body.name)
    existing = await get_profile_by_id_or_slug(db, slug)
    if existing is not None:
        raise HTTPException(status_code=409, detail={"code": "edge_profile_exists", "field": "slug"})
    profile = EdgeProfile(
        id=uuid.uuid4(),
        name=body.name,
        slug=slug,
        description=body.description,
        scope=body.scope,
        agent_id=body.agent_id,
        policy_json=body.policy,
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return profile_read(profile)


@router.get("/profiles/{profile_id_or_slug}", response_model=EdgeProfileRead)
async def get_profile(
    profile_id_or_slug: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    profile = await get_profile_by_id_or_slug(db, profile_id_or_slug)
    if profile is None:
        raise HTTPException(status_code=404, detail="Edge profile not found")
    return profile_read(profile)


@router.put("/profiles/{profile_id_or_slug}", response_model=EdgeProfileRead)
async def put_profile(
    profile_id_or_slug: str,
    body: EdgeProfileUpsert,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    profile = await get_profile_by_id_or_slug(db, profile_id_or_slug)
    if profile is None:
        profile = EdgeProfile(
            id=uuid.uuid4(),
            name=body.name,
            slug=body.slug or slugify(profile_id_or_slug),
        )
        db.add(profile)
    profile.name = body.name
    profile.slug = body.slug or profile.slug
    profile.description = body.description
    profile.scope = body.scope
    profile.agent_id = body.agent_id
    profile.policy_json = body.policy
    await db.commit()
    await db.refresh(profile)
    return profile_read(profile)


@router.delete("/profiles/{profile_id_or_slug}", status_code=204)
async def delete_profile(
    profile_id_or_slug: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    profile = await get_profile_by_id_or_slug(db, profile_id_or_slug)
    if profile is None:
        raise HTTPException(status_code=404, detail="Edge profile not found")
    await db.delete(profile)
    await db.commit()


@router.get("/upstream-pools/{pool_id}", response_model=EdgeUpstreamPoolRead)
async def get_upstream_pool(
    pool_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    row = await db.get(EdgeUpstreamPool, pool_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge upstream pool not found")
    return _upstream_pool_read(row)


@router.put("/upstream-pools/{pool_id}", response_model=EdgeUpstreamPoolRead)
@router.patch("/upstream-pools/{pool_id}", response_model=EdgeUpstreamPoolRead)
async def update_upstream_pool(
    pool_id: uuid.UUID,
    body: EdgeUpstreamPoolUpsert,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await db.get(EdgeUpstreamPool, pool_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge upstream pool not found")
    row.name = body.name
    row.description = body.description
    row.servers = body.servers
    row.health_check = body.health_check
    row.policy_json = body.policy
    await db.commit()
    await db.refresh(row)
    await dispatch_edge_desired_state(row.agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return _upstream_pool_read(row)


@router.delete("/upstream-pools/{pool_id}", status_code=204)
async def delete_upstream_pool(
    pool_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await db.get(EdgeUpstreamPool, pool_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge upstream pool not found")
    agent_id = row.agent_id
    await db.delete(row)
    await db.commit()
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()


@router.get("/routes/{route_id}", response_model=EdgeRouteRead)
async def get_route(
    route_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    route = await db.scalar(
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.id == route_id, PortForward.service_kind == "http")
    )
    if route is None:
        raise HTTPException(status_code=404, detail="Edge route not found")
    return await route_read(db, route, route.edge_route_config)


@router.patch("/routes/{route_id}", response_model=EdgeRouteRead)
@router.put("/routes/{route_id}", response_model=EdgeRouteRead)
async def update_route(
    route_id: uuid.UUID,
    body: EdgeRouteUpsert,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    route = await db.scalar(
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.id == route_id, PortForward.service_kind == "http")
    )
    if route is None:
        raise HTTPException(status_code=404, detail="Edge route not found")
    if body.attachment_id is not None:
        route.attachment_id = body.attachment_id
    if body.enabled is not None:
        route.active = body.enabled
    if body.destination_ip is not None:
        route.destination_ip = body.destination_ip
    if body.destination_port is not None:
        route.destination_port = body.destination_port
    if body.description is not None:
        route.description = body.description
    ec = await route_edge_config(db, route)
    if body.profile_id is not None:
        ec.profile_id = body.profile_id
    if body.profile is not None:
        profile = await get_profile_by_id_or_slug(db, body.profile)
        if profile is None:
            raise HTTPException(status_code=404, detail="Edge profile not found")
        ec.profile_id = profile.id
    if body.priority is not None:
        ec.priority = body.priority
    if body.upstream_scheme is not None:
        ec.upstream_scheme = body.upstream_scheme
    if body.upstream_insecure_skip_verify is not None:
        ec.upstream_insecure_skip_verify = body.upstream_insecure_skip_verify
    if body.policy is not None:
        apply_policy_to_edge_config(ec, body.policy)
    await db.commit()
    await db.refresh(route)
    await dispatch_edge_for_attachment(route.attachment_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    emit_security_changed()
    return await route_read(db, route, ec)


@router.delete("/routes/{route_id}", status_code=204)
async def delete_route(
    route_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    route = await db.get(PortForward, route_id)
    if route is None or route.service_kind != "http":
        raise HTTPException(status_code=404, detail="Edge route not found")
    attachment_id = route.attachment_id
    await db.delete(route)
    await db.commit()
    await dispatch_edge_for_attachment(attachment_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    emit_security_changed()


@router.get("/fragments/{fragment_id}", response_model=EdgeFragmentRead)
async def get_fragment(
    fragment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    row = await db.get(EdgeFragment, fragment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge fragment not found")
    return EdgeFragmentRead.model_validate(row)


@router.put("/fragments/{fragment_id}", response_model=EdgeFragmentRead)
@router.patch("/fragments/{fragment_id}", response_model=EdgeFragmentRead)
async def update_fragment(
    fragment_id: uuid.UUID,
    body: EdgeFragmentCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await db.get(EdgeFragment, fragment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge fragment not found")
    row.name = body.name
    row.fragment_type = body.fragment_type
    row.content = body.content
    row.route_id = body.route_id
    row.enabled = body.enabled
    row.validation_state = "valid" if isinstance(body.content, dict) else "invalid"
    row.last_error = None if row.validation_state == "valid" else "Fragment content must be an object."
    await db.commit()
    await db.refresh(row)
    await dispatch_edge_desired_state(row.agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return EdgeFragmentRead.model_validate(row)


@router.delete("/fragments/{fragment_id}", status_code=204)
async def delete_fragment(
    fragment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await db.get(EdgeFragment, fragment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge fragment not found")
    agent_id = row.agent_id
    await db.delete(row)
    await db.commit()
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()


@router.post("/fragments/{fragment_id}/validate")
async def validate_fragment(
    fragment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    row = await db.get(EdgeFragment, fragment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge fragment not found")
    valid = isinstance(row.content, dict) and row.fragment_type in {"middleware", "service", "router", "tls", "transport"}
    return {"valid": valid, "errors": [] if valid else [{"code": "invalid_fragment"}]}


@router.get("/routes/{route_id}/effective", response_model=EdgeEffectivePolicyRead)
async def get_route_effective(
    route_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    route = await db.scalar(
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.id == route_id, PortForward.service_kind == "http")
    )
    if route is None:
        raise HTTPException(status_code=404, detail="Edge route not found")
    return await route_effective_policy(db, route, route.edge_route_config)


@router.post("/routes/{route_id}/validate")
async def validate_route(
    route_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    route = await db.get(PortForward, route_id)
    if route is None or route.service_kind != "http":
        raise HTTPException(status_code=404, detail="Edge route not found")
    return {"valid": True, "warnings": []}


@router.post("/routes/{route_id}/cache/preview")
async def preview_route_cache(
    route_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    route = await db.get(PortForward, route_id)
    if route is None or route.service_kind != "http":
        raise HTTPException(status_code=404, detail="Edge route not found")
    ec = await route_edge_config(db, route)
    policy = dict(ec.policy_json or {})
    return {"route_id": route_id, "cache": policy.get("cache", {"mode": "off"}), "available": True}


@router.post("/routes/{route_id}/cache/purge")
async def purge_route_cache(
    route_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    route = await db.get(PortForward, route_id)
    if route is None or route.service_kind != "http":
        raise HTTPException(status_code=404, detail="Edge route not found")
    raise HTTPException(status_code=409, detail={"code": "edge_cache_unavailable", "reason": "purge_requires_healthy_backend"})


@router.get("/routes/{route_id}/path-rules", response_model=list[EdgePathRuleRead])
async def list_path_rules(
    route_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    route = await db.scalar(
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.id == route_id, PortForward.service_kind == "http")
    )
    if route is None:
        raise HTTPException(status_code=404, detail="Edge route not found")
    rows = (
        await db.execute(
            select(EdgePathRule)
            .where(EdgePathRule.route_id == route_id)
            .order_by(EdgePathRule.priority.desc(), EdgePathRule.created_at)
        )
    ).scalars().all()
    return [await _path_rule_read(db, route, row) for row in rows]


@router.post("/routes/{route_id}/path-rules", response_model=EdgePathRuleRead, status_code=201)
async def create_path_rule(
    route_id: uuid.UUID,
    body: EdgePathRuleCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    route = await db.scalar(
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.id == route_id, PortForward.service_kind == "http")
    )
    if route is None:
        raise HTTPException(status_code=404, detail="Edge route not found")
    row = EdgePathRule(
        id=uuid.uuid4(),
        route_id=route_id,
        name=body.name,
        match=body.match,
        priority=body.priority,
        enabled=body.enabled,
        policy_json=body.policy,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    await dispatch_edge_for_attachment(route.attachment_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return await _path_rule_read(db, route, row)


@router.get("/path-rules/{rule_id}", response_model=EdgePathRuleRead)
async def get_path_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_ops_role),
):
    row = await db.get(EdgePathRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge path rule not found")
    route = await db.scalar(
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.id == row.route_id, PortForward.service_kind == "http")
    )
    if route is None:
        raise HTTPException(status_code=404, detail="Edge route not found")
    return await _path_rule_read(db, route, row)


@router.put("/path-rules/{rule_id}", response_model=EdgePathRuleRead)
@router.patch("/path-rules/{rule_id}", response_model=EdgePathRuleRead)
async def update_path_rule(
    rule_id: uuid.UUID,
    body: EdgePathRuleCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await db.get(EdgePathRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge path rule not found")
    route = await db.scalar(
        select(PortForward)
        .options(selectinload(PortForward.edge_route_config))
        .where(PortForward.id == row.route_id, PortForward.service_kind == "http")
    )
    if route is None:
        raise HTTPException(status_code=404, detail="Edge route not found")
    row.name = body.name
    row.match = body.match
    row.priority = body.priority
    row.enabled = body.enabled
    row.policy_json = body.policy
    await db.commit()
    await db.refresh(row)
    await dispatch_edge_for_attachment(route.attachment_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    return await _path_rule_read(db, route, row)


@router.delete("/path-rules/{rule_id}", status_code=204)
async def delete_path_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
):
    row = await db.get(EdgePathRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Edge path rule not found")
    route = await db.get(PortForward, row.route_id)
    attachment_id = route.attachment_id if route is not None else None
    await db.delete(row)
    await db.commit()
    if attachment_id is not None:
        await dispatch_edge_for_attachment(attachment_id, db, actor_user_id=actor.id)
    emit_edge_changed()


async def _path_rule_read(
    db: AsyncSession,
    route: PortForward,
    row: EdgePathRule,
) -> EdgePathRuleRead:
    effective = await route_effective_policy(db, route, route.edge_route_config, path_rule=row)
    return EdgePathRuleRead(
        id=row.id,
        route_id=row.route_id,
        name=row.name,
        match=row.match,
        priority=row.priority,
        enabled=row.enabled,
        policy=row.policy_json or {},
        effective=effective.effective,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )

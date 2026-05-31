from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import require_ops_role, require_role
from app.database import get_db
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_profile import EdgeProfile
from app.models.edge_route_config import EdgeRouteConfig
from app.models.port_forward import PortForward
from app.models.user import User
from app.realtime.events import emit_edge_changed, emit_security_changed
from app.schemas.edge import (
    EdgeEffectivePolicyRead,
    EdgePathRuleCreate,
    EdgePathRuleRead,
    EdgeProfileRead,
    EdgeProfileUpsert,
    EdgeRouteRead,
    EdgeRouteUpsert,
)
from app.services.edge_ops import dispatch_edge_for_attachment
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

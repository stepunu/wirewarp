"""Preserve route configuration without storing ACME credentials or private state."""
import json
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import UUID

from app.models.edge_fragment import EdgeFragment
from app.models.edge_migration import EdgeMigration
from app.models.edge_node import EdgeNode
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_profile import EdgeProfile
from app.models.edge_route_config import EdgeRouteConfig
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.services.edge_ownership import load_http_routes


def _row_data(row):
    if row is None:
        return None
    data = {column.name: getattr(row, column.name) for column in row.__table__.columns
            if column.name not in {"created_at", "updated_at"}}
    return json.loads(json.dumps(data, default=str))


def _assign(row, data):
    for column in row.__table__.columns:
        if column.name not in data:
            continue
        value = data[column.name]
        if value is not None and isinstance(column.type, UUID):
            value = uuid.UUID(value)
        setattr(row, column.name, value)


async def capture_edge_source(agent_id, db):
    agent_id = uuid.UUID(str(agent_id))
    node = await db.get(EdgeNode, agent_id)
    policy = await db.get(EdgeNodePolicy, agent_id)
    routes = await load_http_routes(db, agent_id)
    profile_ids = {route.edge_route_config.profile_id for route in routes if route.edge_route_config and route.edge_route_config.profile_id}
    if policy and policy.default_profile_id:
        profile_ids.add(policy.default_profile_id)
    profiles = list((await db.scalars(select(EdgeProfile).where(EdgeProfile.id.in_(profile_ids)).order_by(EdgeProfile.id))).all())
    route_ids = [route.id for route in routes]
    paths = list((await db.scalars(select(EdgePathRule).where(EdgePathRule.route_id.in_(route_ids)).order_by(EdgePathRule.id))).all())
    pools = list((await db.scalars(select(EdgeUpstreamPool).where(EdgeUpstreamPool.agent_id == agent_id).order_by(EdgeUpstreamPool.id))).all())
    fragments = list((await db.scalars(select(EdgeFragment).where(EdgeFragment.agent_id == agent_id).order_by(EdgeFragment.id))).all())
    return {
        "schema_version": 1, "agent_id": str(agent_id),
        "node": {key: getattr(node, key) for key in ("edge_rate_limit_rps", "edge_rate_limit_burst", "lan_bind_ip", "public_bind_ip", "rfc2136_nameserver_override")},
        "node_policy": _row_data(policy), "profiles": [_row_data(profile) for profile in profiles],
        "routes": [{"route": _row_data(route), "config": _row_data(route.edge_route_config), "ingress": _row_data(route.public_ingress)} for route in routes],
        "paths": [_row_data(path) for path in paths], "pools": [_row_data(pool) for pool in pools],
        "fragments": [_row_data(fragment) for fragment in fragments],
    }


async def _restore_owned_rows(model, rows, selector, db):
    existing = {row.id: row for row in (await db.scalars(select(model).where(selector))).all()}
    wanted = {uuid.UUID(row["id"]) for row in rows}
    for key, row in existing.items():
        if key not in wanted:
            await db.delete(row)
        elif hasattr(row, "name"):
            row.name = "rollback-" + key.hex
    await db.flush()
    for data in rows:
        key = uuid.UUID(data["id"])
        row = existing.get(key)
        if row is None:
            if await db.get(model, key) is not None:
                raise HTTPException(409, "A rollback resource now belongs to another node")
            row = model()
            db.add(row)
        _assign(row, data)
    await db.flush()


async def restore_edge_source(version, db):
    snapshot = version.source_snapshot
    if not snapshot or snapshot.get("schema_version") != 1:
        raise HTTPException(409, "This version has no restorable source snapshot")
    agent_id = version.agent_id
    if snapshot.get("agent_id") != str(agent_id):
        raise HTTPException(409, "Config snapshot belongs to another node")
    active_migration = await db.scalar(select(EdgeMigration.id).where(
        ((EdgeMigration.source_agent_id == agent_id) | (EdgeMigration.target_agent_id == agent_id)),
        EdgeMigration.phase.not_in(["completed", "rolled_back", "canceled"]),
    ).limit(1))
    if active_migration:
        raise HTTPException(409, "Use migration rollback or cancel before restoring this node configuration")
    snapshot = json.loads(json.dumps(snapshot))
    profile_map = {}
    for data in snapshot["profiles"]:
        original = uuid.UUID(data["id"])
        current = await db.get(EdgeProfile, original)
        if current and _row_data(current) == data:
            profile_map[str(original)] = original
            continue
        # Global profiles can serve other nodes. Restore a private copy.
        clone_id = uuid.uuid5(version.id, "profile:" + str(original))
        clone = await db.get(EdgeProfile, clone_id)
        if clone is None:
            clone = EdgeProfile(id=clone_id)
            db.add(clone)
        clone_data = dict(data, id=str(clone_id), scope="node", agent_id=str(agent_id),
                          slug=data["slug"] + "-rollback-" + version.id.hex)
        _assign(clone, clone_data)
        profile_map[str(original)] = clone_id
    await db.flush()
    node = await db.get(EdgeNode, agent_id)
    snapshot["node"].setdefault("rfc2136_nameserver_override", None)
    for key, value in snapshot["node"].items():
        setattr(node, key, value)
    policy = await db.get(EdgeNodePolicy, agent_id)
    policy_data = snapshot["node_policy"]
    if policy_data is None:
        if policy:
            await db.delete(policy)
    else:
        if policy is None:
            policy = EdgeNodePolicy(agent_id=agent_id)
            db.add(policy)
        if policy_data.get("default_profile_id"):
            policy_data["default_profile_id"] = str(profile_map[policy_data["default_profile_id"]])
        _assign(policy, policy_data)
    current_routes = {row.id: row for row in await load_http_routes(db, agent_id)}
    wanted = {uuid.UUID(item["route"]["id"]) for item in snapshot["routes"]}
    for key, row in current_routes.items():
        if key not in wanted:
            from app.services.edge_migration import ensure_route_not_referenced
            await ensure_route_not_referenced(db, row.id)
            await db.delete(row)
    await db.flush()
    for item in snapshot["routes"]:
        data = item["route"]
        key = uuid.UUID(data["id"])
        row = current_routes.get(key)
        if row is None:
            if await db.get(HTTPRoute, key) is not None:
                raise HTTPException(409, "A rollback route has moved to another node. Use migration rollback")
            row = HTTPRoute()
            db.add(row)
            _assign(row, data)
            await db.flush()
            row.edge_route_config = None
            row.public_ingress = None
        else:
            _assign(row, data)
        config_data = item["config"]
        if config_data:
            if config_data.get("profile_id"):
                config_data["profile_id"] = str(profile_map[config_data["profile_id"]])
            ec = row.edge_route_config
            if ec is None:
                ec = EdgeRouteConfig()
                db.add(ec)
                row.edge_route_config = ec
            _assign(ec, config_data)
        elif row.edge_route_config:
            await db.delete(row.edge_route_config)
            row.edge_route_config = None
        ingress_data = item["ingress"]
        if ingress_data:
            ingress = row.public_ingress
            if ingress is None:
                ingress = HTTPPublicIngress()
                db.add(ingress)
                row.public_ingress = ingress
            _assign(ingress, ingress_data)
        elif row.public_ingress:
            await db.delete(row.public_ingress)
            row.public_ingress = None
    await db.flush()
    await _restore_owned_rows(EdgePathRule, snapshot["paths"], EdgePathRule.route_id.in_(wanted | set(current_routes)), db)
    await _restore_owned_rows(EdgeUpstreamPool, snapshot["pools"], EdgeUpstreamPool.agent_id == agent_id, db)
    await _restore_owned_rows(EdgeFragment, snapshot["fragments"], EdgeFragment.agent_id == agent_id, db)
    # Reuse publication checks against the current topology and conflicts.
    from app.routers.nodes import _upsert_node_route
    from app.schemas.edge import EdgeRouteUpsert
    # The route writer also fills defaults and activates ingress. Discard those
    # validation mutations so historical disabled ingress and absent config survive.
    validation = await db.begin_nested()
    try:
        for item in snapshot["routes"]:
            data, ingress = item["route"], item["ingress"]
            fields = {"domain":data["domain"], "visibility":data["visibility"]}
            if ingress:
                fields.update(attachment_id=ingress["attachment_id"], tunnel_server_ip_id=ingress["tunnel_server_ip_id"])
            await _upsert_node_route(agent_id, data["domain"], EdgeRouteUpsert(**fields), db, None,
                                     commit=False, route_id=uuid.UUID(data["id"]), validate_config=False)
    finally:
        await validation.rollback()
    db.expire_all()
    from app.services.edge_render import validate_edge_configuration
    await validate_edge_configuration(agent_id, db)
    await db.flush()

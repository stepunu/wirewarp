"""Stage private listeners, verify them, then move the original route UUID."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import uuid

from fastapi import HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import selectinload

from app.models.command_log import CommandLog
from app.models.edge_config_version import EdgeConfigVersion
from app.models.edge_fragment import EdgeFragment
from app.models.edge_migration import EdgeMigration
from app.models.edge_node import EdgeNode
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_profile import EdgeProfile
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.http_public_ingress import HTTPPublicIngress
from app.models.http_route import HTTPRoute
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.services.edge_render import effective_render_policy


def desired_hash(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def fail(detail, status=409):
    raise HTTPException(status_code=status, detail=detail)


async def ensure_route_not_referenced(db, route_id):
    if await db.scalar(select(EdgeMigration.id).where((EdgeMigration.source_route_id == route_id) | (EdgeMigration.stage_route_id == route_id)).limit(1)):
        fail("Cancel or roll back the migration and discard its history before deleting this route")


def row_values(row):
    if row is None:
        return None
    return json.loads(json.dumps({column.name: getattr(row, column.name) for column in row.__table__.columns if column.name not in {"created_at", "updated_at"}}, default=str))


def redacted(value):
    if isinstance(value, dict):
        return {key: "[redacted]" if any(word in key.lower() for word in ("secret", "password", "token", "auth_config", "users", "authorization", "keyfile")) else {header: "[redacted]" for header in item} if key.lower() in {"customrequestheaders", "customresponseheaders"} and isinstance(item, dict) else redacted(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redacted(item) for item in value]
    return value


async def load_route(db, route_id, *, lock=False):
    query = select(HTTPRoute).options(selectinload(HTTPRoute.edge_route_config), selectinload(HTTPRoute.public_ingress)).where(HTTPRoute.id == route_id)
    if lock:
        query = query.with_for_update()
    route = await db.scalar(query.execution_options(populate_existing=True))
    if route is None:
        fail("Migration route no longer exists", 404)
    return route


def pool_ids(value):
    found = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "upstream_pool_id" and item:
                try:
                    found.add(uuid.UUID(str(item)))
                except ValueError:
                    fail("An upstream pool reference is invalid")
            else:
                found.update(pool_ids(item))
    elif isinstance(value, list):
        for item in value:
            found.update(pool_ids(item))
    return found


def mapped_pools(value, mapping):
    if isinstance(value, dict):
        return {key: mapping.get(str(item), item) if key == "upstream_pool_id" else mapped_pools(item, mapping) for key, item in value.items()}
    if isinstance(value, list):
        return [mapped_pools(item, mapping) for item in value]
    return deepcopy(value)


def mapped_fragment_references(value, mapping):
    if isinstance(value, dict):
        return {key: mapped_fragment_references(item, mapping) for key, item in value.items()}
    if isinstance(value, list):
        return [mapped_fragment_references(item, mapping) for item in value]
    if isinstance(value, str):
        for original, clone in mapping.items():
            if value in {f"fragment-{original}", f"fragment-{original}@file"}:
                return value.replace(f"fragment-{original}", f"fragment-{clone}", 1)
    return deepcopy(value)


def fragment_ids(value):
    found = set()
    if isinstance(value, dict):
        for item in value.values():
            found.update(fragment_ids(item))
    elif isinstance(value, list):
        for item in value:
            found.update(fragment_ids(item))
    elif isinstance(value, str) and value.startswith("fragment-"):
        try:
            found.add(uuid.UUID(value.removeprefix("fragment-").removesuffix("@file")))
        except ValueError:
            fail("A fragment dependency reference is invalid")
    return found


async def route_bundle(db, route):
    config = route.edge_route_config
    paths = list((await db.scalars(select(EdgePathRule).where(EdgePathRule.route_id == route.id).order_by(EdgePathRule.id))).all())
    effective = await effective_render_policy(db, route, config)
    policies = [effective, *[await effective_render_policy(db, route, config, path) for path in paths]]
    refs = set()
    for policy in policies:
        refs.update(policy.get("middlewares") or [])
        if (policy.get("origin") or {}).get("service"):
            refs.add(policy["origin"]["service"])
    fragments = list((await db.scalars(select(EdgeFragment).where(EdgeFragment.agent_id == route.agent_id, (EdgeFragment.route_id == route.id) | ((EdgeFragment.route_id.is_(None)) & (EdgeFragment.name.in_(refs)))).order_by(EdgeFragment.id))).all())
    dependencies = set().union(*(fragment_ids(item.content) for item in fragments))
    known = {item.id for item in fragments}
    while dependencies - known:
        dependency_id = next(iter(dependencies - known))
        dependency = await db.get(EdgeFragment, dependency_id)
        if dependency is None or dependency.agent_id != route.agent_id or dependency.route_id not in (None, route.id):
            fail("Fragment dependencies must belong to this route or its node")
        fragments.append(dependency)
        known.add(dependency_id)
        dependencies.update(fragment_ids(dependency.content))
    fragments.sort(key=lambda item: str(item.id))
    ids = set().union(*(pool_ids(policy) for policy in policies))
    pools = []
    for pool_id in sorted(ids, key=str):
        pool = await db.get(EdgeUpstreamPool, pool_id)
        if pool is None or pool.agent_id != route.agent_id:
            fail("Referenced upstream pools must belong to the source node")
        pools.append(row_values(pool))
    node_policy = await db.get(EdgeNodePolicy, route.agent_id)
    profile_id = config.profile_id if config and config.profile_id else node_policy.default_profile_id if node_policy and (config is None or config.inherit_node_policy) else None
    profile = await db.get(EdgeProfile, profile_id) if profile_id else None
    node = await db.get(EdgeNode, route.agent_id)
    return {"route": row_values(route), "config": row_values(config), "ingress": row_values(route.public_ingress), "paths": [row_values(path) for path in paths], "fragments": [row_values(fragment) for fragment in fragments], "pools": pools, "profile": row_values(profile), "node_policy": row_values(node_policy) if config is None or config.inherit_node_policy else None, "node_rate": [node.edge_rate_limit_rps, node.edge_rate_limit_burst] if node else [None, None], "effective": effective}


async def validate_request(db, body, *, existing=None):
    route = await load_route(db, body.source_route_id, lock=True)
    source = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == route.agent_id))
    if source is None or route.visibility != "public_only" or not route.active:
        fail("Select an active VPS-owned public HTTP route")
    gateway = await db.scalar(select(TunnelClient).where(TunnelClient.agent_id == body.target_agent_id, TunnelClient.is_gateway.is_(True)))
    if gateway is None or body.target_agent_id == route.agent_id:
        fail("Select a different gateway node", 400)
    attachment = await db.get(TunnelClientAttachment, body.target_attachment_id)
    if attachment is None or attachment.tunnel_client_id != gateway.id or attachment.tunnel_server_id != source.id:
        fail("The target attachment must connect this gateway to the source VPS", 400)
    if not attachment.wg_public_key or not source.wg_public_key:
        fail("The target attachment must complete WireGuard setup")
    source_node, target_node = await db.get(EdgeNode, route.agent_id), await db.get(EdgeNode, body.target_agent_id)
    for node in (source_node, target_node):
        if node is None or node.edge_mode != "security_edge" or node.edge_state != "enabled":
            fail("Enable Security Edge on both nodes before migration")
    if target_node.lan_bind_ip != gateway.lan_ip or target_node.public_bind_ip not in {None, attachment.tunnel_ip}:
        fail("Configure the gateway LAN and selected attachment public listeners before migration")
    if [source_node.edge_rate_limit_rps, source_node.edge_rate_limit_burst] != [target_node.edge_rate_limit_rps, target_node.edge_rate_limit_burst]:
        fail("Source and target node-wide rate limits must match before migration")
    pending = await db.scalar(select(EdgeMigration).where(EdgeMigration.source_route_id == route.id))
    if pending is not None and (existing is None or pending.id != existing.id):
        fail("This source route already has a migration record")
    conflicts = select(HTTPRoute).outerjoin(HTTPPublicIngress).outerjoin(TunnelClientAttachment, TunnelClientAttachment.id == HTTPPublicIngress.attachment_id).where(func.lower(HTTPRoute.domain) == route.domain.lower(), HTTPRoute.id != route.id, (HTTPRoute.agent_id == body.target_agent_id) | ((HTTPRoute.visibility.in_(["public_only", "both"])) & ((HTTPRoute.agent_id == source.agent_id) | (TunnelClientAttachment.tunnel_server_id == source.id))))
    if existing and existing.stage_route_id:
        conflicts = conflicts.where(HTTPRoute.id != existing.stage_route_id)
    if await db.scalar(conflicts.limit(1)):
        fail("The hostname is already reserved by another route on the gateway or VPS")
    others = select(HTTPPublicIngress).join(HTTPRoute).where(HTTPRoute.agent_id == body.target_agent_id, HTTPRoute.visibility.in_(["public_only", "both"]), HTTPPublicIngress.attachment_id != attachment.id)
    if await db.scalar(others.limit(1)):
        fail("Gateway public routes must use one relay attachment")
    from app.services.edge_port_conflicts import find_active_raw_edge_forward_on_server
    if await find_active_raw_edge_forward_on_server(db, source.id):
        fail("A raw TCP forward uses the source VPS relay ports")
    bundle = await route_bundle(db, route)
    if any(item["enabled"] and item["fragment_type"] in {"router", "tls"} for item in bundle["fragments"]):
        fail("Router and TLS fragments require manual gateway conversion before migration")
    fragment_names = [item["name"] for item in bundle["fragments"]]
    fragment_conflicts = select(EdgeFragment.id).where(EdgeFragment.agent_id == body.target_agent_id, EdgeFragment.name.in_(fragment_names))
    if existing:
        owned_ids = [uuid.UUID(item) for item in existing.resource_map.get("fragments", {}).values()]
        if owned_ids:
            fragment_conflicts = fragment_conflicts.where(EdgeFragment.id.not_in(owned_ids))
    if fragment_names and await db.scalar(fragment_conflicts.limit(1)):
        fail("A fragment name already exists on the target gateway")
    return route, bundle


async def preview(db, body):
    route, bundle = await validate_request(db, body)
    target = await db.get(EdgeNode, body.target_agent_id)
    attachment = await db.get(TunnelClientAttachment, body.target_attachment_id)
    return {"source_route_id": str(route.id), "source_agent_id": str(route.agent_id), "target_agent_id": str(body.target_agent_id), "domain": route.domain, "destination_ip": route.destination_ip, "destination_port": route.destination_port, "visibility": body.visibility, "effective_policy": redacted(bundle["effective"]), "planned_changes": {"public_bind_ip": {"before": target.public_bind_ip, "after": attachment.tunnel_ip, "assigned_on_provision": target.public_bind_ip is None}}, "preservation": {"route_uuid": True, "policy_uuid": bool(bundle["config"]), "path_rule_uuids": len(bundle["paths"]), "fragment_uuids": len([item for item in bundle["fragments"] if item["route_id"]]), "profile": "clone source-owned profile; retain global profile", "inheritance": "freeze source effective policy; ignore target node policy", "credentials": "Reuse configured control-server secrets; no private ACME store transfer"}, "source_fingerprint": desired_hash(bundle)}


def copied_fields(model, values, excluded):
    result = {key: deepcopy(value) for key, value in values.items() if key not in excluded}
    for column in model.__table__.columns:
        if column.name in result and isinstance(column.type, type(HTTPRoute.__table__.c.id.type)) and result[column.name]:
            result[column.name] = uuid.UUID(str(result[column.name]))
    return result


async def stage(db, body, actor):
    route, bundle = await validate_request(db, body)
    if getattr(body, "expected_source_fingerprint", None) != desired_hash(bundle):
        fail("The source configuration changed. Preview the migration again before staging")
    record = EdgeMigration(source_route_id=route.id, source_agent_id=route.agent_id, target_agent_id=body.target_agent_id, target_attachment_id=body.target_attachment_id, target_visibility=body.visibility, original_snapshot=deepcopy(bundle), source_fingerprint=desired_hash(bundle), created_by=actor.id, phase="staged", revision=1, resource_map={}, final_version_ids={}, rollback_version_ids={})
    db.add(record)
    await db.flush()
    staged = HTTPRoute(agent_id=body.target_agent_id, domain=route.domain, destination_ip=route.destination_ip, destination_port=route.destination_port, description=route.description, visibility=body.visibility, active=False)
    db.add(staged)
    await db.flush()
    record.stage_route_id = staged.id
    resources = {"profiles": {}, "pools": {}, "fragments": {}, "paths": {}}
    profile = bundle["profile"]
    profile_id = uuid.UUID(profile["id"]) if profile else None
    if profile and profile["agent_id"]:
        clone = EdgeProfile(name=profile["name"], slug=f"migration-{record.id}-{profile['slug']}", description=profile["description"], scope="node", agent_id=body.target_agent_id, policy_json=deepcopy(profile["policy_json"]))
        db.add(clone)
        await db.flush()
        resources["profiles"][profile["id"]] = str(clone.id)
        profile_id = clone.id
    for pool in bundle["pools"]:
        clone = EdgeUpstreamPool(**copied_fields(EdgeUpstreamPool, pool, {"id", "agent_id", "name"}), agent_id=body.target_agent_id, name=f"migration-{record.id}-{pool['name']}")
        db.add(clone)
        await db.flush()
        resources["pools"][pool["id"]] = str(clone.id)
    fields = copied_fields(type(route.edge_route_config), bundle["config"], {"id", "route_id", "profile_id", "policy_json", "inherit_node_policy"}) if route.edge_route_config else {}
    from app.models.edge_route_config import EdgeRouteConfig
    config = EdgeRouteConfig(route_id=staged.id, profile_id=profile_id, policy_json=mapped_pools(bundle["effective"], resources["pools"]), inherit_node_policy=False, **fields)
    db.add(config)
    for path in bundle["paths"]:
        clone = EdgePathRule(**copied_fields(EdgePathRule, path, {"id", "route_id", "policy_json"}), route_id=staged.id, policy_json=mapped_pools(path["policy_json"], resources["pools"]))
        db.add(clone)
        await db.flush()
        resources["paths"][path["id"]] = str(clone.id)
    for fragment in bundle["fragments"]:
        clone = EdgeFragment(**copied_fields(EdgeFragment, fragment, {"id", "agent_id", "route_id"}), agent_id=body.target_agent_id, route_id=staged.id if fragment["route_id"] else None)
        db.add(clone)
        await db.flush()
        resources["fragments"][fragment["id"]] = str(clone.id)
    for original in bundle["fragments"]:
        clone = await db.get(EdgeFragment, uuid.UUID(resources["fragments"][original["id"]]))
        clone.content = mapped_fragment_references(clone.content, resources["fragments"])
    original_binding = bundle["ingress"] or {}
    db.add(HTTPPublicIngress(route_id=staged.id, attachment_id=body.target_attachment_id, tunnel_server_ip_id=uuid.UUID(original_binding["tunnel_server_ip_id"]) if original_binding.get("tunnel_server_ip_id") else None, public_port=original_binding.get("public_port", 443), active=False))
    record.resource_map = resources
    await db.flush()
    staged = await load_route(db, staged.id)
    record.staged_fingerprint = desired_hash(await route_bundle(db, staged))
    await db.commit()
    return record


async def get_migration(db, migration_id, revision=None):
    record = await db.scalar(select(EdgeMigration).where(EdgeMigration.id == migration_id).with_for_update())
    if record is None:
        fail("Migration not found", 404)
    if revision is not None and revision != record.revision:
        fail("Migration changed; reload before continuing")
    return record


async def staged_routes_unchanged(db, record):
    source = await load_route(db, record.source_route_id, lock=True)
    staged = await load_route(db, record.stage_route_id, lock=True) if record.stage_route_id else None
    if source.agent_id != record.source_agent_id or desired_hash(await route_bundle(db, source)) != record.source_fingerprint:
        fail("The source route or inherited resources changed after staging; cancel and preview again")
    if staged is None or staged.agent_id != record.target_agent_id or desired_hash(await route_bundle(db, staged)) != record.staged_fingerprint:
        fail("The staged route or target resources changed; cancel and preview again")
    return source, staged


async def dispatched_version(db, agent_id, actor):
    from app.services.edge_ops import dispatch_edge_desired_state
    sent, command_id = await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    command = await db.get(CommandLog, uuid.UUID(command_id)) if command_id != "edge_feature_disabled" else None
    version_id = (command.params or {}).get("config_version_id") if command else None
    version = await db.get(EdgeConfigVersion, uuid.UUID(version_id)) if version_id else None
    if version is None:
        fail("Edge dispatch did not persist a verifiable configuration version")
    return sent, version, command.id


async def provision(db, record, actor):
    from app.schemas.edge_migration import EdgeMigrationRequest
    if record.phase not in {"staged", "provisioning"}:
        fail("Only a staged migration can be provisioned")
    _, staged = await staged_routes_unchanged(db, record)
    await validate_request(db, EdgeMigrationRequest(source_route_id=record.source_route_id, target_agent_id=record.target_agent_id, target_attachment_id=record.target_attachment_id, visibility=record.target_visibility), existing=record)
    target = await db.get(EdgeNode, record.target_agent_id)
    attachment = await db.get(TunnelClientAttachment, record.target_attachment_id)
    if target.public_bind_ip is None:
        target.public_bind_ip = attachment.tunnel_ip
    staged.active = True
    record.phase = "provisioning"
    record.test_command_id = None
    record.revision += 1
    await db.flush()
    record.staged_fingerprint = desired_hash(await route_bundle(db, staged))
    await db.commit()
    _, version, command_id = await dispatched_version(db, record.target_agent_id, actor)
    record.stage_desired_hash = version.desired_hash
    record.stage_version_id = version.id
    record.stage_command_id = command_id
    await db.commit()
    return record


async def command_applied(db, agent_id, command_id, version_id, current_hash):
    command = await db.get(CommandLog, command_id) if command_id else None
    if command is None or command.agent_id != agent_id or command.command_type != "edge_desired_state" or command.success is not True:
        return False
    params = command.params or {}
    if params.get("config_version_id") != str(version_id) or params.get("desired_hash") != current_hash:
        return False
    pending = await db.scalar(select(CommandLog.id).where(CommandLog.agent_id == agent_id, CommandLog.command_type == "edge_desired_state", CommandLog.id != command.id, CommandLog.executed_at >= command.executed_at, (CommandLog.success.is_(None)) | (CommandLog.success.is_(False))).limit(1))
    return pending is None


async def stage_gate(db, record, *, probe=False):
    if record.phase != "provisioning":
        fail("Provision the staged migration first")
    await staged_routes_unchanged(db, record)
    from app.schemas.edge_migration import EdgeMigrationRequest
    await validate_request(db, EdgeMigrationRequest(source_route_id=record.source_route_id, target_agent_id=record.target_agent_id, target_attachment_id=record.target_attachment_id, visibility=record.target_visibility), existing=record)
    from app.services.edge_ops import build_edge_desired_state
    current_hash = desired_hash(await build_edge_desired_state(record.target_agent_id, db))
    version = await db.get(EdgeConfigVersion, record.stage_version_id) if record.stage_version_id else None
    if version is None or version.agent_id != record.target_agent_id or version.desired_hash != current_hash or current_hash != record.stage_desired_hash or version.applied_at is None or version.agent_result != "applied" or not await command_applied(db, record.target_agent_id, record.stage_command_id, version.id, current_hash):
        fail("The gateway has not acknowledged this exact staged configuration successfully")
    if probe:
        command = await db.get(CommandLog, record.test_command_id) if record.test_command_id else None
        if command is None or command.agent_id != record.target_agent_id or command.command_type != "edge_route_test" or command.success is not True:
            fail("The gateway must pass the staged TLS and upstream probe before public switch")
        try:
            result = json.loads(command.output or "")
        except (TypeError, ValueError):
            fail("The gateway route probe returned an invalid result")
        expected = {"migration_id": str(record.id), "route_id": str(record.stage_route_id), "config_version_id": str(record.stage_version_id), "desired_hash": current_hash, "domain": (await load_route(db, record.source_route_id)).domain}
        if any(result.get(key) != value or (command.params or {}).get(key) != value for key, value in expected.items()) or result.get("status") != "verified" or any(result.get(key) is not True for key in ("tls_verified", "upstream_reachable", "route_response_received")):
            fail("The gateway probe does not verify this migration and staged configuration")
    return version


async def test_route(db, record, actor):
    await stage_gate(db, record)
    from app.services.agent_commands import send_command
    source = await load_route(db, record.source_route_id)
    params = {"migration_id": str(record.id), "route_id": str(record.stage_route_id), "config_version_id": str(record.stage_version_id), "desired_hash": record.stage_desired_hash, "domain": source.domain}
    _, command_id = await send_command(str(record.target_agent_id), "edge_route_test", params, db, actor_user_id=actor.id)
    record.test_command_id = uuid.UUID(command_id)
    record.revision += 1
    await db.commit()
    return record


async def finalize(db, record, actor):
    await stage_gate(db, record, probe=True)
    source, staged = await staged_routes_unchanged(db, record)
    source.agent_id = record.target_agent_id
    source.visibility = record.target_visibility
    source.active = staged.active
    config = source.edge_route_config
    if config is None:
        from app.models.edge_route_config import EdgeRouteConfig
        config = EdgeRouteConfig(route_id=source.id)
        db.add(config)
    config.profile_id = staged.edge_route_config.profile_id
    config.policy_json = deepcopy(staged.edge_route_config.policy_json)
    config.inherit_node_policy = False
    for path in (await db.scalars(select(EdgePathRule).where(EdgePathRule.route_id == source.id))).all():
        path.policy_json = mapped_pools(path.policy_json, record.resource_map["pools"])
    for original in record.original_snapshot["fragments"]:
        clone_id = uuid.UUID(record.resource_map["fragments"][original["id"]])
        if original["route_id"]:
            fragment = await db.get(EdgeFragment, uuid.UUID(original["id"]))
            fragment.agent_id = record.target_agent_id
            fragment.content = mapped_fragment_references(fragment.content, {key: value for key, value in record.resource_map["fragments"].items() if any(item["id"] == key and item["route_id"] is None for item in record.original_snapshot["fragments"])})
            await db.execute(delete(EdgeFragment).where(EdgeFragment.id == clone_id))
        else:
            fragment = await db.get(EdgeFragment, clone_id)
            fragment.content = mapped_fragment_references(original["content"], {key: value for key, value in record.resource_map["fragments"].items() if any(item["id"] == key and item["route_id"] is None for item in record.original_snapshot["fragments"])})
    binding = source.public_ingress
    if binding is None:
        binding = HTTPPublicIngress(route_id=source.id)
        db.add(binding)
    binding.attachment_id = record.target_attachment_id
    binding.tunnel_server_ip_id = staged.public_ingress.tunnel_server_ip_id
    binding.public_port = staged.public_ingress.public_port
    binding.active = True
    record.stage_route_id = None
    await db.execute(delete(HTTPRoute).where(HTTPRoute.id == staged.id))
    record.phase = "switched"
    record.revision += 1
    await db.flush()
    source = await load_route(db, source.id)
    record.switched_fingerprint = desired_hash(await route_bundle(db, source))
    await db.commit()
    versions = {}
    for agent_id in (record.target_agent_id, record.source_agent_id):
        _, version, command_id = await dispatched_version(db, agent_id, actor)
        versions[str(agent_id)] = {"version_id": str(version.id), "command_id": str(command_id), "desired_hash": version.desired_hash}
    record.final_version_ids = versions
    await db.commit()
    return record


def restore_fields(row, model, values, excluded):
    for key, value in copied_fields(model, values, excluded).items():
        setattr(row, key, value)


async def rollback(db, record, actor):
    if record.phase not in {"switched", "completed"}:
        fail("Only a switched migration can be rolled back")
    route = await load_route(db, record.source_route_id, lock=True)
    if route.agent_id != record.target_agent_id or desired_hash(await route_bundle(db, route)) != record.switched_fingerprint:
        fail("The migrated route or its resources changed; rollback would overwrite those changes")
    original = record.original_snapshot
    source_node = await db.get(EdgeNode, record.source_agent_id)
    source_policy = await db.get(EdgeNodePolicy, record.source_agent_id)
    if source_node is None or source_node.edge_state != "enabled" or source_node.edge_mode != "security_edge" or row_values(source_policy) != original["node_policy"] or [source_node.edge_rate_limit_rps, source_node.edge_rate_limit_burst] != original["node_rate"]:
        fail("The original VPS policy changed or Security Edge is disabled")
    for resource, model in ((original["profile"], EdgeProfile), *((pool, EdgeUpstreamPool) for pool in original["pools"])):
        if resource and row_values(await db.get(model, uuid.UUID(resource["id"]))) != resource:
            fail("An original profile or upstream pool changed; rollback cannot preserve the saved policy")
    for resource in original["fragments"]:
        if resource["route_id"] is None and row_values(await db.get(EdgeFragment, uuid.UUID(resource["id"]))) != resource:
            fail("An original node fragment changed; rollback cannot preserve the saved policy")
    restore_fields(route, HTTPRoute, original["route"], {"id"})
    from app.models.edge_route_config import EdgeRouteConfig
    if original["config"]:
        restore_fields(route.edge_route_config, EdgeRouteConfig, original["config"], {"id", "route_id"})
    else:
        await db.execute(delete(EdgeRouteConfig).where(EdgeRouteConfig.route_id == route.id))
    for path in original["paths"]:
        restore_fields(await db.get(EdgePathRule, uuid.UUID(path["id"])), EdgePathRule, path, {"id", "route_id"})
    for fragment in original["fragments"]:
        if fragment["route_id"]:
            restore_fields(await db.get(EdgeFragment, uuid.UUID(fragment["id"])), EdgeFragment, fragment, {"id"})
    if original["ingress"]:
        restore_fields(route.public_ingress, HTTPPublicIngress, original["ingress"], {"route_id"})
    else:
        await db.execute(delete(HTTPPublicIngress).where(HTTPPublicIngress.route_id == route.id))
    record.phase = "rollback_pending"
    record.revision += 1
    await db.flush()
    await remove_unused_clones(db, record)
    await db.commit()
    versions = {}
    for agent_id in (record.source_agent_id, record.target_agent_id):
        _, version, command_id = await dispatched_version(db, agent_id, actor)
        versions[str(agent_id)] = {"version_id": str(version.id), "command_id": str(command_id), "desired_hash": version.desired_hash}
    record.rollback_version_ids = versions
    await db.commit()
    return record


async def remove_unused_clones(db, record):
    from app.models.edge_route_config import EdgeRouteConfig
    for clone_id in record.resource_map.get("profiles", {}).values():
        profile_id = uuid.UUID(clone_id)
        used = await db.scalar(select(EdgeRouteConfig.id).where(EdgeRouteConfig.profile_id == profile_id).limit(1))
        default = await db.scalar(select(EdgeNodePolicy.agent_id).where(EdgeNodePolicy.default_profile_id == profile_id).limit(1))
        if not used and not default:
            await db.execute(delete(EdgeProfile).where(EdgeProfile.id == profile_id))
    used_pools = set()
    for model in (EdgeRouteConfig, EdgePathRule, EdgeProfile, EdgeNodePolicy):
        for policy in (await db.scalars(select(model.policy_json))).all():
            used_pools.update(pool_ids(policy))
    for clone_id in record.resource_map.get("pools", {}).values():
        if uuid.UUID(clone_id) not in used_pools:
            await db.execute(delete(EdgeUpstreamPool).where(EdgeUpstreamPool.id == uuid.UUID(clone_id)))
    owned_fragments = {uuid.UUID(item) for item in record.resource_map.get("fragments", {}).values()}
    references = set()
    for route in (await db.scalars(select(HTTPRoute).options(selectinload(HTTPRoute.edge_route_config)).where(HTTPRoute.agent_id == record.target_agent_id))).all():
        policies = [await effective_render_policy(db, route, route.edge_route_config)]
        for path in (await db.scalars(select(EdgePathRule).where(EdgePathRule.route_id == route.id))).all():
            policies.append(await effective_render_policy(db, route, route.edge_route_config, path))
        for policy in policies:
            references.update(policy.get("middlewares") or [])
            if (policy.get("origin") or {}).get("service"):
                references.add(policy["origin"]["service"])
    other_contents = json.dumps([row.content for row in (await db.scalars(select(EdgeFragment).where(EdgeFragment.agent_id == record.target_agent_id, EdgeFragment.id.not_in(owned_fragments)))).all()], sort_keys=True)
    fragments = {clone_id: await db.get(EdgeFragment, clone_id) for clone_id in owned_fragments}
    retained = {clone_id for clone_id, fragment in fragments.items() if fragment and (fragment.name in references or f"fragment-{clone_id}" in other_contents)}
    changed = True
    while changed:
        changed = False
        contents = json.dumps([fragments[item].content for item in retained], sort_keys=True)
        for clone_id, fragment in fragments.items():
            if fragment and clone_id not in retained and f"fragment-{clone_id}" in contents:
                retained.add(clone_id)
                changed = True
    for clone_id, fragment in fragments.items():
        if fragment and clone_id not in retained:
            await db.execute(delete(EdgeFragment).where(EdgeFragment.id == clone_id))


async def cancel(db, record, actor):
    if record.phase not in {"staged", "provisioning"}:
        fail("Only staged or provisioned migrations can be canceled")
    was_provisioned = record.phase == "provisioning"
    if record.stage_route_id:
        stage_id = record.stage_route_id
        record.stage_route_id = None
        await db.flush()
        await db.execute(delete(HTTPRoute).where(HTTPRoute.id == stage_id))
    await remove_unused_clones(db, record)
    record.phase = "cancel_pending" if was_provisioned else "canceled"
    record.revision += 1
    record.final_version_ids = {}
    await db.commit()
    if was_provisioned:
        _, version, command_id = await dispatched_version(db, record.target_agent_id, actor)
        record.final_version_ids = {str(record.target_agent_id): {"version_id": str(version.id), "command_id": str(command_id), "desired_hash": version.desired_hash}}
        await db.commit()
    return record


async def discard(db, record):
    await migration_read(db, record)
    if record.phase not in {"canceled", "rolled_back", "completed"}:
        fail("Verify cancellation, migration, or rollback before discarding its history")
    if record.phase in {"completed", "rolled_back"}:
        metadata = record.final_version_ids if record.phase == "completed" else record.rollback_version_ids
        from app.services.edge_ops import build_edge_desired_state
        for agent_id, acknowledgement in metadata.items():
            current = desired_hash(await build_edge_desired_state(uuid.UUID(agent_id), db))
            if current != acknowledgement["desired_hash"] or not await command_applied(db, uuid.UUID(agent_id), uuid.UUID(acknowledgement["command_id"]), uuid.UUID(acknowledgement["version_id"]), current):
                fail("Current migration or rollback configuration is no longer verified")
    await remove_unused_clones(db, record)
    await db.delete(record)
    await db.commit()


async def migration_read(db, record):
    versions = record.rollback_version_ids if record.phase == "rollback_pending" else record.final_version_ids
    applied = bool(versions)
    from app.services.edge_ops import build_edge_desired_state
    for agent_id, metadata in versions.items():
        version = await db.get(EdgeConfigVersion, uuid.UUID(metadata["version_id"]))
        try:
            current = desired_hash(await build_edge_desired_state(uuid.UUID(agent_id), db))
        except (HTTPException, ValueError):
            current = None
        applied = applied and version is not None and str(version.agent_id) == agent_id and version.desired_hash == current and version.applied_at is not None and version.agent_result == "applied" and await command_applied(db, uuid.UUID(agent_id), uuid.UUID(metadata["command_id"]), version.id, current)
    if applied and record.phase in {"switched", "rollback_pending", "cancel_pending"}:
        record.phase = {"switched": "completed", "rollback_pending": "rolled_back", "cancel_pending": "canceled"}[record.phase]
        record.revision += 1
        await db.commit()
    readiness = False
    stage_applied = False
    readiness_detail = None
    probe_status = "not_run"
    if record.phase == "provisioning":
        try:
            await stage_gate(db, record)
            stage_applied = True
        except HTTPException as exc:
            readiness_detail = exc.detail
        if record.test_command_id:
            command = await db.get(CommandLog, record.test_command_id)
            probe_status = "pending" if command is not None and command.success is None else "failed"
            if not stage_applied:
                probe_status = "stale"
        if stage_applied:
            try:
                await stage_gate(db, record, probe=True)
                readiness = True
                probe_status = "verified"
            except HTTPException as exc:
                readiness_detail = exc.detail
    route = await db.get(HTTPRoute, record.source_route_id)
    return {"id": str(record.id), "source_route_id": str(record.source_route_id), "source_agent_id": str(record.source_agent_id), "target_agent_id": str(record.target_agent_id), "target_attachment_id": str(record.target_attachment_id), "stage_route_id": str(record.stage_route_id) if record.stage_route_id else None, "domain": route.domain if route else None, "phase": record.phase, "revision": record.revision, "visibility": record.target_visibility, "stage_desired_hash": record.stage_desired_hash, "stage_version_id": str(record.stage_version_id) if record.stage_version_id else None, "test_command_id": str(record.test_command_id) if record.test_command_id else None, "ready_to_switch": readiness, "stage_applied": stage_applied, "probe_status": probe_status, "readiness_detail": readiness_detail, "runtime_verified": applied, "last_error": record.last_error, "effective_policy": redacted(record.original_snapshot["effective"]), "prerequisites": ["Both nodes must acknowledge the selected configuration", "Gateway TLS, origin, and route probes must pass before public switch", "Private ACME stores are not transferred", "LAN client routing and DNS must be configured separately"]}

"""Import HTTP routes through the same owner and exposure checks as the editor."""
import ipaddress
import uuid
import tomllib

import yaml

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tunnel_server import TunnelServer
from app.schemas.edge import EdgeRouteUpsert, NodeTraefikImportRequest
from app.schemas.security import TraefikImportResult
from app.schemas.system_settings import valid_dns_name
from app.services.edge_ownership import get_edge_owner, is_gateway_edge, load_http_routes
from app.services.traefik_importer import HOST_RE, _parse_import_request_config, preview_traefik_config


def _route_request(body, imported):
    policy = dict(imported.mapped_policy)
    policy["tls_source"] = imported.tls_source
    fields = dict(
        domain=imported.domain, destination_ip=imported.destination_ip,
        destination_port=imported.destination_port, enabled=body.activate,
        visibility=imported.visibility, attachment_id=body.attachment_id, policy=policy,
        upstream_scheme=imported.upstream_scheme,
        upstream_insecure_skip_verify=imported.upstream_insecure_skip_verify,
    )
    if "tunnel_server_ip_id" in body.model_fields_set:
        fields["tunnel_server_ip_id"] = body.tunnel_server_ip_id
    return EdgeRouteUpsert(**fields)


async def preview_node_import(agent_id: uuid.UUID, body: NodeTraefikImportRequest, db: AsyncSession):
    await get_edge_owner(db, agent_id)
    gateway = await is_gateway_edge(db, agent_id)
    server = await db.scalar(select(TunnelServer).where(TunnelServer.agent_id == agent_id))
    if body.server_id is not None and (server is None or body.server_id != server.id):
        raise HTTPException(400, "Import server_id must identify the node in the request URL")
    if not gateway and body.visibility not in {None, "public_only"}:
        raise HTTPException(409, "VPS routes support public visibility only")
    routes = await load_http_routes(db, agent_id)
    existing, duplicate = {}, set()
    for route in routes:
        name = route.domain.lower().rstrip(".")
        if name in existing:
            duplicate.add(name)
        existing[name] = route.id
    try:
        config = _parse_import_request_config(body)
        preview = preview_traefik_config(config, existing, overwrite=body.overwrite)
    except (ValueError, yaml.YAMLError, tomllib.TOMLDecodeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    seen = set()
    existing_visibility = {route.id: route.visibility for route in routes}
    source_routers = (config.get("http") or {}).get("routers") or {}
    for route in preview.routes:
        if route.domain:
            route.domain = route.domain.lower().rstrip(".")
            route.existing_site_id = existing.get(route.domain)
        if not route.domain or not valid_dns_name(route.domain):
            route.importable = False
            route.warnings.append("A managed route requires one valid DNS hostname")
        if route.domain in duplicate or route.domain in seen:
            route.importable = False
            route.warnings.append("Multiple routes use this hostname. Resolve the ambiguity before importing")
        seen.add(route.domain)
        try:
            target = ipaddress.ip_address(route.destination_ip or "")
            valid_target = not (target.is_unspecified or target.is_multicast)
        except ValueError:
            valid_target = False
        if not valid_target:
            route.importable = False
            route.warnings.append("The managed upstream requires a unicast IP address")
        if route.existing_site_id and not body.overwrite:
            route.importable = False
        route.visibility = body.visibility or existing_visibility.get(route.existing_site_id) or ("lan_only" if gateway else "public_only")
        route.managed_entrypoints = (["lan", "lansecure"] if route.visibility in {"lan_only", "both"} else []) + (["web", "websecure"] if route.visibility in {"public_only", "both"} else [])
        route.action = "update" if route.existing_site_id else "create"
        source_rule = str(source_routers[route.router_name].get("rule") or "").strip()
        if not HOST_RE.fullmatch(source_rule) or any("multiple Host()" in warning or "not modelled" in warning or "not found" in warning or "multiple upstream servers" in warning for warning in route.warnings):
            route.importable = False
            route.warnings.append("This import would discard routing or middleware behavior. Convert it to managed resources before importing")
        route.warnings.append("Imported entrypoints are replaced by the route's managed visibility")
        if route.importable:
            from app.routers.nodes import _upsert_node_route
            # Roll back the editor's validation render. Preview sends no commands.
            savepoint = await db.begin_nested()
            try:
                await _upsert_node_route(agent_id, route.domain if route.existing_site_id else None,
                                         _route_request(body, route), db, None, commit=False,
                                         route_id=route.existing_site_id)
            except HTTPException as exc:
                route.importable = False
                route.warnings.append(f"Managed route validation failed: {exc.detail}")
            finally:
                await savepoint.rollback()
        if not route.importable:
            route.action = "skip"
    preview.summary.importable = sum(route.importable for route in preview.routes)
    preview.summary.skipped = len(preview.routes) - preview.summary.importable
    preview.summary.existing = sum(route.existing_site_id is not None for route in preview.routes)
    return preview


async def apply_node_import(agent_id: uuid.UUID, body: NodeTraefikImportRequest, db: AsyncSession, actor):
    from app.routers.nodes import _upsert_node_route
    from app.models.http_route import HTTPRoute
    from app.services.edge_ops import dispatch_edge_desired_state
    from app.realtime.events import emit_edge_changed, emit_security_changed
    preview = await preview_node_import(agent_id, body, db)
    gateway = await is_gateway_edge(db, agent_id)
    created = updated = 0
    for imported in preview.routes:
        if not imported.importable:
            continue
        existing = await db.get(HTTPRoute, imported.existing_site_id) if imported.existing_site_id else None
        route = await _upsert_node_route(agent_id, imported.domain if existing else None,
                                        _route_request(body, imported), db, actor, commit=False,
                                        route_id=existing.id if existing else None)
        ec = route.edge_route_config
        ec.imported_router_name = imported.router_name
        ec.imported_service_name = imported.service_name
        ec.imported_middlewares = imported.middlewares
        ec.import_warnings = imported.warnings
        if existing:
            updated += 1
        else:
            route.description = f"Imported from Traefik router {imported.router_name}"
            created += 1
    await db.commit()
    await dispatch_edge_desired_state(agent_id, db, actor_user_id=actor.id)
    emit_edge_changed()
    emit_security_changed()
    return TraefikImportResult(**preview.model_dump(), created=created, updated=updated, skipped=preview.summary.skipped)

from __future__ import annotations

import uuid
import json

import pytest
from sqlalchemy import select
from fastapi import HTTPException

from app.models.edge_node import EdgeNode
from app.models.edge_node_policy import EdgeNodePolicy
from app.models.edge_profile import EdgeProfile
from app.models.edge_route_config import EdgeRouteConfig
from app.models.edge_path_rule import EdgePathRule
from app.models.edge_upstream_pool import EdgeUpstreamPool
from app.models.edge_fragment import EdgeFragment
from app.models.http_route import HTTPRoute
from app.services.edge_cache_ops import build_nginx_cache_config
from app.services.edge_render import path_match, validate_edge_configuration
from app.services.traefik_ops import build_traefik_dynamic_config


async def setup_route(db, factories, gateway=True, **config):
    node = await factories.make_client(db) if gateway else await factories.make_server(db)
    if gateway:
        db.add(EdgeNode(agent_id=node.agent_id, edge_mode="security_edge", edge_state="enabled", lan_bind_ip=node.lan_ip))
    route = HTTPRoute(id=uuid.uuid4(), agent_id=node.agent_id, domain="app.example.test",
                      destination_ip="192.168.1.5", destination_port=8080,
                      visibility="lan_only" if gateway else "public_only")
    db.add(route)
    await db.flush()
    db.add(EdgeRouteConfig(route_id=route.id, **config))
    await db.commit()
    return node, route


@pytest.mark.asyncio
async def test_inheritance_paths_pool_and_disabled_resources_render(session_maker, factories):
    async with session_maker() as db:
        node, route = await setup_route(db, factories, waf_mode="block", rate_limit_rps=3)
        profile = EdgeProfile(id=uuid.uuid4(), name="Base", slug="base", policy_json={"headers": {"customResponseHeaders": {"X-Profile": "yes"}}, "rate_limit": {"requests": 12}})
        pool = EdgeUpstreamPool(id=uuid.uuid4(), agent_id=node.agent_id, name="origin", servers=[{"url": "http://192.168.1.11:80"}, {"url": "http://192.168.1.12:80"}], health_check={"path": "/health", "interval": "10s"})
        db.add_all([profile, pool])
        await db.flush()
        db.add(EdgeNodePolicy(agent_id=node.agent_id, default_profile_id=profile.id, policy_json={"headers": {"customRequestHeaders": {"X-Node": "yes"}}}))
        path = EdgePathRule(id=uuid.uuid4(), route_id=route.id, name="api", match={"path_prefix": "/api"}, priority=12345, policy_json={"waf_mode": "observe", "rate_limit": {"requests": 2}, "origin": {"upstream_pool_id": str(pool.id)}})
        db.add_all([path, EdgePathRule(route_id=route.id, name="disabled", enabled=False, match={"path_prefix": "/disabled"}, policy_json={"waf_mode": "invalid"})])
        await db.commit()
        cfg = (await build_traefik_dynamic_config(node.agent_id, db))["http"]
        root = cfg["routers"]["app-example-test"]
        api_name = f"app-example-test-path-{path.id}"
        api = cfg["routers"][api_name]
        assert root["entryPoints"] == api["entryPoints"] == ["lansecure"]
        assert api["rule"] == "Host(`app.example.test`) && (PathPrefix(`/api`))"
        assert api["priority"] == 12345
        assert root["priority"] == 1
        assert len(cfg["routers"]) == 2
        assert cfg["middlewares"]["ratelimit-app-example-test"]["rateLimit"]["average"] == 12
        assert cfg["middlewares"][f"ratelimit-{api_name}"]["rateLimit"]["average"] == 2
        assert cfg["middlewares"]["headers-app-example-test"]["headers"]["customRequestHeaders"] == {"X-Node": "yes"}
        assert cfg["middlewares"]["headers-app-example-test"]["headers"]["customResponseHeaders"] == {"X-Profile": "yes"}
        lb = cfg["services"][api["service"]]["loadBalancer"]
        assert lb["servers"] == pool.servers
        assert lb["healthCheck"] == pool.health_check
        observer = cfg["middlewares"]["crowdsec-observe-waf"]["plugin"]["bouncer"]
        blocker = cfg["middlewares"]["crowdsec-bouncer"]["plugin"]["bouncer"]
        assert observer["crowdsecMode"] == "appsec"
        assert observer["crowdsecAppsecHost"] == "127.0.0.1:7423"
        assert blocker["crowdsecMode"] == "stream"
        assert blocker["crowdsecAppsecHost"] == "127.0.0.1:7422"


@pytest.mark.asyncio
async def test_flat_legacy_and_denyip_alias_remain_effective(session_maker, factories):
    async with session_maker() as db:
        node, _ = await setup_route(db, factories, gateway=False, ip_deny=["192.0.2.0/24"], upstream_scheme="https", upstream_insecure_skip_verify=True)
        http = (await build_traefik_dynamic_config(node.agent_id, db))["http"]
        assert http["middlewares"]["ipdeny-app-example-test"] == {"plugin": {"denyip": {"ipDenyList": ["192.0.2.0/24"]}}}
        lb = http["services"]["svc-app-example-test"]["loadBalancer"]
        assert lb["servers"][0]["url"] == "https://192.168.1.5:8080"
        assert lb["serversTransport"] == "wirewarp-insecure-skip-verify"
        assert http["routers"]["app-example-test"]["entryPoints"] == ["websecure"]


@pytest.mark.asyncio
async def test_observe_waf_keeps_antibot_as_separate_policy(session_maker, factories):
    async with session_maker() as db:
        node, _ = await setup_route(db, factories, waf_mode="observe", antibot=True)
        http = (await build_traefik_dynamic_config(node.agent_id, db))["http"]
        names = http["routers"]["app-example-test"]["middlewares"]
        assert names == ["crowdsec-observe-antibot", "crowdsec-antibot"]
        assert http["middlewares"][names[0]]["plugin"]["bouncer"]["crowdsecMode"] == "appsec"
        bot = http["middlewares"][names[1]]["plugin"]["bouncer"]
        assert bot["crowdsecMode"] == "stream" and bot["crowdsecAppsecEnabled"] is False


@pytest.mark.asyncio
async def test_fragments_attach_only_when_enabled_valid_and_owned(session_maker, factories):
    async with session_maker() as db:
        node, route = await setup_route(db, factories)
        fragment = EdgeFragment(id=uuid.uuid4(), agent_id=node.agent_id, route_id=route.id, name="headers", fragment_type="middleware", content={"headers": {"customResponseHeaders": {"X-Fragment": "yes"}}})
        db.add_all([fragment, EdgeFragment(agent_id=node.agent_id, name="disabled", fragment_type="router", enabled=False, content={"entryPoints": ["websecure"]}), EdgeFragment(agent_id=node.agent_id, name="invalid", fragment_type="router", validation_state="invalid", content={})])
        await db.commit()
        http = (await build_traefik_dynamic_config(node.agent_id, db))["http"]
        name = f"fragment-{fragment.id}"
        assert name in http["routers"]["app-example-test"]["middlewares"]
        assert http["middlewares"][name] == fragment.content
        assert len(http["routers"]) == 1
        fragment.content = {"entryPoints": ["websecure"]}
        await db.commit()
        with pytest.raises(ValueError, match="inject"):
            await build_traefik_dynamic_config(node.agent_id, db)


@pytest.mark.asyncio
async def test_foreign_profile_pool_and_fragment_refs_rejected(session_maker, factories):
    async with session_maker() as db:
        node, route = await setup_route(db, factories)
        other = await factories.make_client(db)
        pool = EdgeUpstreamPool(id=uuid.uuid4(), agent_id=other.agent_id, name="foreign", servers=[{"url": "http://192.0.2.1"}])
        db.add(pool)
        ec = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.route_id == route.id))
        ec.policy_json = {"origin": {"upstream_pool_id": str(pool.id)}}
        await db.commit()
        with pytest.raises(ValueError, match="pool must belong"):
            await build_traefik_dynamic_config(node.agent_id, db)
        ec.policy_json = {"middlewares": ["foreign"]}
        await db.commit()
        with pytest.raises(ValueError, match="Middleware fragment"):
            await build_traefik_dynamic_config(node.agent_id, db)
        profile = EdgeProfile(id=uuid.uuid4(), name="Foreign", slug="foreign", agent_id=other.agent_id, scope="node", policy_json={})
        db.add(profile)
        ec.policy_json = {}
        ec.profile_id = profile.id
        await db.commit()
        with pytest.raises(ValueError, match="profile must"):
            await build_traefik_dynamic_config(node.agent_id, db)


@pytest.mark.asyncio
async def test_profile_cache_and_route_origin_reach_fixed_local_cache(session_maker, factories):
    async with session_maker() as db:
        node, route = await setup_route(db, factories, policy_json={"origin": {"scheme": "https"}})
        profile = EdgeProfile(id=uuid.uuid4(), name="Cache", slug="cache", policy_json={"cache": {"mode": "proxy_cache", "edge_ttl_seconds": 47, "browser_ttl_seconds": 23}})
        db.add(profile)
        await db.flush()
        db.add(EdgeNodePolicy(agent_id=node.agent_id, default_profile_id=profile.id, policy_json={"cache": {"listen": "0.0.0.0:80"}}))
        await db.commit()
        cache = await build_nginx_cache_config(node.agent_id, db)
        assert cache["listen"] == "127.0.0.1:18080"
        assert cache["routes"][0]["origin_url"] == "https://192.168.1.5:8080"
        assert cache["routes"][0]["edge_ttl_seconds"] == 47
        assert cache["routes"][0]["browser_ttl_seconds"] == 23


@pytest.mark.parametrize("match", [{"entryPoints": ["websecure"]}, {"path_prefix": "/api`) || Host(`bad"}, {}])
def test_unsafe_or_unknown_path_match_rejected(match):
    with pytest.raises(ValueError):
        path_match(match)


def test_existing_typed_path_match_is_supported():
    assert path_match({"type": "prefix", "value": "/login"}) == "PathPrefix(`/login`)"


@pytest.mark.asyncio
async def test_pending_invalid_configuration_returns_422_before_commit(session_maker, factories):
    async with session_maker() as db:
        node, route = await setup_route(db, factories)
        ec = await db.scalar(select(EdgeRouteConfig).where(EdgeRouteConfig.route_id == route.id))
        ec.policy_json = {"unsupported_feature": True}
        await db.flush()
        with pytest.raises(HTTPException) as error:
            await validate_edge_configuration(node.agent_id, db)
        assert error.value.status_code == 422
        assert error.value.detail["code"] == "edge_policy_invalid"
        await db.rollback()
        await db.refresh(ec)
        assert ec.policy_json in (None, {})


@pytest.mark.asyncio
async def test_route_only_cache_enables_backend_and_unsupported_path_fails(session_maker, factories):
    async with session_maker() as db:
        node, route = await setup_route(db, factories, policy_json={"cache": {"mode": "proxy_cache"}})
        cache = await build_nginx_cache_config(node.agent_id, db)
        assert cache["enabled"] and cache["mode"] == "proxy_cache"
        db.add(EdgePathRule(route_id=route.id, name="cached", match={"path_prefix": "/files"}, policy_json={"cache": {"edge_ttl_seconds": 8}}))
        await db.commit()
        with pytest.raises(ValueError, match="Path-specific backend cache"):
            await build_nginx_cache_config(node.agent_id, db)


@pytest.mark.asyncio
async def test_native_renderer_config_proof(session_maker, factories, tmp_path):
    async with session_maker() as db:
        node, route = await setup_route(db, factories, policy_json={
            "headers": {"customResponseHeaders": {"X-Root": "yes"}},
            "origin": {"retry_attempts": 2, "timeout": "5s"},
        })
        pool = EdgeUpstreamPool(id=uuid.uuid4(), agent_id=node.agent_id, name="proof",
                                servers=[{"url": "http://127.0.0.1:8090"}],
                                health_check={"path": "/health", "interval": "10s", "timeout": "1s"})
        db.add(pool)
        await db.flush()
        db.add(EdgePathRule(route_id=route.id, name="pool", match={"path_prefix": "/pool", "method": "GET"}, policy_json={"origin": {"upstream_pool_id": str(pool.id)}}))
        await db.commit()
        config = await build_traefik_dynamic_config(node.agent_id, db)
        proof = tmp_path / "edge-render-proof.json"
        proof.write_text(json.dumps(config))
        print(f"native render proof: {proof}")
        assert config["http"]["routers"]["app-example-test"]["entryPoints"] == ["lansecure"]

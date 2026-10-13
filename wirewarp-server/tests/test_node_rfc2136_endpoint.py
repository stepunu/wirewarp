import importlib.util
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect, text

from app.models.edge_node import EdgeNode
from app.models.system_settings import SystemSettings
from app.routers import settings as settings_router
from app.services.edge_ops import build_edge_desired_state
from app.services.traefik_ops import load_letsencrypt_config
from app.services.edge_config_snapshots import capture_edge_source, restore_edge_source
from tests.test_rfc2136_acme import CONFIG

pytestmark = pytest.mark.asyncio


async def test_override_persists_dispatches_one_node_and_matches_dns_test(client, db, factories, fake_manager, monkeypatch):
    home = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    other = await factories.make_server(db, network="10.22.0.0/24", edge_mode="security_edge", edge_state="enabled")
    fake_manager.online.update((str(home.agent_id), str(other.agent_id)))
    assert (await client.patch("/api/settings", json=CONFIG)).status_code == 200
    fake_manager.sent.clear()
    endpoint = f"/api/nodes/{home.agent_id}/edge/capabilities"
    response = await client.put(endpoint, json={"rfc2136_nameserver_override": "10.50.30.53"})
    assert response.status_code == 200, response.text
    assert response.json()["rfc2136_nameserver_override"] == "10.50.30.53:53"
    assert response.json()["rfc2136_effective_nameserver"] == "10.50.30.53:53"
    assert {item["agent_id"] for item in fake_manager.sent} == {str(home.agent_id)}
    desired = (await build_edge_desired_state(home.agent_id, db))["traefik_acme"]
    assert desired["rfc2136_nameserver"] == "10.50.30.53:53"
    assert (await build_edge_desired_state(other.agent_id, db))["traefik_acme"]["rfc2136_nameserver"] == "ns1.step1.ro:53"
    monkeypatch.setattr(settings_router, "manager", fake_manager)
    probe = await client.post("/api/settings/acme/test", json={"agent_id": str(home.agent_id), "domain": "step1.ro"})
    assert probe.status_code == 200, probe.text
    assert fake_manager.sent[-1]["message"]["params"]["credentials"] == desired
    await db.refresh(await db.get(EdgeNode, home.agent_id))
    assert (await client.get(endpoint)).json()["rfc2136_nameserver_override"] == "10.50.30.53:53"
    global_update = await client.patch("/api/settings", json={"letsencrypt_rfc2136_nameserver": "ns2.step1.ro"})
    assert global_update.status_code == 200
    assert (await build_edge_desired_state(home.agent_id, db))["traefik_acme"]["rfc2136_nameserver"] == "10.50.30.53:53"
    assert (await build_edge_desired_state(other.agent_id, db))["traefik_acme"]["rfc2136_nameserver"] == "ns2.step1.ro:53"
    assert (await client.put(endpoint, json={})).json()["rfc2136_nameserver_override"] == "10.50.30.53:53"
    cleared = await client.put(endpoint, json={"rfc2136_nameserver_override": None})
    assert cleared.status_code == 200
    assert cleared.json()["rfc2136_nameserver_override"] is None
    assert cleared.json()["rfc2136_effective_nameserver"] == "ns2.step1.ro:53"
    assert (await build_edge_desired_state(home.agent_id, db))["traefik_acme"]["rfc2136_nameserver"] == "ns2.step1.ro:53"


@pytest.mark.parametrize("value", ["", "https://ns1.step1.ro", "ns1.step1.ro:0", "ns1.step1.ro:65536", "::1", "bad host", "10.50.30.53\n"])
async def test_invalid_override_has_no_storage_or_dispatch(client, db, factories, fake_manager, value):
    server = await factories.make_server(db)
    response = await client.put(f"/api/nodes/{server.agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": value})
    assert response.status_code == 422
    assert (await db.get(EdgeNode, server.agent_id)).rfc2136_nameserver_override is None
    assert fake_manager.sent == []


@pytest.mark.parametrize("value,expected", [("ns1.example.test", "ns1.example.test:53"), ("[2001:db8::53]", "[2001:db8::53]:53"), ("10.50.30.53:5353", "10.50.30.53:5353")])
async def test_valid_override_can_be_saved_before_edge_enable(client, factories, db, value, expected):
    server = await factories.make_server(db)
    response = await client.put(f"/api/nodes/{server.agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": value})
    assert response.status_code == 200, response.text
    assert response.json()["rfc2136_nameserver_override"] == expected


async def test_override_operator_cannot_change(operator_client, db, factories):
    server = await factories.make_server(db)
    path = f"/api/nodes/{server.agent_id}/edge/capabilities"
    assert (await operator_client.put(path, json={"rfc2136_nameserver_override": "10.50.30.53"})).status_code == 403
    assert (await operator_client.get(path)).status_code == 200


async def test_override_viewer_cannot_change(viewer_client, db, factories):
    server = await factories.make_server(db)
    assert (await viewer_client.put(f"/api/nodes/{server.agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": "10.50.30.53"})).status_code == 403


async def test_plain_client_cannot_set_override(client, db, factories):
    plain = await factories.make_client(db, is_gateway=False)
    assert (await client.put(f"/api/nodes/{plain.agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": "10.50.30.53"})).status_code == 409


async def test_node_readiness_uses_override_without_global_endpoint(client, db, factories):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    assert (await client.patch("/api/settings", json=CONFIG)).status_code == 200
    assert (await client.put(f"/api/nodes/{server.agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": "10.50.30.53"})).status_code == 200
    settings = await db.get(SystemSettings, 1)
    settings.letsencrypt_rfc2136_nameserver = None
    await db.commit()
    assert not (await load_letsencrypt_config(db)).complete
    assert (await load_letsencrypt_config(db, server.agent_id)).complete
    payload = await build_edge_desired_state(server.agent_id, db)
    assert payload["traefik_acme"]["rfc2136_nameserver"] == "10.50.30.53:53"
    assert payload["traefik_static_config"]["certificatesResolvers"]["wirewarp-le"]["acme"]["dnsChallenge"]["resolvers"] == ["1.1.1.1:53"]
    origin = await factories.make_client(db)
    attachment = await factories.make_attachment(db, client=origin, server=server)
    route = await client.post(f"/api/nodes/{server.agent_id}/edge/routes", json={"domain": "override.example.test", "attachment_id": str(attachment.id), "destination_ip": "192.0.2.10", "destination_port": 8080})
    assert route.status_code == 201, route.text
    routers = (await build_edge_desired_state(server.agent_id, db))["traefik_dynamic_config"]["http"]["routers"]
    assert any(router.get("tls", {}).get("certResolver") == "wirewarp-le" for router in routers.values())


async def test_gateway_override_delivers_same_endpoint_without_attachment(client, db, factories, fake_manager, monkeypatch):
    gateway = await factories.make_client(db, vm_network="192.168.20.0/24", lan_ip="192.168.20.110")
    fake_manager.online.add(str(gateway.agent_id))
    assert (await client.patch("/api/settings", json=CONFIG)).status_code == 200
    path = f"/api/nodes/{gateway.agent_id}/edge/capabilities"
    assert (await client.put(path, json={"rfc2136_nameserver_override": "10.50.30.53"})).status_code == 200
    assert (await client.post(f"/api/nodes/{gateway.agent_id}/edge/enable")).status_code == 202
    desired = await build_edge_desired_state(gateway.agent_id, db)
    assert desired["traefik_acme"]["rfc2136_nameserver"] == "10.50.30.53:53"
    monkeypatch.setattr(settings_router, "manager", fake_manager)
    response = await client.post("/api/settings/acme/test", json={"agent_id": str(gateway.agent_id), "domain": "step1.ro"})
    assert response.status_code == 200, response.text
    assert fake_manager.sent[-1]["message"]["params"]["credentials"] == desired["traefik_acme"]


async def test_override_does_not_replace_cloudflare_credentials(client, db, factories):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    assert (await client.put(f"/api/nodes/{server.agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": "10.50.30.53"})).status_code == 200
    assert (await client.patch("/api/settings", json={"letsencrypt_enabled": True, "letsencrypt_email": "admin@example.test", "letsencrypt_dns_provider": "cloudflare", "letsencrypt_cloudflare_api_token": "synthetic-cloudflare-token"})).status_code == 200
    assert (await build_edge_desired_state(server.agent_id, db))["traefik_acme"] == {"cloudflare_dns_api_token": "synthetic-cloudflare-token"}


async def test_node_config_snapshot_restores_override_without_shared_credentials(client, db, factories):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    assert (await client.put(f"/api/nodes/{server.agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": "10.50.30.53"})).status_code == 200
    snapshot = await capture_edge_source(server.agent_id, db)
    assert snapshot["node"]["rfc2136_nameserver_override"] == "10.50.30.53:53"
    assert "tsig" not in str(snapshot)
    node = await db.get(EdgeNode, server.agent_id)
    node.rfc2136_nameserver_override = None
    await db.commit()
    await restore_edge_source(SimpleNamespace(id=uuid.uuid4(), agent_id=server.agent_id, source_snapshot=snapshot), db)
    await db.commit()
    assert node.rfc2136_nameserver_override == "10.50.30.53:53"


async def test_historical_node_snapshot_restores_global_endpoint_inheritance(client, db, factories):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    agent_id = server.agent_id
    snapshot = await capture_edge_source(agent_id, db)
    snapshot["node"].pop("rfc2136_nameserver_override")
    assert (await client.put(f"/api/nodes/{agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": "10.50.30.53"})).status_code == 200
    await restore_edge_source(SimpleNamespace(id=uuid.uuid4(), agent_id=agent_id, source_snapshot=snapshot), db)
    await db.commit()
    node = await db.get(EdgeNode, agent_id)
    assert node.rfc2136_nameserver_override is None


async def test_failed_capability_validation_does_not_save_partial_override(client, db, factories, fake_manager):
    server = await factories.make_server(db)
    response = await client.put(f"/api/nodes/{server.agent_id}/edge/capabilities", json={"rfc2136_nameserver_override": "10.50.30.53", "lan_bind_ip": "invalid"})
    assert response.status_code == 422
    assert (await db.get(EdgeNode, server.agent_id)).rfc2136_nameserver_override is None
    assert fake_manager.sent == []


async def test_endpoint_migration_preserves_populated_rows_and_downgrade_guard(monkeypatch):
    path = Path(__file__).parents[1] / "alembic/versions/0047_node_rfc2136_endpoint.py"
    spec = importlib.util.spec_from_file_location("node_endpoint_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE edge_nodes (agent_id TEXT PRIMARY KEY, edge_mode TEXT, edge_state TEXT)"))
        connection.execute(text("INSERT INTO edge_nodes VALUES ('home', 'security_edge', 'enabled')"))
        monkeypatch.setattr(migration, "op", Operations(MigrationContext.configure(connection)))
        migration.upgrade()
        row = connection.execute(text("SELECT * FROM edge_nodes")).mappings().one()
        assert dict(row) == {"agent_id": "home", "edge_mode": "security_edge", "edge_state": "enabled", "rfc2136_nameserver_override": None}
        connection.execute(text("UPDATE edge_nodes SET rfc2136_nameserver_override='10.50.30.53:53'"))
        with pytest.raises(RuntimeError, match="Clear node RFC2136"):
            migration.downgrade()
        assert connection.execute(text("SELECT rfc2136_nameserver_override FROM edge_nodes")).scalar_one() == "10.50.30.53:53"
        connection.execute(text("UPDATE edge_nodes SET rfc2136_nameserver_override=NULL"))
        migration.downgrade()
        assert {column["name"] for column in inspect(connection).get_columns("edge_nodes")} == {"agent_id", "edge_mode", "edge_state"}
        assert connection.execute(text("SELECT edge_mode FROM edge_nodes")).scalar_one() == "security_edge"
    engine.dispose()

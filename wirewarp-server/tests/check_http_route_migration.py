"""Run the populated migration check against a disposable localhost database.

Run with DATABASE_URL pointing to the empty wirewarp_schema test database.
This check uses PostgreSQL rather than the SQLite unit-test fixtures.
"""
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

import asyncpg


ROOT = Path(__file__).resolve().parents[1]
OLD = "0040_rfc2136_acme_settings"
NEW = "0046_site_link_generations"


def migrate(direction, revision, *, fails=False):
    started = time.monotonic()
    print(f"Running {direction} {revision}; expected refusal: {fails}", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "alembic", direction, revision], cwd=ROOT,
        capture_output=True, text=True, timeout=60,
    )
    print(f"Finished in {time.monotonic() - started:.1f}s", flush=True)
    if fails:
        assert result.returncode != 0, "Unsafe downgrade unexpectedly succeeded"
    elif result.returncode:
        raise AssertionError(result.stderr)


async def check():
    url = os.environ["DATABASE_URL"]
    parsed = urlparse(url)
    if parsed.hostname != "127.0.0.1" or parsed.path != "/wirewarp_schema":
        raise ValueError("Use only the disposable localhost wirewarp_schema database")
    migrate("upgrade", OLD)
    db = await asyncpg.connect(url.replace("postgresql+asyncpg://", "postgresql://"))
    try:
        assert await db.fetchval("SELECT count(*) FROM agents") == 0, "Test database must be empty"
        ids = {name: uuid.uuid4() for name in ("server_agent", "gateway_agent", "server", "gateway", "attachment", "http", "raw", "config", "rule", "fragment")}
        await db.execute("INSERT INTO agents(id,name,type) VALUES($1,'schema-server','server'),($2,'schema-gateway','client')", ids["server_agent"], ids["gateway_agent"])
        await db.execute("INSERT INTO tunnel_servers(id,agent_id,edge_mode,edge_state,edge_install_phase,edge_rate_limit_rps) VALUES($1,$2,'security_edge','enabled','healthy',37)", ids["server"], ids["server_agent"])
        await db.execute("INSERT INTO tunnel_clients(id,agent_id,is_gateway) VALUES($1,$2,true)", ids["gateway"], ids["gateway_agent"])
        await db.execute("INSERT INTO tunnel_client_attachments(id,tunnel_client_id,tunnel_server_id,tunnel_ip,wg_interface,fwmark,route_table_id) VALUES($1,$2,$3,'10.21.0.10','wg0',257,100)", ids["attachment"], ids["gateway"], ids["server"])
        for kind, port in (("http", 443), ("raw", 2222)):
            await db.execute("INSERT INTO port_forwards(id,attachment_id,protocol,public_port,destination_ip,destination_port,active,service_kind,domain) VALUES($1,$2,'tcp',$3,'192.168.20.3',80,true,$4,$5)", ids[kind], ids["attachment"], port, kind, "app.example.test" if kind == "http" else None)
        await db.execute("INSERT INTO edge_route_configs(id,port_forward_id,waf_mode,policy_json) VALUES($1,$2,'block','{\"waf_mode\":\"block\"}')", ids["config"], ids["http"])
        await db.execute("INSERT INTO edge_path_rules(id,route_id,name) VALUES($1,$2,'admin')", ids["rule"], ids["http"])
        await db.execute("INSERT INTO edge_fragments(id,agent_id,route_id,name,fragment_type) VALUES($1,$2,$3,'custom','middleware')", ids["fragment"], ids["server_agent"], ids["http"])
        await db.execute("INSERT INTO edge_access_events(agent_id,route_id) VALUES($1,$2)", ids["server_agent"], ids["http"])
        raw_before = dict(await db.fetchrow("SELECT * FROM port_forwards WHERE id=$1", ids["raw"]))
        raw_bytes_before = await db.fetchval("SELECT to_jsonb(row)::text FROM port_forwards row WHERE id=$1", ids["raw"])
        config_before = dict(await db.fetchrow("SELECT * FROM edge_route_configs WHERE id=$1", ids["config"]))

        async def assert_upgrade():
            assert await db.fetchval("SELECT count(*) FROM information_schema.columns WHERE table_name='tunnel_servers' AND column_name='edge_state'") == 0
            assert await db.fetchval("SELECT relay_enabled FROM edge_nodes WHERE agent_id=$1", ids["server_agent"]) is False
            assert await db.fetchval("SELECT count(*) FROM port_forwards") == 1
            assert dict(await db.fetchrow("SELECT * FROM port_forwards WHERE id=$1", ids["raw"])) == raw_before
            assert await db.fetchval("SELECT to_jsonb(row)::text FROM port_forwards row WHERE id=$1", ids["raw"]) == raw_bytes_before
            route = await db.fetchrow("SELECT * FROM http_routes WHERE id=$1", ids["http"])
            assert route["agent_id"] == ids["server_agent"] and route["visibility"] == "public_only"
            assert await db.fetchval("SELECT edge_rate_limit_rps FROM edge_nodes WHERE agent_id=$1", ids["server_agent"]) == 37
            assert await db.fetchval("SELECT attachment_id FROM http_public_ingresses WHERE route_id=$1", ids["http"]) == ids["attachment"]
            config = dict(await db.fetchrow("SELECT * FROM edge_route_configs WHERE id=$1", ids["config"]))
            assert config.pop("inherit_node_policy") is True
            config["port_forward_id"] = config.pop("route_id")
            assert config == config_before
            for table in ("edge_path_rules", "edge_fragments", "edge_access_events"):
                assert await db.fetchval(f"SELECT route_id FROM {table}") == ids["http"]
            rows = await db.fetch("SELECT conrelid::regclass::text AS table_name, confrelid::regclass::text AS target, confdeltype FROM pg_constraint WHERE contype='f' AND conrelid IN ('edge_route_configs'::regclass,'edge_path_rules'::regclass,'edge_fragments'::regclass,'edge_access_events'::regclass) AND confrelid='http_routes'::regclass")
            actions = {row["table_name"]: row["confdeltype"] for row in rows}
            assert actions == {"edge_route_configs": b"c", "edge_path_rules": b"c", "edge_fragments": b"c", "edge_access_events": b"n"}

        migrate("upgrade", "0045_edge_config_snapshot")
        await db.execute("INSERT INTO site_link_agent_states(agent_id,revision,desired_hash,phase) VALUES($1,9,'synthetic-seed-hash','applied')", ids["server_agent"])
        migrate("upgrade", NEW)
        assert await db.fetchval("SELECT revision FROM site_link_agent_generations WHERE agent_id=$1", ids["server_agent"]) == 9
        await db.execute("DELETE FROM site_link_agent_states WHERE agent_id=$1", ids["server_agent"])
        migrate("downgrade", "0045_edge_config_snapshot", fails=True)
        assert await db.fetchval("SELECT version_num FROM alembic_version") == NEW
        assert await db.fetchval("SELECT revision FROM site_link_agent_generations WHERE agent_id=$1", ids["server_agent"]) == 9
        await db.execute("DELETE FROM site_link_agent_generations WHERE agent_id=$1", ids["server_agent"])
        await assert_upgrade()
        snapshot_id = uuid.uuid4()
        await db.execute("INSERT INTO edge_config_versions(id,agent_id,desired_hash,source_snapshot) VALUES($1,$2,'synthetic-config-hash','{\"schema_version\":1}')", snapshot_id, ids["server_agent"])
        migrate("downgrade", OLD, fails=True)
        assert await db.fetchval("SELECT version_num FROM alembic_version") == NEW
        assert await db.fetchval("SELECT source_snapshot IS NOT NULL FROM edge_config_versions WHERE id=$1", snapshot_id)
        await db.execute("DELETE FROM edge_config_versions WHERE id=$1", snapshot_id)
        migration_id = uuid.uuid4()
        await db.execute("INSERT INTO edge_migrations(id,source_route_id,source_agent_id,target_agent_id,target_attachment_id,phase,revision,target_visibility,original_snapshot,source_fingerprint,resource_map,final_version_ids,rollback_version_ids) VALUES($1,$2,$3,$4,$5,'staged',1,'both','{}','synthetic-fingerprint','{}','{}','{}')", migration_id, ids["http"], ids["server_agent"], ids["gateway_agent"], ids["attachment"])
        try:
            await db.execute("DELETE FROM http_routes WHERE id=$1", ids["http"])
        except asyncpg.ForeignKeyViolationError:
            pass
        else:
            raise AssertionError("Migration rollback ownership did not protect its original route")
        migrate("downgrade", OLD, fails=True)
        assert await db.fetchval("SELECT version_num FROM alembic_version") == NEW
        assert await db.fetchval("SELECT revision FROM edge_migrations WHERE id=$1", migration_id) == 1
        await db.execute("DELETE FROM edge_migrations WHERE id=$1", migration_id)
        await db.execute("UPDATE edge_route_configs SET inherit_node_policy=false WHERE id=$1", ids["config"])
        migrate("downgrade", OLD, fails=True)
        assert await db.fetchval("SELECT version_num FROM alembic_version") == NEW
        assert await db.fetchval("SELECT inherit_node_policy FROM edge_route_configs WHERE id=$1", ids["config"]) is False
        await db.execute("UPDATE edge_route_configs SET inherit_node_policy=true WHERE id=$1", ids["config"])
        second_agent, second_gateway, second_attachment, link_id = (uuid.uuid4() for _ in range(4))
        await db.execute("INSERT INTO agents(id,name,type) VALUES($1,'schema-vienna','client')", second_agent)
        await db.execute("INSERT INTO tunnel_clients(id,agent_id,is_gateway) VALUES($1,$2,true)", second_gateway, second_agent)
        await db.execute("INSERT INTO tunnel_client_attachments(id,tunnel_client_id,tunnel_server_id,tunnel_ip,wg_interface,fwmark,route_table_id) VALUES($1,$2,$3,'10.21.0.11','wg0',257,100)", second_attachment, second_gateway, ids["server"])
        await db.execute("INSERT INTO site_links(id,name,site_a_gateway_id,site_b_gateway_id,site_a_attachment_id,site_b_attachment_id,hub_agent_id,site_a_subnets,site_b_subnets,direction,snat_at_a,snat_at_b,access_rules,enabled,revision) VALUES($1,'Home to Vienna',$2,$3,$4,$5,$6,'[\"192.168.20.0/24\"]','[\"192.168.0.0/24\"]','a_to_b',true,true,'[]',true,7)", link_id, ids["gateway_agent"], second_agent, ids["attachment"], second_attachment, ids["server_agent"])
        await db.execute("INSERT INTO site_link_agent_states(agent_id,revision,desired_hash,phase) VALUES($1,9,'synthetic-hash','pending')", ids["server_agent"])
        migrate("downgrade", OLD, fails=True)
        assert await db.fetchval("SELECT version_num FROM alembic_version") == NEW
        assert await db.fetchval("SELECT revision FROM site_links WHERE id=$1", link_id) == 7
        await db.execute("DELETE FROM site_links WHERE id=$1", link_id)
        migrate("downgrade", OLD, fails=True)
        assert await db.fetchval("SELECT revision FROM site_link_agent_states WHERE agent_id=$1", ids["server_agent"]) == 9
        await db.execute("DELETE FROM site_link_agent_states WHERE agent_id=$1", ids["server_agent"])
        await db.execute("UPDATE edge_nodes SET relay_enabled=true WHERE agent_id=$1", ids["server_agent"])
        migrate("downgrade", OLD, fails=True)
        assert await db.fetchval("SELECT version_num FROM alembic_version") == NEW
        await db.execute("UPDATE edge_nodes SET relay_enabled=false WHERE agent_id=$1", ids["server_agent"])
        migrate("downgrade", OLD)
        assert await db.fetchval("SELECT count(*) FROM port_forwards") == 2
        assert dict(await db.fetchrow("SELECT * FROM port_forwards WHERE id=$1", ids["raw"])) == raw_before
        assert await db.fetchval("SELECT to_jsonb(row)::text FROM port_forwards row WHERE id=$1", ids["raw"]) == raw_bytes_before
        assert dict(await db.fetchrow("SELECT * FROM edge_route_configs WHERE id=$1", ids["config"])) == config_before
        migrate("upgrade", NEW)
        await assert_upgrade()
        lan_id = uuid.uuid4()
        await db.execute("INSERT INTO http_routes(id,agent_id,domain,destination_ip,destination_port,visibility) VALUES($1,$2,'lan.example.test','192.168.20.5',80,'lan_only')", lan_id, ids["gateway_agent"])
        migrate("downgrade", OLD, fails=True)
        assert await db.fetchval("SELECT version_num FROM alembic_version") == NEW
        assert await db.fetchval("SELECT count(*) FROM http_routes WHERE id=$1", lan_id) == 1
        await db.execute("DELETE FROM http_routes WHERE id=$1", lan_id)
        migrate("downgrade", OLD)
        await db.execute("INSERT INTO edge_route_configs(id,port_forward_id) VALUES($1,$2)", uuid.uuid4(), ids["raw"])
        migrate("upgrade", NEW, fails=True)
        assert await db.fetchval("SELECT version_num FROM alembic_version") == OLD
        assert await db.fetchval("SELECT to_regclass('http_routes')") is None
        assert await db.fetchval("SELECT count(*) FROM port_forwards") == 2
        print("Populated PostgreSQL0040→0046→0040→0046 passed: raw JSON bytes, route/policy UUIDs and four FK actions preserved; inheritance defaults true; retained revisions seed durable generation watermarks; migration ownership, frozen policy, source snapshots, generation history, site links, relays, LAN routes and non-HTTP policy guards refused unsafe downgrade.")
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(check())

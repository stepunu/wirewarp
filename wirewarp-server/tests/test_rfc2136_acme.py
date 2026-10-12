from __future__ import annotations

import pytest
import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect, select, text

from app.models.command_log import CommandLog
from app.models.system_settings import SystemSettings
from app.services.edge_ops import build_edge_desired_state
from app.services.secrets import decrypt_secret, encrypt_secret
from app.services.traefik_ops import load_letsencrypt_config


SECRET = "dGVzdC1hY21lLXNlY3JldA=="
CONFIG = {
    "letsencrypt_enabled": True,
    "letsencrypt_email": "admin@example.com",
    "letsencrypt_dns_provider": "rfc2136",
    "letsencrypt_rfc2136_nameserver": "ns1.step1.ro",
    "letsencrypt_rfc2136_tsig_key": "acme-step1-ro.",
    "letsencrypt_rfc2136_tsig_algorithm": "HMAC-SHA256.",
    "letsencrypt_rfc2136_tsig_secret": SECRET,
    "letsencrypt_dns_delay_seconds": 30,
}


@pytest.mark.asyncio
async def test_settings_encrypt_redact_dispatch_and_preserve_secret(client, db, factories, fake_manager):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    fake_manager.online.add(str(server.agent_id))
    response = await client.patch("/api/settings", json=CONFIG)
    assert response.status_code == 200
    assert response.json()["letsencrypt_rfc2136_secret_set"] is True
    assert response.json()["letsencrypt_rfc2136_nameserver"] == "ns1.step1.ro:53"
    assert response.json()["letsencrypt_rfc2136_tsig_algorithm"] == "hmac-sha256"
    assert "letsencrypt_rfc2136_tsig_secret" not in response.json()
    row = await db.get(SystemSettings, 1)
    assert row.letsencrypt_rfc2136_tsig_secret != SECRET
    assert decrypt_secret(row.letsencrypt_rfc2136_tsig_secret) == SECRET
    assert SECRET not in (await client.get("/api/settings")).text

    message = fake_manager.sent[-1]["message"]
    assert message["params"]["traefik_acme"] == {
        "rfc2136_nameserver": "ns1.step1.ro:53",
        "rfc2136_tsig_key": "acme-step1-ro.",
        "rfc2136_tsig_algorithm": "hmac-sha256",
        "rfc2136_tsig_secret": SECRET,
    }
    challenge = message["params"]["traefik_static_config"]["certificatesResolvers"]["wirewarp-le"]["acme"]["dnsChallenge"]
    assert challenge == {"provider": "exec", "resolvers": ["1.1.1.1:53"], "delayBeforeCheck": 30}
    log = await db.scalar(select(CommandLog).where(CommandLog.command_type == "edge_desired_state"))
    assert log.params["traefik_acme"]["rfc2136_tsig_secret"] == "[redacted]"

    await client.patch("/api/settings", json={"instance_name": "Updated"})
    await db.refresh(row)
    assert decrypt_secret(row.letsencrypt_rfc2136_tsig_secret) == SECRET
    cleared = await client.patch("/api/settings", json={"letsencrypt_rfc2136_tsig_secret": ""})
    assert cleared.status_code == 200
    assert cleared.json()["letsencrypt_rfc2136_secret_set"] is False
    assert fake_manager.sent[-1]["message"]["params"]["traefik_acme"] == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("letsencrypt_rfc2136_nameserver", "https://ns1.step1.ro"),
    ("letsencrypt_rfc2136_nameserver", "ns1.step1.ro:0"),
    ("letsencrypt_rfc2136_nameserver", "ns1.step1.ro:65536"),
    ("letsencrypt_rfc2136_nameserver", "::1"),
    ("letsencrypt_rfc2136_tsig_key", "bad key"),
    ("letsencrypt_rfc2136_tsig_key", "acme.."),
    ("letsencrypt_rfc2136_tsig_algorithm", "hmac-md5"),
    ("letsencrypt_dns_delay_seconds", -1),
    ("letsencrypt_dns_delay_seconds", 601),
    ("letsencrypt_dns_delay_seconds", None),
])
async def test_invalid_settings_rejected(client, field, value):
    response = await client.patch("/api/settings", json={field: value})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_invalid_secret_is_not_echoed_or_saved(client, db):
    invalid = "THIS IS A PRIVATE INVALID SECRET"
    response = await client.patch("/api/settings", json={"letsencrypt_rfc2136_tsig_secret": invalid})
    assert response.status_code == 422
    assert invalid not in response.text
    row = await db.get(SystemSettings, 1)
    assert row.letsencrypt_rfc2136_tsig_secret is None


@pytest.mark.asyncio
async def test_invalid_secret_type_is_not_echoed(client):
    invalid = {"accidental_secret": SECRET}
    response = await client.patch("/api/settings", json={"letsencrypt_rfc2136_tsig_secret": invalid})
    assert response.status_code == 422
    assert SECRET not in response.text


@pytest.mark.asyncio
async def test_settings_operator_denied(operator_client):
    assert (await operator_client.get("/api/settings")).status_code == 403
    assert (await operator_client.patch("/api/settings", json=CONFIG)).status_code == 403


@pytest.mark.asyncio
async def test_settings_viewer_denied(viewer_client):
    assert (await viewer_client.get("/api/settings")).status_code == 403
    assert (await viewer_client.patch("/api/settings", json=CONFIG)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["nameserver", "tsig_key", "tsig_secret"])
async def test_rfc2136_requires_all_credentials(db, missing):
    row = SystemSettings(
        id=1, letsencrypt_enabled=True, letsencrypt_email="admin@example.com",
        letsencrypt_dns_provider="rfc2136", letsencrypt_rfc2136_nameserver="ns1.step1.ro:53",
        letsencrypt_rfc2136_tsig_key="acme.", letsencrypt_rfc2136_tsig_secret=encrypt_secret(SECRET),
    )
    setattr(row, f"letsencrypt_rfc2136_{missing}", None)
    db.add(row)
    await db.commit()
    assert not (await load_letsencrypt_config(db)).complete


@pytest.mark.asyncio
async def test_cloudflare_delivery_and_non_dns_challenge_compatibility(db, factories):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    row = SystemSettings(id=1, letsencrypt_enabled=True, letsencrypt_email="admin@example.com",
                         letsencrypt_cloudflare_api_token=encrypt_secret("cf-token"))
    db.add(row)
    await db.commit()
    payload = await build_edge_desired_state(server.agent_id, db)
    assert payload["traefik_acme"] == {"cloudflare_dns_api_token": "cf-token"}
    dns = payload["traefik_static_config"]["certificatesResolvers"]["wirewarp-le"]["acme"]["dnsChallenge"]
    assert "delayBeforeCheck" not in dns
    row.letsencrypt_challenge = "http-01"
    row.letsencrypt_dns_provider = "rfc2136"
    await db.commit()
    payload = await build_edge_desired_state(server.agent_id, db)
    assert payload["traefik_acme"] == {}
    assert payload["traefik_static_config"]["certificatesResolvers"]["wirewarp-le"]["acme"]["httpChallenge"] == {"entryPoint": "web"}


@pytest.mark.asyncio
async def test_ipv6_endpoint_and_zero_delay(client):
    response = await client.patch("/api/settings", json={
        "letsencrypt_rfc2136_nameserver": "[2001:db8::1]",
        "letsencrypt_dns_delay_seconds": 0,
    })
    assert response.status_code == 200
    assert response.json()["letsencrypt_rfc2136_nameserver"] == "[2001:db8::1]:53"
    assert response.json()["letsencrypt_dns_delay_seconds"] == 0


def test_migration_preserves_existing_settings_and_has_defaults(monkeypatch):
    path = Path(__file__).parents[1] / "alembic/versions/0040_rfc2136_acme_settings.py"
    spec = importlib.util.spec_from_file_location("rfc2136_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE system_settings (id INTEGER PRIMARY KEY, letsencrypt_cloudflare_api_token TEXT)"))
        connection.execute(text("INSERT INTO system_settings VALUES (1, 'existing-ciphertext')"))
        monkeypatch.setattr(migration, "op", Operations(MigrationContext.configure(connection)))
        migration.upgrade()
        row = connection.execute(text("SELECT * FROM system_settings")).mappings().one()
        assert row["letsencrypt_cloudflare_api_token"] == "existing-ciphertext"
        assert row["letsencrypt_rfc2136_tsig_secret"] is None
        assert row["letsencrypt_rfc2136_tsig_algorithm"] == "hmac-sha256"
        assert row["letsencrypt_dns_delay_seconds"] == 30
        migration.downgrade()
        assert {column["name"] for column in inspect(connection).get_columns("system_settings")} == {"id", "letsencrypt_cloudflare_api_token"}
    engine.dispose()

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.command_log import CommandLog
from app.models.system_settings import SystemSettings
from app.routers import settings as settings_router
from app.services.secrets import encrypt_secret


pytestmark = pytest.mark.asyncio
SECRET = "dGVzdC1kbnMtc2VjcmV0"


@pytest.fixture(autouse=True)
def patch_settings_manager(monkeypatch, fake_manager):
    monkeypatch.setattr(settings_router, "manager", fake_manager)


async def configure(db):
    row = SystemSettings(
        id=1, letsencrypt_dns_provider="rfc2136", letsencrypt_challenge="dns-01",
        letsencrypt_rfc2136_nameserver="ns1.example.com:53",
        letsencrypt_rfc2136_tsig_key="acme.",
        letsencrypt_rfc2136_tsig_algorithm="hmac-sha256",
        letsencrypt_rfc2136_tsig_secret=encrypt_secret(SECRET),
        letsencrypt_dns_delay_seconds=0,
    )
    db.add(row)
    await db.commit()
    return row


async def test_dns_test_dispatch_uses_saved_credentials_and_redacts_log(client, db, factories, fake_manager):
    await configure(db)
    gateway = await factories.make_client(db)
    fake_manager.online.add(str(gateway.agent_id))
    response = await client.post("/api/settings/acme/test", json={
        "agent_id": str(gateway.agent_id), "domain": "*.Service.Example.com",
    })
    assert response.status_code == 200
    assert response.json()["status"] == "running"
    assert SECRET not in response.text
    params = fake_manager.sent[-1]["message"]["params"]
    assert params["domain"] == "service.example.com"
    assert params["credentials"]["rfc2136_tsig_secret"] == SECRET
    log = await db.get(CommandLog, uuid.UUID(response.json()["command_id"]))
    assert log.params["credentials"]["rfc2136_tsig_secret"] == "[redacted]"
    assert log.actor_user_id is not None
    pending = await client.get(f"/api/settings/acme/test/{log.id}")
    assert pending.json() == {"status": "pending", "command_id": str(log.id), "result": None}


async def test_same_domain_test_is_not_dispatched_twice(client, db, factories, fake_manager):
    await configure(db)
    server = await factories.make_server(db)
    fake_manager.online.add(str(server.agent_id))
    body = {"agent_id": str(server.agent_id), "domain": "example.com"}
    first = await client.post("/api/settings/acme/test", json=body)
    assert first.status_code == 200
    second = await client.post("/api/settings/acme/test", json=body)
    assert second.status_code == 409
    assert len(fake_manager.sent) == 1


async def test_missing_result_expires_honestly_and_late_result_remains_readable(client, db, factories, fake_manager):
    await configure(db)
    server = await factories.make_server(db)
    fake_manager.online.add(str(server.agent_id))
    response = await client.post("/api/settings/acme/test", json={
        "agent_id": str(server.agent_id), "domain": "example.com",
    })
    command_id = response.json()["command_id"]
    log = await db.get(CommandLog, uuid.UUID(command_id))
    log.executed_at = datetime.now(timezone.utc) - timedelta(seconds=151)
    await db.commit()
    response = await client.get(f"/api/settings/acme/test/{command_id}")
    assert response.json()["status"] == "failure"
    assert response.json()["result"]["stage"] == "timeout"
    assert response.json()["result"]["cleanup_ok"] is False
    await db.refresh(log)
    assert log.success is None
    log.success = True
    log.output = json.dumps({
        "ok": True, "stage": "complete", "detail": "Done", "record_name": "_acme-challenge.example.com",
        "cleanup_ok": True, "authoritative_results": [],
    })
    await db.commit()
    response = await client.get(f"/api/settings/acme/test/{command_id}")
    assert response.json()["status"] == "success"


@pytest.mark.parametrize("invalid_setting", ["delay", "secret"])
async def test_unusable_saved_settings_fail_before_dispatch(client, db, factories, fake_manager, invalid_setting):
    row = await configure(db)
    if invalid_setting == "delay":
        row.letsencrypt_dns_delay_seconds = 91
    else:
        row.letsencrypt_rfc2136_tsig_secret = "gAAAAA-invalid-ciphertext"
    await db.commit()
    server = await factories.make_server(db)
    fake_manager.online.add(str(server.agent_id))
    response = await client.post("/api/settings/acme/test", json={
        "agent_id": str(server.agent_id), "domain": "example.com",
    })
    assert response.status_code == 409
    assert "90 seconds" in response.text if invalid_setting == "delay" else "Re-enter" in response.text
    assert fake_manager.sent == []


async def test_disconnected_and_plain_client_cannot_test(client, db, factories, fake_manager):
    await configure(db)
    server = await factories.make_server(db)
    body = {"agent_id": str(server.agent_id), "domain": "example.com"}
    assert (await client.post("/api/settings/acme/test", json=body)).status_code == 409
    plain = await factories.make_client(db, is_gateway=False)
    fake_manager.online.add(str(plain.agent_id))
    body["agent_id"] = str(plain.agent_id)
    assert (await client.post("/api/settings/acme/test", json=body)).status_code == 409
    assert fake_manager.sent == []


async def test_disconnect_during_send_reports_failure(client, db, factories, fake_manager, monkeypatch):
    await configure(db)
    server = await factories.make_server(db)
    fake_manager.online.add(str(server.agent_id))
    async def disconnect_send(agent_id, message):
        fake_manager.online.discard(agent_id)
        return False
    monkeypatch.setattr(fake_manager, "send", disconnect_send)
    response = await client.post("/api/settings/acme/test", json={
        "agent_id": str(server.agent_id), "domain": "example.com",
    })
    assert response.status_code == 409
    log = await db.scalar(select(CommandLog).where(CommandLog.command_type == "acme_dns_test"))
    assert log.success is False
    assert "disconnected" in log.output


@pytest.mark.parametrize("provider,secret", [("cloudflare", SECRET), ("rfc2136", None)])
async def test_incomplete_or_wrong_provider_rejected(client, db, factories, fake_manager, provider, secret):
    row = await configure(db)
    row.letsencrypt_dns_provider = provider
    row.letsencrypt_rfc2136_tsig_secret = encrypt_secret(secret) if secret else None
    await db.commit()
    server = await factories.make_server(db)
    fake_manager.online.add(str(server.agent_id))
    assert (await client.post("/api/settings/acme/test", json={
        "agent_id": str(server.agent_id), "domain": "example.com",
    })).status_code == 409
    assert fake_manager.sent == []


@pytest.mark.parametrize("domain", ["localhost", "https://example.com", "example..com", "bad_name.example.com"])
async def test_invalid_domain_never_dispatches(client, fake_manager, domain):
    response = await client.post("/api/settings/acme/test", json={"agent_id": str(uuid.uuid4()), "domain": domain})
    assert response.status_code == 422
    assert fake_manager.sent == []


@pytest.mark.parametrize("success,ok,cleanup_ok,status", [
    (True, True, True, "success"), (False, False, True, "failure"),
    (True, True, False, "failure"), (False, True, True, "failure"),
])
async def test_result_requires_command_probe_and_cleanup_success(client, db, success, ok, cleanup_ok, status):
    report = {"ok": ok, "stage": "cleanup", "detail": "DNS test result", "cleanup_ok": cleanup_ok,
              "record_name": "_acme-challenge.example.com.", "authoritative_results": [
                  {"server": "ns1.example.com", "ok": True, "detail": "TXT value visible"},
              ]}
    log = CommandLog(command_type="acme_dns_test", success=success, output=json.dumps(report))
    db.add(log)
    await db.commit()
    response = await client.get(f"/api/settings/acme/test/{log.id}")
    assert response.status_code == 200
    assert response.json()["status"] == status
    assert response.json()["result"] == report


async def test_old_agent_error_is_visible_and_not_success(client, db):
    log = CommandLog(command_type="acme_dns_test", success=False, output="unknown command type: acme_dns_test")
    db.add(log)
    await db.commit()
    response = await client.get(f"/api/settings/acme/test/{log.id}")
    assert response.json()["status"] == "failure"
    assert response.json()["result"]["detail"] == log.output
    assert response.json()["result"]["cleanup_ok"] is False


async def test_result_rejects_other_command_and_missing_id(client, db):
    log = CommandLog(command_type="wg_init", success=True, output="done")
    db.add(log)
    await db.commit()
    assert (await client.get(f"/api/settings/acme/test/{log.id}")).status_code == 404
    assert (await client.get(f"/api/settings/acme/test/{uuid.uuid4()}")).status_code == 404


async def test_operator_cannot_start_or_read_dns_test(operator_client):
    assert (await operator_client.post("/api/settings/acme/test", json={
        "agent_id": str(uuid.uuid4()), "domain": "example.com",
    })).status_code == 403
    assert (await operator_client.get(f"/api/settings/acme/test/{uuid.uuid4()}")).status_code == 403

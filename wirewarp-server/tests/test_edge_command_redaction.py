from copy import deepcopy
import json
import uuid

import pytest

from app.models.command_log import CommandLog
from app.services import edge_ops


def payload():
    return {"runtime_mode": "security_edge", "traefik_static_config": {},
            "traefik_dynamic_config": {"http": {"middlewares": {
                "credentials": {"basicAuth": {"users": ["synthetic-basic-hash"]}},
                "headers": {"headers": {"customRequestHeaders": {"Authorization": "Bearer synthetic-token", "X-Custom": "synthetic-custom-secret"}, "customResponseHeaders": {"X-Private": "synthetic-response-secret"}}},
            }}}, "nginx_cache_config": {}, "traefik_acme": {"rfc2136_tsig_secret": "synthetic-tsig"}}


def test_redaction_masks_nested_credentials_without_changing_payload():
    original = payload()
    before = deepcopy(original)
    safe = edge_ops.redact_edge_desired_state(original)
    encoded = json.dumps(safe)
    for secret in ("synthetic-basic-hash", "synthetic-token", "synthetic-custom-secret", "synthetic-response-secret", "synthetic-tsig"):
        assert secret not in encoded
    assert original == before
    assert safe["runtime_mode"] == "security_edge"


@pytest.mark.asyncio
async def test_dispatch_sends_credentials_but_logs_only_redacted_values(db, factories, fake_manager, monkeypatch):
    server = await factories.make_server(db, edge_mode="security_edge", edge_state="enabled")
    original = payload()

    async def desired(*args, **kwargs):
        return deepcopy(original)

    monkeypatch.setattr(edge_ops, "build_edge_desired_state", desired)
    fake_manager.online.add(str(server.agent_id))
    sent, command_id = await edge_ops.dispatch_edge_desired_state(server.agent_id, db)
    assert sent
    transported = fake_manager.sent[-1]["message"]["params"]
    assert transported["traefik_dynamic_config"] == original["traefik_dynamic_config"]
    assert transported["traefik_acme"] == original["traefik_acme"]
    log = await db.get(CommandLog, uuid.UUID(command_id))
    assert "synthetic-" not in json.dumps(log.params)
    assert log.params["config_version_id"] == transported["config_version_id"]
    assert log.params["desired_hash"] == transported["desired_hash"]

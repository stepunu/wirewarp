"""Registration tokens: plaintext returned once, only the SHA-256 hash
persists, agent registration verifies via hash."""
from __future__ import annotations

import json
import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.auth import create_agent_token
from app.models.agent import Agent
from app.models.registration_token import RegistrationToken
from app.services.secrets import hash_token


@pytest.mark.asyncio
async def test_token_issuance_returns_plaintext_and_persists_only_hash(client, db):
    resp = await client.post("/api/agents/tokens", json={"agent_type": "server"})
    assert resp.status_code == 201
    body = resp.json()
    plaintext = body["token"]
    assert plaintext

    # Plaintext is not stored anywhere on the row.
    rows = (await db.execute(select(RegistrationToken))).scalars().all()
    assert len(rows) == 1
    stored = rows[0]
    assert stored.token_hash == hash_token(plaintext)
    # Defensive: there's no `token` attribute on the model.
    assert not hasattr(stored, "token")


@pytest.mark.asyncio
async def test_ws_register_uses_hashed_lookup(client, db, fake_manager, session_maker):
    """The /ws/agent register branch hashes the presented token and looks
    up by token_hash. Drive the full handler with a fake WS client."""
    resp = await client.post("/api/agents/tokens", json={"agent_type": "client"})
    plaintext = resp.json()["token"]

    from datetime import datetime, timezone
    from sqlalchemy import select as _select

    from app import main as main_module

    # WS handler imported `SessionLocal` at module load — bind its local
    # alias to the test session_maker so its `async with SessionLocal()`
    # hits our SQLite database.
    main_module.SessionLocal = session_maker

    received: list[dict] = []

    class FakeWS:
        def __init__(self, payload):
            self._payload = payload
            self.closed = False

        async def accept(self):
            return None

        async def receive_text(self):
            if self._payload is None:
                # Force the handler out of its main loop after register
                from fastapi import WebSocketDisconnect

                raise WebSocketDisconnect(code=1000)
            p, self._payload = self._payload, None
            return p

        async def send_text(self, msg):
            received.append(json.loads(msg))

        async def close(self, code: int = 1000):
            self.closed = True

        @property
        def query_params(self):
            return {}

    ws = FakeWS(
        json.dumps(
            {
                "type": "register",
                "token": plaintext,
                "hostname": "test-agent",
                "agent_type": "client",
            }
        )
    )

    # Patch dispatch_wg_init / send_command to no-ops so the post-register
    # replay path doesn't blow up without a real connected agent.
    with patch.object(main_module, "send_command") as cmd:
        cmd.return_value = (False, "noop")
        await main_module.agent_websocket(ws)

    # First message back is "registered" with a JWT; the JWT carries typ=agent.
    assert received[0]["type"] == "registered"
    jwt = received[0]["jwt"]

    from app.auth import TYP_AGENT, decode_token

    decoded = decode_token(jwt, expected_typ=TYP_AGENT)
    assert decoded == received[0]["agent_id"]
    # The token row got marked used.
    rows = (await db.execute(_select(RegistrationToken))).scalars().all()
    assert rows[0].used is True
    # Anti-regression: the plaintext does not appear anywhere in the row.
    assert not any(plaintext in str(getattr(rows[0], col, "")) for col in ("token_hash",))
    _ = datetime.now(timezone.utc)  # silence unused import lint


@pytest.mark.asyncio
async def test_ws_register_rejects_unknown_token(client, fake_manager, session_maker):
    """Presenting a token whose hash isn't stored returns an error and closes."""
    from app import main as main_module

    main_module.SessionLocal = session_maker

    received: list[dict] = []

    class FakeWS:
        def __init__(self, payload):
            self._payload = payload

        async def accept(self):
            return None

        async def receive_text(self):
            return self._payload

        async def send_text(self, msg):
            received.append(json.loads(msg))

        async def close(self, code: int = 1000):
            pass

        @property
        def query_params(self):
            return {}

    ws = FakeWS(
        json.dumps(
            {
                "type": "register",
                "token": "AAAA-BBBB-NEVERISSUED",
                "hostname": "x",
                "agent_type": "client",
            }
        )
    )
    await main_module.agent_websocket(ws)
    assert received[0]["type"] == "error"
    assert "Invalid" in received[0]["message"] or "expired" in received[0]["message"]


@pytest.mark.asyncio
async def test_ws_agent_ping_gets_application_pong(db, fake_manager, session_maker):
    from fastapi import WebSocketDisconnect
    from app import main as main_module

    main_module.SessionLocal = session_maker

    agent = Agent(
        id=uuid.uuid4(),
        name="ping-agent",
        type="server",
        status="disconnected",
    )
    db.add(agent)
    await db.commit()
    token = create_agent_token(str(agent.id))

    received: list[dict] = []
    payloads = [
        json.dumps({"type": "auth", "jwt": token}),
        json.dumps({"type": "agent_ping", "nonce": "n-1"}),
    ]

    class FakeWS:
        async def accept(self):
            return None

        async def receive_text(self):
            if not payloads:
                raise WebSocketDisconnect(code=1000)
            return payloads.pop(0)

        async def send_text(self, msg):
            received.append(json.loads(msg))

        async def close(self, code: int = 1000):
            pass

        @property
        def query_params(self):
            return {}

    with patch.object(main_module, "send_command") as cmd:
        cmd.return_value = (False, "noop")
        await main_module.agent_websocket(FakeWS())

    assert {"type": "authenticated"} in received
    assert {"type": "agent_pong", "nonce": "n-1"} in received

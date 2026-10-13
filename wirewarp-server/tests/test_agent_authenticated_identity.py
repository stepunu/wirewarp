import json
import uuid

import pytest

from app.auth import create_agent_token
from tests.test_reconnect_runtime_replay import RecordingWebSocket, _use_real_socket_manager


@pytest.mark.asyncio
@pytest.mark.parametrize("supplied_identity", [None, "foreign"])
async def test_jwt_auth_response_uses_verified_canonical_identity(db, session_maker, factories, monkeypatch, supplied_identity):
    owner = await factories.make_agent(db, type_="client")
    main_module = _use_real_socket_manager(monkeypatch, session_maker)
    socket = RecordingWebSocket(create_agent_token(str(owner.id)))
    if supplied_identity:
        socket.payloads[0] = json.dumps({
            "type": "auth", "jwt": create_agent_token(str(owner.id)), "agent_id": str(uuid.uuid4())})
    await main_module.agent_websocket(socket)
    assert socket.received[0] == {"type": "authenticated", "agent_id": str(owner.id)}
    assert len([frame for frame in socket.received if frame.get("type") == "authenticated"]) == 1

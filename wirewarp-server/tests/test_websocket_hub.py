import pytest
from starlette.websockets import WebSocketDisconnect

from app.websocket.hub import ConnectionManager


class FailingWebSocket:
    async def send_text(self, _: str) -> None:
        raise WebSocketDisconnect(code=1006)


class ReconnectingFailingWebSocket:
    def __init__(self, manager: ConnectionManager, replacement: "RecordingWebSocket") -> None:
        self.manager = manager
        self.replacement = replacement

    async def send_text(self, _: str) -> None:
        await self.manager.connect("agent-1", self.replacement)
        raise WebSocketDisconnect(code=1006)


class RecordingWebSocket:
    def __init__(self) -> None:
        self.messages: list[str] = []

    async def send_text(self, message: str) -> None:
        self.messages.append(message)


@pytest.mark.asyncio
async def test_send_drops_stale_websocket_and_reports_unsent() -> None:
    manager = ConnectionManager()
    await manager.connect("agent-1", FailingWebSocket())

    sent = await manager.send("agent-1", {"type": "agent_update"})

    assert sent is False
    assert manager.is_connected("agent-1") is False


@pytest.mark.asyncio
async def test_send_failure_does_not_drop_reconnected_socket() -> None:
    manager = ConnectionManager()
    replacement = RecordingWebSocket()
    stale = ReconnectingFailingWebSocket(manager, replacement)
    await manager.connect("agent-1", stale)

    sent = await manager.send("agent-1", {"type": "agent_update"})

    assert sent is False
    assert manager.is_connected("agent-1") is True
    assert replacement.messages == []

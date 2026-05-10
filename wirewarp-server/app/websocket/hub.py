import json
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        # agent_id (str) -> WebSocket
        self._connections: dict[str, WebSocket] = {}

    def is_connected(self, agent_id: str) -> bool:
        return agent_id in self._connections

    async def connect(self, agent_id: str, websocket: WebSocket) -> None:
        self._connections[agent_id] = websocket

    def disconnect(self, agent_id: str) -> None:
        self._connections.pop(agent_id, None)

    async def send(self, agent_id: str, message: dict[str, Any]) -> bool:
        """Send a message to a specific agent. Returns False if agent not connected."""
        ws = self._connections.get(agent_id)
        if ws is None:
            return False
        await ws.send_text(json.dumps(message))
        return True

    async def broadcast(self, agent_type: str, message: dict[str, Any], agent_types: dict[str, str]) -> None:
        """Broadcast to all connected agents of a given type.

        agent_types is a mapping of agent_id -> agent_type, maintained by the caller.
        """
        for agent_id, ws in list(self._connections.items()):
            if agent_types.get(agent_id) == agent_type:
                await ws.send_text(json.dumps(message))

    @property
    def connected_agent_ids(self) -> list[str]:
        return list(self._connections.keys())


# Module-level singleton used by the WebSocket endpoint and command dispatch service
manager = ConnectionManager()

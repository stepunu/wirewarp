import time
import uuid
from datetime import datetime

from pydantic import BaseModel, computed_field


class WgPeerSnapshotRead(BaseModel):
    id: int
    agent_id: uuid.UUID
    interface: str
    kind: str  # 'mesh' | 'vpn'
    public_key: str
    endpoint: str | None
    allowed_ips: str | None
    last_handshake_unix: int | None
    rx_bytes: int
    tx_bytes: int
    persistent_keepalive: int | None
    updated_at: datetime

    model_config = {"from_attributes": True}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def handshake_age_seconds(self) -> int | None:
        """Seconds since last successful handshake. None when no handshake
        has happened yet (peer added but never connected). The frontend
        uses this to colour the status dot — < 3min ok, < 15min warn,
        otherwise err / offline.
        """
        if not self.last_handshake_unix or self.last_handshake_unix <= 0:
            return None
        return max(0, int(time.time()) - self.last_handshake_unix)

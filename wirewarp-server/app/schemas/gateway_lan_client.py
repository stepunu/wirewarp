import uuid
from datetime import datetime

from pydantic import BaseModel


class DnsRecordRef(BaseModel):
    """One DNS record this LAN client tracks. Stored as JSONB inside
    `dns_record_ids` so we can address it by provider id without
    re-scanning the zone on every egress change. `name` is denormalized
    for UI display; it's the source of truth nowhere except the provider.
    """
    provider: str  # "cloudflare"
    zone_id: str
    record_id: str
    name: str  # FQDN e.g. "lan.example.com"


class GatewayLanClientRead(BaseModel):
    id: uuid.UUID
    tunnel_client_id: uuid.UUID
    lan_ip: str
    mac: str | None
    hostname: str | None
    last_seen: datetime
    bytes_recent: int
    egress_attachment_id: uuid.UUID | None
    egress_tunnel_server_ip_id: uuid.UUID | None
    dns_record_ids: list[DnsRecordRef] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class GatewayLanClientCreate(BaseModel):
    """POST body. Manually register a LAN host that hasn't been auto-
    discovered yet (e.g. one that hasn't sent any public-bound traffic
    so conntrack hasn't seen it). Idempotent on (tunnel_client_id, lan_ip)
    — the unique constraint enforces it.

    `egress_tunnel_server_ip_id` is only meaningful when
    `egress_attachment_id` is also set, and must reference an IP held by
    that attachment's tunnel server. The router validates both.
    """
    lan_ip: str
    mac: str | None = None
    hostname: str | None = None
    egress_attachment_id: uuid.UUID | None = None
    egress_tunnel_server_ip_id: uuid.UUID | None = None
    dns_record_ids: list[DnsRecordRef] | None = None


class GatewayLanClientUpdate(BaseModel):
    """PATCH body. Set egress_attachment_id=null to clear pinning (egress
    falls back to the LAN's default router). Setting
    `egress_tunnel_server_ip_id` to a non-null value drives a per-host
    SNAT rule on the VPS so outbound appears as that specific IP rather
    than the server's primary.
    """
    egress_attachment_id: uuid.UUID | None = None
    egress_tunnel_server_ip_id: uuid.UUID | None = None
    dns_record_ids: list[DnsRecordRef] | None = None


class HeartbeatLanClient(BaseModel):
    """One entry in the agent's heartbeat `lan_clients` field."""
    lan_ip: str
    mac: str | None = None
    hostname: str | None = None
    bytes_recent: int = 0

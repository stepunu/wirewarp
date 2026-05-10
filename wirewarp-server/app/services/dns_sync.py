"""DNS sync — push egress IP changes out to the operator's DNS provider
so public hostnames keep resolving to a working VPS.

## Why this exists

When a LAN client's egress moves from VPS A to VPS B, the dashboard's
auto-migration moves the inbound DNAT rules with it. But public DNS
records still point at A — clients keep connecting to A which no
longer has the rule. The fix is to update the DNS records pointing at
A so they point at B instead, in the same operation.

## Provider abstraction

`SyncProvider` is the minimal interface every backend implements:

  * `update_record(zone_id, record_id, new_ip)` — single PATCH.
  * `discover_a_records_for_ip(zone_id, ip)` — used by the
    "discover records" button to pre-populate the per-LAN-client list.

Today only the Cloudflare provider is implemented. Other providers
(Route53, Gandi, deSEC, etc.) plug in by implementing the same
interface and registering in `PROVIDERS`. Operators on providers we
don't support set `dns_provider=null` and the dashboard falls back to
"manual mode": egress changes still work, but each one emits a
`dns.manual_update_needed` event listing the records that should be
updated by hand.
"""
from __future__ import annotations

import logging
from typing import Protocol

import httpx

logger = logging.getLogger(__name__)


CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


class DiscoveredRecord:
    __slots__ = ("zone_id", "record_id", "name", "content")

    def __init__(self, zone_id: str, record_id: str, name: str, content: str):
        self.zone_id = zone_id
        self.record_id = record_id
        self.name = name
        self.content = content

    def to_dict(self) -> dict:
        return {
            "provider": "cloudflare",
            "zone_id": self.zone_id,
            "record_id": self.record_id,
            "name": self.name,
        }


class SyncProvider(Protocol):
    """Minimal provider interface. Implementations should be stateless
    apart from credentials passed at construction.
    """

    async def update_record(self, zone_id: str, record_id: str, new_ip: str) -> None:
        ...

    async def discover_a_records_for_ip(
        self, zone_id: str, ip: str
    ) -> list[DiscoveredRecord]:
        ...

    async def list_zones(self) -> list[dict]:
        ...


class CloudflareProvider:
    """Calls the Cloudflare v4 API. Token must have `Zone.DNS:Edit` on
    the zones you want to manage. Failures bubble up as exceptions —
    the caller (the lan-clients router) logs them but doesn't fail the
    request: an egress change that doesn't get DNS sync still beats no
    change at all, and the operator can rerun discover/sync manually.
    """

    def __init__(self, api_token: str):
        self._token = api_token
        self._headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

    async def update_record(self, zone_id: str, record_id: str, new_ip: str) -> None:
        url = f"{CLOUDFLARE_API}/zones/{zone_id}/dns_records/{record_id}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.patch(url, headers=self._headers, json={"content": new_ip})
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Cloudflare PATCH {record_id} → {new_ip} failed: {resp.status_code} {resp.text[:200]}"
            )

    async def discover_a_records_for_ip(
        self, zone_id: str, ip: str
    ) -> list[DiscoveredRecord]:
        # CF lists records with type+content filters server-side.
        url = f"{CLOUDFLARE_API}/zones/{zone_id}/dns_records"
        params = {"type": "A", "content": ip, "per_page": 100}
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=self._headers, params=params)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Cloudflare list zones/{zone_id} dns_records failed: {resp.status_code} {resp.text[:200]}"
            )
        body = resp.json()
        out = []
        for r in body.get("result", []):
            out.append(
                DiscoveredRecord(
                    zone_id=zone_id,
                    record_id=r["id"],
                    name=r["name"],
                    content=r["content"],
                )
            )
        return out

    async def list_zones(self) -> list[dict]:
        url = f"{CLOUDFLARE_API}/zones"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=self._headers, params={"per_page": 50})
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Cloudflare list zones failed: {resp.status_code} {resp.text[:200]}"
            )
        body = resp.json()
        return [
            {"id": z["id"], "name": z["name"]}
            for z in body.get("result", [])
        ]


PROVIDERS = {"cloudflare": CloudflareProvider}


def provider_from_settings(settings) -> SyncProvider | None:
    """Build a configured provider from SystemSettings. Returns None if
    DNS sync is disabled or required credentials aren't set.

    The Cloudflare token is stored Fernet-encrypted on
    `system_settings.cloudflare_api_token` (since migration 0016).
    Decrypt here so callers don't need to know.
    """
    from cryptography.fernet import InvalidToken

    from app.services.secrets import decrypt_secret, looks_like_fernet

    name = (settings.dns_provider or "").lower()
    if name == "cloudflare":
        token = settings.cloudflare_api_token
        if not token:
            return None
        if looks_like_fernet(token):
            try:
                token = decrypt_secret(token)
            except InvalidToken:
                logger.error(
                    "Cloudflare token decrypt failed — SECRET_KEY rotated? Re-save the token in Settings."
                )
                return None
        return CloudflareProvider(token)
    return None


async def sync_lan_client_egress(
    dns_record_ids: list[dict],
    new_ip: str,
    provider: SyncProvider,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Update every record in `dns_record_ids` to point at `new_ip`.

    Returns `(updated_names, failed_pairs)` where failed_pairs is a list
    of (name, error-message). Best-effort: one failed record doesn't
    abort the rest. Caller logs/surfaces failures via the realtime
    channel so the operator can react.
    """
    updated: list[str] = []
    failed: list[tuple[str, str]] = []
    for entry in dns_record_ids or []:
        name = entry.get("name", entry.get("record_id", "?"))
        try:
            await provider.update_record(entry["zone_id"], entry["record_id"], new_ip)
            updated.append(name)
            logger.info("DNS sync: %s -> %s", name, new_ip)
        except Exception as exc:  # noqa: BLE001
            failed.append((name, str(exc)))
            logger.warning("DNS sync failed for %s: %s", name, exc)
    return updated, failed

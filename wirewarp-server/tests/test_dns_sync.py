"""DNS sync provider tests.

Covers the Cloudflare adapter (mocked HTTP) + the dispatch helper that
walks a LAN client's record list. The router-level integration is
covered separately via the lan-clients PATCH path; here we just verify
the building blocks.
"""
from unittest.mock import AsyncMock, patch

import pytest

from app.services.dns_sync import (
    CloudflareProvider,
    DiscoveredRecord,
    PROVIDERS,
    provider_from_settings,
    sync_lan_client_egress,
)


pytestmark = pytest.mark.asyncio


class _Resp:
    """Minimal stand-in for httpx.Response."""

    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class _MockClient:
    def __init__(self, mapping: dict[tuple[str, str], _Resp]):
        # mapping keys are (method, url-suffix); router matches by suffix in URL.
        self._map = mapping
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def patch(self, url, headers=None, json=None):  # noqa: A002
        self.calls.append({"method": "PATCH", "url": url, "json": json})
        for (method, suffix), resp in self._map.items():
            if method == "PATCH" and url.endswith(suffix):
                return resp
        return _Resp(500, text="no mock")

    async def get(self, url, headers=None, params=None):
        self.calls.append({"method": "GET", "url": url, "params": params})
        for (method, suffix), resp in self._map.items():
            if method == "GET" and suffix in url:
                return resp
        return _Resp(500, text="no mock")


async def test_cloudflare_update_record_ok():
    mock = _MockClient({
        ("PATCH", "/zones/Z1/dns_records/R1"): _Resp(200, {"success": True}),
    })
    p = CloudflareProvider("token-xyz")
    with patch("app.services.dns_sync.httpx.AsyncClient", return_value=mock):
        await p.update_record("Z1", "R1", "1.2.3.4")
    assert any(c["method"] == "PATCH" and c["json"] == {"content": "1.2.3.4"} for c in mock.calls)


async def test_cloudflare_update_record_raises_on_error():
    mock = _MockClient({
        ("PATCH", "/zones/Z1/dns_records/R1"): _Resp(403, text="forbidden"),
    })
    p = CloudflareProvider("token-xyz")
    with patch("app.services.dns_sync.httpx.AsyncClient", return_value=mock):
        with pytest.raises(RuntimeError) as exc:
            await p.update_record("Z1", "R1", "1.2.3.4")
        assert "403" in str(exc.value)


async def test_cloudflare_discover_filters_by_ip():
    mock = _MockClient({
        ("GET", "/zones/Z1/dns_records"): _Resp(
            200,
            {
                "result": [
                    {"id": "R1", "name": "lan.example.com", "content": "1.2.3.4"},
                    {"id": "R2", "name": "example.com", "content": "1.2.3.4"},
                ]
            },
        ),
    })
    p = CloudflareProvider("token-xyz")
    with patch("app.services.dns_sync.httpx.AsyncClient", return_value=mock):
        rows = await p.discover_a_records_for_ip("Z1", "1.2.3.4")
    names = sorted(r.name for r in rows)
    assert names == ["lan.example.com", "example.com"]


async def test_provider_from_settings_returns_none_when_disabled():
    class S:
        dns_provider = None
        cloudflare_api_token = "secret"

    assert provider_from_settings(S()) is None


async def test_provider_from_settings_returns_none_without_token():
    class S:
        dns_provider = "cloudflare"
        cloudflare_api_token = None

    assert provider_from_settings(S()) is None


async def test_provider_from_settings_returns_cloudflare():
    class S:
        dns_provider = "cloudflare"
        cloudflare_api_token = "secret"

    p = provider_from_settings(S())
    assert isinstance(p, CloudflareProvider)


async def test_sync_lan_client_egress_calls_each_record():
    """Best-effort fan-out: every record in the list gets PATCHed; one
    failure doesn't abort the rest. Returns (updated, failed).
    """
    provider = type("Stub", (), {})()
    provider.update_record = AsyncMock(side_effect=[None, RuntimeError("boom"), None])

    records = [
        {"provider": "cloudflare", "zone_id": "Z1", "record_id": "R1", "name": "a.example"},
        {"provider": "cloudflare", "zone_id": "Z1", "record_id": "R2", "name": "b.example"},
        {"provider": "cloudflare", "zone_id": "Z1", "record_id": "R3", "name": "c.example"},
    ]
    updated, failed = await sync_lan_client_egress(records, "9.9.9.9", provider)

    assert updated == ["a.example", "c.example"]
    assert len(failed) == 1
    assert failed[0][0] == "b.example"
    assert "boom" in failed[0][1]


async def test_providers_registry_includes_cloudflare():
    assert "cloudflare" in PROVIDERS

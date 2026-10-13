import pytest

from app.services.site_link_ops import aggregate_payload
from tests.test_site_links import topology


@pytest.mark.asyncio
async def test_hub_ingress_interface_is_authoritative_and_hash_bound(client, db, factories, fake_manager):
    hub, a, _, _, _, body = await topology(db, factories, fake_manager)
    hub.wg_interface = "wg7"
    await db.commit()
    assert (await client.post("/api/site-links", json=body)).status_code == 201
    payload = await aggregate_payload(hub.agent_id, db)
    assert payload["hub_wireguard_interface"] == "wg7"
    assert "hub_wireguard_interface" not in await aggregate_payload(a.agent_id, db)
    sent = next(item["message"]["params"] for item in fake_manager.sent
                if item["agent_id"] == str(hub.agent_id) and item["message"]["type"] == "site_link_desired_state")
    assert sent["hub_wireguard_interface"] == "wg7"
    import hashlib
    import json
    unsigned = {key: value for key, value in sent.items() if key not in {"revision", "desired_hash"}}
    assert sent["desired_hash"] == hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

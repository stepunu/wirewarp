import pytest
from sqlalchemy import select

from app.models.site_link import SiteLinkAgentState
from app.models.tunnel_client import TunnelClient
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.services.site_link_topology import refresh_site_link_topology
from tests.test_site_links import topology

pytestmark = pytest.mark.asyncio


async def test_linked_gateway_and_attachment_edits_fail_before_commands(client, db, factories, fake_manager):
    hub, a, _, aa, _, body = await topology(db, factories, fake_manager)
    assert (await client.post("/api/site-links", json=body)).status_code == 201
    fake_manager.sent.clear()
    for fields in ({"is_gateway": False}, {"vm_network": "192.168.30.0/24", "lan_ip": "192.168.30.110"}, {"lan_ip": "192.168.20.111"}):
        response = await client.patch(f"/api/tunnel-clients/{a.id}", json=fields)
        assert response.status_code == 409, response.text
    response = await client.patch(f"/api/tunnel-client-attachments/{aa.id}", json={"tunnel_ip": "10.21.0.20"})
    assert response.status_code == 409, response.text
    response = await client.post(f"/api/tunnel-servers/{hub.id}/rebase", json={"tunnel_network": "10.22.0.0/24"})
    assert response.status_code == 409, response.text
    assert not fake_manager.sent
    await db.refresh(a)
    await db.refresh(aa)
    assert a.is_gateway and a.lan_ip == "192.168.20.110"
    assert aa.tunnel_ip == "10.21.0.10"


async def test_new_third_peer_refreshes_managed_deny_inventory(client, db, factories, fake_manager):
    hub, _, _, _, _, body = await topology(db, factories, fake_manager)
    assert (await client.post("/api/site-links", json=body)).status_code == 201
    third = await factories.make_client(db, vm_network="192.168.30.0/24", lan_ip="192.168.30.110")
    await factories.make_attachment(db, client=third, server=hub, tunnel_ip="10.21.0.12", public_key="CKEY")
    fake_manager.sent.clear()
    await refresh_site_link_topology(db)
    hub_payload = next(row["message"]["params"] for row in fake_manager.sent if row["agent_id"] == str(hub.agent_id))
    assert len(hub_payload["transit_peers"]) == 3
    assert len(hub_payload["links"]) == 1
    assert hub_payload["revision"] == 2
    state = await db.get(SiteLinkAgentState, hub.agent_id, populate_existing=True)
    assert state.phase == "pending"

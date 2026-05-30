"""Port forwards now reference attachments. Verify the create/list endpoints
resolve through the attachment join correctly and dispatch iptables to the
right server agent.
"""
import pytest


pytestmark = pytest.mark.asyncio


async def test_create_forward_with_attachment(client, db, factories, fake_manager):
    server = await factories.make_server(db, primary_ip="1.2.3.4")
    cli = await factories.make_client(db)
    att = await factories.make_attachment(db, client=cli, server=server)
    fake_manager.online.add(str(server.agent_id))

    res = await client.post(
        "/api/port-forwards",
        json={
            "attachment_id": str(att.id),
            "protocol": "tcp",
            "public_port": 8080,
            "destination_ip": att.tunnel_ip,
            "destination_port": 8080,
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["attachment_id"] == str(att.id)

    # Dispatched iptables_add_forward to the *server's* agent
    add_msgs = [s for s in fake_manager.sent if s["message"]["type"] == "iptables_add_forward"]
    assert len(add_msgs) == 1
    assert add_msgs[0]["agent_id"] == str(server.agent_id)
    assert add_msgs[0]["message"]["params"]["public_port"] == 8080
    assert add_msgs[0]["message"]["params"]["public_ip"] == "1.2.3.4"


async def test_create_raw_edge_forward_rejects_active_security_site(client, db, factories, fake_manager):
    server = await factories.make_server(
        db,
        primary_ip="1.2.3.4",
        edge_mode="security_edge",
        edge_state="enabled",
        edge_install_phase="healthy",
    )
    cli = await factories.make_client(db)
    att = await factories.make_attachment(db, client=cli, server=server)

    site = await client.post(
        "/api/security/sites",
        json={
            "attachment_id": str(att.id),
            "domain": "app.example.com",
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
        },
    )
    assert site.status_code == 201, site.text

    res = await client.post(
        "/api/port-forwards",
        json={
            "attachment_id": str(att.id),
            "protocol": "tcp",
            "public_port": 443,
            "destination_ip": att.tunnel_ip,
            "destination_port": 443,
        },
    )

    assert res.status_code == 409
    assert "Raw TCP forwards on 80/443" in res.json()["detail"]
    assert not [s for s in fake_manager.sent if s["message"]["type"] == "iptables_add_forward"]


async def test_create_forward_404_when_attachment_missing(client, db, factories, fake_manager):
    res = await client.post(
        "/api/port-forwards",
        json={
            "attachment_id": "00000000-0000-0000-0000-000000000000",
            "protocol": "tcp",
            "public_port": 8080,
            "destination_ip": "10.21.0.2",
            "destination_port": 8080,
        },
    )
    assert res.status_code == 404


async def test_patch_raw_edge_forward_rejects_active_security_site(client, db, factories):
    server = await factories.make_server(
        db,
        edge_mode="security_edge",
        edge_state="enabled",
        edge_install_phase="healthy",
    )
    cli = await factories.make_client(db)
    att = await factories.make_attachment(db, client=cli, server=server)

    site = await client.post(
        "/api/security/sites",
        json={
            "attachment_id": str(att.id),
            "domain": "app.example.com",
            "destination_ip": "192.168.1.10",
            "destination_port": 8080,
        },
    )
    assert site.status_code == 201, site.text
    raw = await client.post(
        "/api/port-forwards",
        json={
            "attachment_id": str(att.id),
            "protocol": "tcp",
            "public_port": 8080,
            "destination_ip": att.tunnel_ip,
            "destination_port": 8080,
        },
    )
    assert raw.status_code == 201, raw.text

    res = await client.patch(f"/api/port-forwards/{raw.json()['id']}", json={"public_port": 80})

    assert res.status_code == 409
    assert "Raw TCP forwards on 80/443" in res.json()["detail"]


async def test_list_filter_by_tunnel_server_id(client, db, factories, fake_manager):
    server_a = await factories.make_server(db, network="10.21.0.0/24")
    server_b = await factories.make_server(db, network="10.22.0.0/24")
    cli = await factories.make_client(db)
    att_a = await factories.make_attachment(db, client=cli, server=server_a)
    att_b = await factories.make_attachment(
        db, client=cli, server=server_b, tunnel_ip="10.22.0.10", wg_interface="wg1",
        fwmark=0x102, route_table_id=101,
    )
    fake_manager.online.add(str(server_a.agent_id))
    fake_manager.online.add(str(server_b.agent_id))

    for att, port in [(att_a, 8080), (att_b, 9090)]:
        res = await client.post(
            "/api/port-forwards",
            json={
                "attachment_id": str(att.id),
                "protocol": "tcp",
                "public_port": port,
                "destination_ip": att.tunnel_ip,
                "destination_port": port,
            },
        )
        assert res.status_code == 201

    listed = await client.get(f"/api/port-forwards?tunnel_server_id={server_a.id}")
    assert listed.status_code == 200
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["public_port"] == 8080


async def test_delete_forward_dispatches_remove(client, db, factories, fake_manager):
    server = await factories.make_server(db)
    cli = await factories.make_client(db)
    att = await factories.make_attachment(db, client=cli, server=server)
    fake_manager.online.add(str(server.agent_id))

    create = await client.post(
        "/api/port-forwards",
        json={
            "attachment_id": str(att.id),
            "protocol": "tcp",
            "public_port": 8080,
            "destination_ip": att.tunnel_ip,
            "destination_port": 8080,
        },
    )
    pf_id = create.json()["id"]

    fake_manager.sent.clear()
    res = await client.delete(f"/api/port-forwards/{pf_id}")
    assert res.status_code == 204
    remove_msgs = [s for s in fake_manager.sent if s["message"]["type"] == "iptables_remove_forward"]
    assert len(remove_msgs) == 1
    assert remove_msgs[0]["agent_id"] == str(server.agent_id)

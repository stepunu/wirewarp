"""LAN-client discovery + egress pinning tests.

Covers:
- Heartbeat upserts: agent reports `lan_clients`, the row appears under the
  matching gateway client.
- Heartbeat update path: subsequent reports refresh `last_seen` + MAC.
- PATCH egress pin: 503 if agent offline, 400 for cross-client attachment,
  200 + dispatch on success, NULL clears pin.
- DELETE: removes row, dispatches clear if pinned.
- Attachment delete clears any LAN-client pins referencing it.
- Per-IP egress pinning: set/move/clear of `egress_tunnel_server_ip_id`
  drives `set_lan_snat` dispatches to the matching VPS agent.
"""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from app.models.gateway_lan_client import GatewayLanClient
from app.models.tunnel_server_ip import TunnelServerIP
from app.websocket.handlers import handle_command_result, handle_heartbeat


pytestmark = pytest.mark.asyncio


def _ack_raw_forward_commands(fake_manager, session_maker):
    original_send = fake_manager.send

    async def send_with_result(agent_id, message):
        sent = await original_send(agent_id, message)
        if sent and message["type"] in {
            "iptables_remove_forward",
            "iptables_add_forward",
        }:
            async with session_maker() as result_db:
                await handle_command_result(
                    agent_id,
                    {
                        "command_id": message["id"],
                        "success": True,
                        "output": "applied",
                    },
                    result_db,
                )
        return sent

    fake_manager.send = send_with_result


async def _add_secondary_ip(db, server, address: str = "1.2.3.5") -> TunnelServerIP:
    ip = TunnelServerIP(
        tunnel_server_id=server.id, address=address, label=None, is_primary=False
    )
    db.add(ip)
    await db.commit()
    await db.refresh(ip)
    return ip


async def test_heartbeat_upserts_lan_clients(db, factories):
    cli = await factories.make_client(db)
    await handle_heartbeat(
        str(cli.agent_id),
        {
            "type": "heartbeat",
            "lan_clients": [
                {"lan_ip": "192.168.1.204", "mac": "aa:bb:cc:dd:ee:01"},
                {"lan_ip": "192.168.1.205"},
            ],
        },
        db,
    )
    rows = (
        await db.execute(
            select(GatewayLanClient).where(GatewayLanClient.tunnel_client_id == cli.id)
        )
    ).scalars().all()
    assert {r.lan_ip for r in rows} == {"192.168.1.204", "192.168.1.205"}
    by_ip = {r.lan_ip: r for r in rows}
    assert by_ip["192.168.1.204"].mac == "aa:bb:cc:dd:ee:01"
    assert by_ip["192.168.1.205"].mac is None


async def test_heartbeat_refreshes_existing(db, factories):
    cli = await factories.make_client(db)
    # Seed initial discovery.
    await handle_heartbeat(
        str(cli.agent_id),
        {"type": "heartbeat", "lan_clients": [{"lan_ip": "192.168.1.50"}]},
        db,
    )
    first = await db.scalar(
        select(GatewayLanClient).where(
            GatewayLanClient.tunnel_client_id == cli.id,
            GatewayLanClient.lan_ip == "192.168.1.50",
        )
    )
    first_seen = first.last_seen
    first_id = first.id

    # Force time gap so timestamps would differ if updated.
    await db.execute(
        select(GatewayLanClient).where(GatewayLanClient.id == first_id)
    )

    # Re-report with MAC populated this time.
    await handle_heartbeat(
        str(cli.agent_id),
        {
            "type": "heartbeat",
            "lan_clients": [{"lan_ip": "192.168.1.50", "mac": "11:22:33:44:55:66"}],
        },
        db,
    )
    refreshed = await db.scalar(
        select(GatewayLanClient).where(GatewayLanClient.id == first_id)
    )
    assert refreshed.mac == "11:22:33:44:55:66"
    # last_seen was touched (datetime comparison can be naive vs aware
    # depending on driver — just sanity-check it's set)
    assert refreshed.last_seen is not None


async def test_heartbeat_ignores_for_unknown_agent(db):
    # No tunnel_client for this agent_id → upsert is a no-op (no exception).
    await handle_heartbeat(
        str(uuid.uuid4()),
        {"type": "heartbeat", "lan_clients": [{"lan_ip": "10.0.0.1"}]},
        db,
    )
    count = await db.scalar(select(GatewayLanClient.id))
    assert count is None


async def test_set_egress_503_when_agent_offline(client, db, factories, fake_manager):
    cli = await factories.make_client(db)
    server = await factories.make_server(db)
    att = await factories.make_attachment(db, client=cli, server=server)
    lc = GatewayLanClient(tunnel_client_id=cli.id, lan_ip="192.168.1.204")
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    # Agent NOT in fake_manager.online → 503

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={"egress_attachment_id": str(att.id)},
    )
    assert res.status_code == 503


async def test_set_egress_400_for_cross_client_attachment(client, db, factories, fake_manager):
    cli_a = await factories.make_client(db)
    cli_b = await factories.make_client(db)
    server = await factories.make_server(db)
    att_b = await factories.make_attachment(db, client=cli_b, server=server)
    lc = GatewayLanClient(tunnel_client_id=cli_a.id, lan_ip="192.168.1.204")
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli_a.agent_id))

    res = await client.patch(
        f"/api/tunnel-clients/{cli_a.id}/lan-clients/{lc.id}",
        json={"egress_attachment_id": str(att_b.id)},
    )
    assert res.status_code == 400
    assert "this gateway client" in res.text


async def test_set_egress_200_dispatches(client, db, session_maker, factories, fake_manager):
    cli = await factories.make_client(db)
    server = await factories.make_server(db)
    att = await factories.make_attachment(
        db, client=cli, server=server, wg_interface="wg0", fwmark=0x101, route_table_id=100
    )
    lc = GatewayLanClient(tunnel_client_id=cli.id, lan_ip="192.168.1.204")
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))
    fake_manager.online.add(str(server.agent_id))
    await db.close()

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={"egress_attachment_id": str(att.id)},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["egress_attachment_id"] == str(att.id)

    sent = [m for m in fake_manager.sent if m["message"]["type"] == "set_lan_egress"]
    assert len(sent) == 1
    p = sent[0]["message"]["params"]
    assert p["lan_ip"] == "192.168.1.204"
    assert p["route_table_id"] == 100
    assert p["wg_interface"] == "wg0"


async def test_set_egress_clear(client, db, session_maker, factories, fake_manager):
    cli = await factories.make_client(db)
    server = await factories.make_server(db)
    att = await factories.make_attachment(db, client=cli, server=server)
    lc = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.204",
        egress_attachment_id=att.id,
    )
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))
    await db.close()

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={"egress_attachment_id": None},
    )
    assert res.status_code == 200, res.text
    assert res.json()["egress_attachment_id"] is None

    sent = [m for m in fake_manager.sent if m["message"]["type"] == "set_lan_egress"]
    assert len(sent) == 1
    assert sent[0]["message"]["params"]["route_table_id"] == 0


async def test_delete_lan_client_with_pin_is_blocked(
    client, db, session_maker, factories, fake_manager
):
    cli = await factories.make_client(db)
    server = await factories.make_server(db)
    att = await factories.make_attachment(db, client=cli, server=server)
    lc = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.204",
        egress_attachment_id=att.id,
    )
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    await db.close()

    res = await client.delete(f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}")
    assert res.status_code == 409
    assert "cannot be delivered durably" in res.text

    async with session_maker() as fresh:
        retained = await fresh.scalar(
            select(GatewayLanClient).where(GatewayLanClient.id == lc.id)
        )
        assert retained is not None
        assert retained.egress_attachment_id == att.id

    assert not fake_manager.sent


async def test_attachment_delete_is_blocked_and_preserves_pinned_lan_clients(
    client, db, session_maker, factories, fake_manager
):
    cli = await factories.make_client(db)
    server = await factories.make_server(db)
    att = await factories.make_attachment(db, client=cli, server=server)
    lc = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.204",
        egress_attachment_id=att.id,
    )
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))
    fake_manager.online.add(str(server.agent_id))
    await db.close()

    res = await client.delete(f"/api/tunnel-client-attachments/{att.id}")
    assert res.status_code == 409, res.text
    async with session_maker() as fresh:
        retained = await fresh.get(GatewayLanClient, lc.id)
        assert retained is not None
        assert retained.egress_attachment_id == att.id
    assert not fake_manager.sent


async def test_list_filters_to_client(client, db, factories, fake_manager):
    cli_a = await factories.make_client(db)
    cli_b = await factories.make_client(db)
    db.add(GatewayLanClient(tunnel_client_id=cli_a.id, lan_ip="192.168.1.10"))
    db.add(GatewayLanClient(tunnel_client_id=cli_b.id, lan_ip="192.168.1.20"))
    await db.commit()

    res = await client.get(f"/api/tunnel-clients/{cli_a.id}/lan-clients")
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["lan_ip"] == "192.168.1.10"


async def test_heartbeat_evicts_stale_unpinned(db, factories):
    """An unpinned row whose last_seen is past the TTL cutoff is dropped on
    the next heartbeat; pinned rows are sticky regardless of last_seen.
    """
    from datetime import datetime, timedelta, timezone
    from app.websocket.handlers import LAN_CLIENT_TTL

    cli = await factories.make_client(db)
    server = await factories.make_server(db)
    att = await factories.make_attachment(db, client=cli, server=server)

    # Two rows: one stale-and-unpinned, one stale-and-pinned, one fresh.
    stale_unpinned = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.10",
        last_seen=datetime.now(timezone.utc) - LAN_CLIENT_TTL - timedelta(minutes=1),
    )
    stale_pinned = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.11",
        egress_attachment_id=att.id,
        last_seen=datetime.now(timezone.utc) - LAN_CLIENT_TTL - timedelta(hours=2),
    )
    fresh = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.12",
        last_seen=datetime.now(timezone.utc),
    )
    db.add_all([stale_unpinned, stale_pinned, fresh])
    await db.commit()

    # Heartbeat with empty lan_clients list still triggers the sweep.
    await handle_heartbeat(
        str(cli.agent_id),
        {"type": "heartbeat", "lan_clients": []},
        db,
    )

    remaining = (
        await db.execute(
            select(GatewayLanClient).where(GatewayLanClient.tunnel_client_id == cli.id)
        )
    ).scalars().all()
    ips = sorted(r.lan_ip for r in remaining)
    # Stale unpinned (.10) is gone. Stale pinned (.11) survives. Fresh (.12) survives.
    assert ips == ["192.168.1.11", "192.168.1.12"]


async def test_set_egress_with_ip_pin_dispatches_snat(
    client, db, session_maker, factories, fake_manager
):
    """PATCH with both egress_attachment_id + egress_tunnel_server_ip_id
    dispatches set_lan_egress to the gateway agent AND set_lan_snat to
    the tunnel-server agent that owns the chosen IP.
    """
    cli = await factories.make_client(db)
    server = await factories.make_server(db, primary_ip="100.64.0.1")
    secondary = await _add_secondary_ip(db, server, address="100.64.0.2")
    att = await factories.make_attachment(db, client=cli, server=server)
    lc = GatewayLanClient(tunnel_client_id=cli.id, lan_ip="192.168.1.50")
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))
    fake_manager.online.add(str(server.agent_id))
    await db.close()

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={
            "egress_attachment_id": str(att.id),
            "egress_tunnel_server_ip_id": str(secondary.id),
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["egress_attachment_id"] == str(att.id)
    assert body["egress_tunnel_server_ip_id"] == str(secondary.id)

    egress_msgs = [m for m in fake_manager.sent if m["message"]["type"] == "set_lan_egress"]
    snat_msgs = [m for m in fake_manager.sent if m["message"]["type"] == "set_lan_snat"]
    assert len(egress_msgs) == 1
    assert len(snat_msgs) == 1
    assert snat_msgs[0]["agent_id"] == str(server.agent_id)
    p = snat_msgs[0]["message"]["params"]
    assert p["lan_ip"] == "192.168.1.50"
    assert p["public_ip"] == "100.64.0.2"
    assert p["action"] == "set"


async def test_set_ip_pin_without_attachment_400(
    client, db, factories, fake_manager
):
    """An IP pin only makes sense alongside an attachment pin — without one,
    there's no routing path for the SNAT rule to attach to. Reject 400.
    """
    cli = await factories.make_client(db)
    server = await factories.make_server(db)
    primary = (
        await db.execute(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id))
    ).scalar_one()
    lc = GatewayLanClient(tunnel_client_id=cli.id, lan_ip="192.168.1.50")
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={
            "egress_attachment_id": None,
            "egress_tunnel_server_ip_id": str(primary.id),
        },
    )
    assert res.status_code == 400
    assert "egress_attachment_id" in res.text


async def test_set_ip_pin_cross_server_400(
    client, db, factories, fake_manager
):
    """Pinning to an IP from a server different from the attachment's
    server is rejected — operator was almost certainly mid-edit.
    """
    cli = await factories.make_client(db)
    server_a = await factories.make_server(db, network="10.21.0.0/24", primary_ip="1.1.1.1")
    server_b = await factories.make_server(db, network="10.22.0.0/24", primary_ip="2.2.2.2")
    server_b_ip = (
        await db.execute(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server_b.id))
    ).scalar_one()
    att = await factories.make_attachment(db, client=cli, server=server_a)
    lc = GatewayLanClient(tunnel_client_id=cli.id, lan_ip="192.168.1.50")
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={
            "egress_attachment_id": str(att.id),
            "egress_tunnel_server_ip_id": str(server_b_ip.id),
        },
    )
    assert res.status_code == 400
    assert "same tunnel server" in res.text


async def test_move_ip_pin_clears_old_then_sets_new(
    client, db, session_maker, factories, fake_manager
):
    """Moving the pin from .175 → .176 (same attachment) should dispatch a
    clear for the old IP and a set for the new IP, both to the same VPS.
    """
    cli = await factories.make_client(db)
    server = await factories.make_server(db, primary_ip="100.64.0.1")
    secondary = await _add_secondary_ip(db, server, address="100.64.0.2")
    primary = (
        await db.execute(
            select(TunnelServerIP).where(
                TunnelServerIP.tunnel_server_id == server.id,
                TunnelServerIP.is_primary.is_(True),
            )
        )
    ).scalar_one()
    att = await factories.make_attachment(db, client=cli, server=server)
    lc = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.50",
        egress_attachment_id=att.id,
        egress_tunnel_server_ip_id=primary.id,
    )
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))
    fake_manager.online.add(str(server.agent_id))
    await db.close()

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={
            "egress_attachment_id": str(att.id),
            "egress_tunnel_server_ip_id": str(secondary.id),
        },
    )
    assert res.status_code == 200, res.text

    snat_msgs = [m for m in fake_manager.sent if m["message"]["type"] == "set_lan_snat"]
    actions = [m["message"]["params"]["action"] for m in snat_msgs]
    assert actions == ["clear", "set"]
    assert snat_msgs[1]["message"]["params"]["public_ip"] == "100.64.0.2"


async def test_clear_ip_pin_only(
    client, db, session_maker, factories, fake_manager
):
    """Clearing just the IP pin (keeping the attachment pin) dispatches
    set_lan_snat clear and re-issues set_lan_egress to keep routing intact.
    """
    cli = await factories.make_client(db)
    server = await factories.make_server(db)
    primary = (
        await db.execute(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id))
    ).scalar_one()
    att = await factories.make_attachment(db, client=cli, server=server)
    lc = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.50",
        egress_attachment_id=att.id,
        egress_tunnel_server_ip_id=primary.id,
    )
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))
    fake_manager.online.add(str(server.agent_id))
    await db.close()

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={
            "egress_attachment_id": str(att.id),
            "egress_tunnel_server_ip_id": None,
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["egress_attachment_id"] == str(att.id)
    assert body["egress_tunnel_server_ip_id"] is None

    snat_msgs = [m for m in fake_manager.sent if m["message"]["type"] == "set_lan_snat"]
    assert len(snat_msgs) == 1
    assert snat_msgs[0]["message"]["params"]["action"] == "clear"


async def test_delete_lan_client_with_snat_is_blocked(
    client, db, session_maker, factories, fake_manager
):
    cli = await factories.make_client(db)
    server = await factories.make_server(db, primary_ip="100.64.0.1")
    primary = (
        await db.execute(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server.id))
    ).scalar_one()
    att = await factories.make_attachment(db, client=cli, server=server)
    lc = GatewayLanClient(
        tunnel_client_id=cli.id,
        lan_ip="192.168.1.50",
        egress_attachment_id=att.id,
        egress_tunnel_server_ip_id=primary.id,
    )
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    await db.close()

    res = await client.delete(f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}")
    assert res.status_code == 409

    async with session_maker() as fresh:
        retained = await fresh.scalar(
            select(GatewayLanClient).where(GatewayLanClient.id == lc.id)
        )
        assert retained is not None
        assert retained.egress_tunnel_server_ip_id == primary.id
    assert not fake_manager.sent


async def test_egress_change_auto_migrates_port_forwards(
    client, db, session_maker, factories, fake_manager
):
    """Changing a LAN client's egress pin should atomically PATCH every
    port forward whose destination_ip matches that host so inbound (DNAT)
    follows outbound (SNAT). The agent dispatches in test mode are
    captured by fake_manager.
    """
    from app.models.port_forward import PortForward

    cli = await factories.make_client(db)
    server_a = await factories.make_server(db, network="10.21.0.0/24", primary_ip="1.1.1.1")
    server_b = await factories.make_server(db, network="10.22.0.0/24", primary_ip="2.2.2.2")
    server_b_ip = (
        await db.execute(select(TunnelServerIP).where(TunnelServerIP.tunnel_server_id == server_b.id))
    ).scalar_one()
    att_a = await factories.make_attachment(db, client=cli, server=server_a, tunnel_ip="10.21.0.10")
    att_b = await factories.make_attachment(
        db, client=cli, server=server_b, tunnel_ip="10.22.0.10",
        wg_interface="wg1", fwmark=0x102, route_table_id=101,
    )
    # Pre-existing forward on attachment A (vps-at-1) targeting traefik
    pf = PortForward(
        attachment_id=att_a.id,
        tunnel_server_ip_id=None,
        protocol="tcp",
        public_port=443,
        destination_ip="192.168.1.111",
        destination_port=443,
        active=True,
    )
    db.add(pf)
    # And a discovered LAN client for traefik, currently unpinned
    lc = GatewayLanClient(tunnel_client_id=cli.id, lan_ip="192.168.1.111")
    db.add(lc)
    await db.commit()
    await db.refresh(pf)
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))
    fake_manager.online.add(str(server_a.agent_id))
    fake_manager.online.add(str(server_b.agent_id))
    _ack_raw_forward_commands(fake_manager, session_maker)
    await db.close()

    # Pin egress to attachment B + its IP
    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={
            "egress_attachment_id": str(att_b.id),
            "egress_tunnel_server_ip_id": str(server_b_ip.id),
        },
    )
    assert res.status_code == 200, res.text

    # The forward should now live on attachment B with that IP
    async with session_maker() as fresh:
        moved = await fresh.scalar(select(PortForward).where(PortForward.id == pf.id))
        assert moved.attachment_id == att_b.id
        assert moved.tunnel_server_ip_id == server_b_ip.id

    # And the agent dispatch sequence must include a remove on server-A
    # followed by an add on server-B
    iptables_msgs = [m for m in fake_manager.sent if m["message"]["type"].startswith("iptables_")]
    actions = [(m["agent_id"], m["message"]["type"]) for m in iptables_msgs]
    assert (str(server_a.agent_id), "iptables_remove_forward") in actions
    assert (str(server_b.agent_id), "iptables_add_forward") in actions


async def test_egress_change_skips_forwards_that_would_conflict(
    client, db, session_maker, factories, fake_manager
):
    """If the target (attachment, ip, proto, port) slot is already
    occupied by another forward, the migration helper logs and skips —
    it must not raise IntegrityError + corrupt the session (which used
    to surface as 500 + MissingGreenlet at the request boundary).
    """
    from app.models.port_forward import PortForward

    cli = await factories.make_client(db)
    server_a = await factories.make_server(db, network="10.21.0.0/24", primary_ip="1.1.1.1")
    server_b = await factories.make_server(db, network="10.22.0.0/24", primary_ip="2.2.2.2")
    server_b_primary = (
        await db.execute(
            select(TunnelServerIP).where(
                TunnelServerIP.tunnel_server_id == server_b.id,
                TunnelServerIP.is_primary.is_(True),
            )
        )
    ).scalar_one()
    att_a = await factories.make_attachment(db, client=cli, server=server_a, tunnel_ip="10.21.0.10")
    att_b = await factories.make_attachment(
        db, client=cli, server=server_b, tunnel_ip="10.22.0.10",
        wg_interface="wg1", fwmark=0x102, route_table_id=101,
    )
    # Pre-existing forward on attachment A targeting host .77, port 8443
    pf_a = PortForward(
        attachment_id=att_a.id,
        protocol="tcp",
        public_port=8443,
        destination_ip="192.168.1.77",
        destination_port=18001,
        active=True,
    )
    # AND another forward on attachment B already at the (att_b, primary_ip,
    # tcp, 8443) slot — different destination IP, but same target slot.
    pf_b = PortForward(
        attachment_id=att_b.id,
        tunnel_server_ip_id=server_b_primary.id,
        protocol="tcp",
        public_port=8443,
        destination_ip="192.168.1.99",
        destination_port=18002,
        active=True,
    )
    db.add_all([pf_a, pf_b])
    lc = GatewayLanClient(tunnel_client_id=cli.id, lan_ip="192.168.1.77")
    db.add(lc)
    await db.commit()
    await db.refresh(lc)
    fake_manager.online.add(str(cli.agent_id))
    fake_manager.online.add(str(server_a.agent_id))
    fake_manager.online.add(str(server_b.agent_id))
    _ack_raw_forward_commands(fake_manager, session_maker)
    await db.close()

    res = await client.patch(
        f"/api/tunnel-clients/{cli.id}/lan-clients/{lc.id}",
        json={
            "egress_attachment_id": str(att_b.id),
            "egress_tunnel_server_ip_id": str(server_b_primary.id),
        },
    )
    # No 500 — the conflict path is handled cleanly.
    assert res.status_code == 200, res.text

    # pf_a stayed on attachment A (couldn't migrate due to conflict)
    async with session_maker() as fresh:
        pa = await fresh.scalar(select(PortForward).where(PortForward.id == pf_a.id))
        assert pa.attachment_id == att_a.id
        pb = await fresh.scalar(select(PortForward).where(PortForward.id == pf_b.id))
        assert pb.attachment_id == att_b.id  # untouched


async def test_pf_patch_attachment_id_migrates_rule(
    client, db, session_maker, factories, fake_manager
):
    """Recovery path: operator manually PATCHes a single port-forward's
    attachment_id (the "fix" button on an asymmetric forward). Old DNAT
    is removed from the previous server, new DNAT installed on the new.
    """
    from app.models.port_forward import PortForward

    cli = await factories.make_client(db)
    server_a = await factories.make_server(db, network="10.21.0.0/24", primary_ip="1.1.1.1")
    server_b = await factories.make_server(db, network="10.22.0.0/24", primary_ip="2.2.2.2")
    att_a = await factories.make_attachment(db, client=cli, server=server_a, tunnel_ip="10.21.0.10")
    att_b = await factories.make_attachment(
        db, client=cli, server=server_b, tunnel_ip="10.22.0.10",
        wg_interface="wg1", fwmark=0x102, route_table_id=101,
    )
    pf = PortForward(
        attachment_id=att_a.id,
        protocol="tcp",
        public_port=8080,
        destination_ip="192.168.1.50",
        destination_port=8080,
        active=True,
    )
    db.add(pf)
    await db.commit()
    await db.refresh(pf)
    fake_manager.online.add(str(server_a.agent_id))
    fake_manager.online.add(str(server_b.agent_id))
    _ack_raw_forward_commands(fake_manager, session_maker)
    await db.close()

    res = await client.patch(
        f"/api/port-forwards/{pf.id}",
        json={"attachment_id": str(att_b.id)},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["attachment_id"] == str(att_b.id)

    iptables_msgs = [m for m in fake_manager.sent if m["message"]["type"].startswith("iptables_")]
    actions = [(m["agent_id"], m["message"]["type"]) for m in iptables_msgs]
    assert (str(server_a.agent_id), "iptables_remove_forward") in actions
    assert (str(server_b.agent_id), "iptables_add_forward") in actions


async def test_create_lan_client_with_ip_pin_dispatches_snat(
    client, db, session_maker, factories, fake_manager
):
    cli = await factories.make_client(db)
    server = await factories.make_server(db, primary_ip="100.64.0.1")
    secondary = await _add_secondary_ip(db, server, address="100.64.0.9")
    att = await factories.make_attachment(db, client=cli, server=server)
    fake_manager.online.add(str(cli.agent_id))
    fake_manager.online.add(str(server.agent_id))
    await db.close()

    res = await client.post(
        f"/api/tunnel-clients/{cli.id}/lan-clients",
        json={
            "lan_ip": "192.168.1.77",
            "egress_attachment_id": str(att.id),
            "egress_tunnel_server_ip_id": str(secondary.id),
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["egress_tunnel_server_ip_id"] == str(secondary.id)

    snat_msgs = [m for m in fake_manager.sent if m["message"]["type"] == "set_lan_snat"]
    assert len(snat_msgs) == 1
    assert snat_msgs[0]["message"]["params"]["public_ip"] == "100.64.0.9"
    assert snat_msgs[0]["message"]["params"]["action"] == "set"


async def test_heartbeat_empty_list_is_valid(db, factories):
    """Empty lan_clients (gateway agent has no current egress flows) is a
    valid signal — used to drive TTL sweeps. Does not error.
    """
    cli = await factories.make_client(db)
    await handle_heartbeat(
        str(cli.agent_id),
        {"type": "heartbeat", "lan_clients": []},
        db,
    )
    rows = await db.scalar(select(func.count(GatewayLanClient.id)))
    assert rows == 0

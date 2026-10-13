import pytest
from sqlalchemy import select

from app.models.edge_component_state import EdgeComponentState
from app.models.edge_node import EdgeNode
from app.models.crowdsec_snapshot import CrowdSecSnapshot
from app.services.edge_ops import build_edge_desired_state
from app.websocket.handlers import handle_traefik_status


pytestmark = pytest.mark.asyncio


async def edge_node(db, factories, gateway=True):
    transport = await factories.make_client(db, lan_ip="192.168.20.110") if gateway else await factories.make_server(db)
    node = await db.get(EdgeNode, transport.agent_id)
    if node is None:
        node = EdgeNode(agent_id=transport.agent_id)
    node.edge_mode = "security_edge"
    node.edge_state = "enabled"
    node.edge_install_phase = "pending"
    node.lan_bind_ip = "192.168.20.110" if gateway else None
    db.add(node)
    await db.commit()
    return node


@pytest.mark.parametrize("gateway", [True, False])
async def test_access_logging_desired_render_can_disable_collection(db, factories, gateway):
    node = await edge_node(db, factories, gateway)
    enabled = await build_edge_desired_state(node.agent_id, db)
    assert enabled["traefik_static_config"]["accessLog"] == {"format": "json", "fields": {"defaultMode": "keep", "headers": {"defaultMode": "drop"}}}
    db.add(EdgeComponentState(agent_id=node.agent_id, component="access_log", desired="disabled"))
    await db.commit()
    disabled = await build_edge_desired_state(node.agent_id, db)
    assert "accessLog" not in disabled["traefik_static_config"]


async def test_relay_only_does_not_collect_access_logs(db, factories):
    node = await edge_node(db, factories, False)
    node.edge_state = "disabled"
    node.relay_enabled = True
    await db.commit()
    assert "accessLog" not in (await build_edge_desired_state(node.agent_id, db))["traefik_static_config"]


async def test_reported_collector_health_finishes_installation(db, factories):
    node = await edge_node(db, factories)
    db.add(CrowdSecSnapshot(agent_id=node.agent_id, installed=True, running=True, phase="healthy", appsec_enabled=True, bouncer_registered=True))
    await db.commit()
    await handle_traefik_status(str(node.agent_id), {"installed": True, "running": True, "access_log": {"installed": True, "running": True}}, db)
    row = await db.scalar(select(EdgeComponentState).where(EdgeComponentState.agent_id == node.agent_id, EdgeComponentState.component == "access_log"))
    assert row.desired == "enabled"
    assert row.installed and row.running and row.phase == "healthy"
    assert node.edge_install_phase == "healthy"

    await handle_traefik_status(str(node.agent_id), {"installed": True, "running": True, "access_log": {"installed": True, "running": False, "error": "journald permission denied"}}, db)
    assert row.running is False and row.phase == "degraded"
    assert row.last_error == "journald permission denied"
    assert node.edge_install_phase == "degraded"


async def test_disabled_and_legacy_status_do_not_fabricate_collector_health(db, factories):
    node = await edge_node(db, factories)
    await handle_traefik_status(str(node.agent_id), {"installed": True, "running": True}, db)
    assert await db.scalar(select(EdgeComponentState).where(EdgeComponentState.agent_id == node.agent_id)) is None
    assert node.edge_install_phase == "pending"
    await handle_traefik_status(str(node.agent_id), {"installed": True, "running": True, "access_log": {"installed": False, "running": False}}, db)
    row = await db.scalar(select(EdgeComponentState).where(EdgeComponentState.agent_id == node.agent_id))
    assert row.phase == "disabled" and not row.running
    assert node.edge_install_phase == "pending"

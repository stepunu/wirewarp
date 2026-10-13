import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.database import engine, Base, SessionLocal
from app.realtime.bus import bus
from app.realtime.events import emit_agent_changed
from app.routers import auth, agents, tunnel_servers, tunnel_clients, tunnel_client_attachments, lan_clients, port_forwards, service_templates, settings, tunnel_server_ips, audit, users, oidc, ldap as ldap_router, vpn_endpoints, vpn_profiles, security, nodes, edge, edge_node
from app.websocket.hub import manager
from app.websocket.handlers import dispatch
from app.services.traffic_sampler import run_traffic_sampler
from app.routers import edge_migration, site_links

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (migrations handle production schema)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sampler_task = asyncio.create_task(run_traffic_sampler())
    try:
        yield
    finally:
        sampler_task.cancel()
        try:
            await sampler_task
        except asyncio.CancelledError:
            pass
        await engine.dispose()


app = FastAPI(title="WireWarp Control Server", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(oidc.router, prefix="/api/auth/oidc", tags=["auth"])
app.include_router(ldap_router.router, prefix="/api/auth/ldap", tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(agents.router, prefix="/api/agents", tags=["agents"])
app.include_router(nodes.router, prefix="/api/nodes", tags=["nodes"])
app.include_router(tunnel_servers.router, prefix="/api/tunnel-servers", tags=["tunnel-servers"])
app.include_router(tunnel_server_ips.router, prefix="/api/tunnel-server-ips", tags=["tunnel-server-ips"])
app.include_router(tunnel_clients.router, prefix="/api/tunnel-clients", tags=["tunnel-clients"])
app.include_router(tunnel_client_attachments.router, prefix="/api/tunnel-client-attachments", tags=["tunnel-client-attachments"])
app.include_router(lan_clients.router, prefix="/api", tags=["lan-clients"])
app.include_router(port_forwards.router, prefix="/api/port-forwards", tags=["port-forwards"])
app.include_router(service_templates.router, prefix="/api/service-templates", tags=["service-templates"])
app.include_router(settings.router, prefix="/api/settings", tags=["settings"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(vpn_endpoints.router, prefix="/api/vpn-endpoints", tags=["vpn"])
app.include_router(vpn_profiles.router, prefix="/api/vpn-profiles", tags=["vpn"])
app.include_router(security.router, prefix="/api/security", tags=["security"])
app.include_router(edge.router, prefix="/api/edge", tags=["edge"])
app.include_router(edge_node.router, prefix="/api/nodes", tags=["edge"])
app.include_router(site_links.router, prefix="/api/site-links", tags=["site-links"])
app.include_router(edge_migration.router, prefix="/api/edge/migrations", tags=["edge"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket):
    from app.auth import decode_token, create_agent_token, TYP_AGENT
    from app.models.agent import Agent
    from app.models.registration_token import RegistrationToken
    from app.models.tunnel_server import TunnelServer
    from app.models.tunnel_client import TunnelClient
    from app.services.secrets import hash_token
    from sqlalchemy import select

    await websocket.accept()
    agent_id: str | None = None

    try:
        # First message must be either registration (token) or auth (jwt)
        raw = await websocket.receive_text()
        msg = json.loads(raw)
        msg_type = msg.get("type")

        async with SessionLocal() as db:
            if msg_type == "register":
                # First-run: validate token, create agent record, issue JWT
                token_str = msg.get("token", "")
                hostname = msg.get("hostname", "")
                agent_type = msg.get("agent_type", "")  # 'server' | 'client'

                result = await db.execute(
                    select(RegistrationToken).where(
                        RegistrationToken.token_hash == hash_token(token_str)
                    )
                )
                token = result.scalar_one_or_none()

                if (
                    token is None
                    or token.used
                    or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
                ):
                    await websocket.send_text(json.dumps({"type": "error", "message": "Invalid or expired token"}))
                    await websocket.close()
                    return

                # Create agent
                agent = Agent(
                    name=hostname or f"agent-{token_str[:8]}",
                    type=token.agent_type,
                    hostname=hostname,
                    status="connected",
                    last_seen=datetime.now(timezone.utc),
                )
                db.add(agent)
                token.used = True

                # Create the type-specific config record
                if token.agent_type == "server":
                    from app.services.network_alloc import allocate_tunnel_network
                    allocated = await allocate_tunnel_network(db)
                    db.add(TunnelServer(agent=agent, tunnel_network=allocated))
                elif token.agent_type == "client":
                    db.add(TunnelClient(agent=agent))

                await db.commit()
                await db.refresh(agent)
                agent_id = str(agent.id)

                jwt = create_agent_token(agent_id, expires_delta=timedelta(days=3650))
                await websocket.send_text(json.dumps({"type": "registered", "agent_id": agent_id, "jwt": jwt}))
            elif msg_type == "auth":
                # Reconnect: validate JWT (must carry typ=agent)
                jwt = msg.get("jwt", "")
                try:
                    agent_id = decode_token(jwt, expected_typ=TYP_AGENT)
                except Exception:
                    await websocket.send_text(json.dumps({"type": "error", "message": "Invalid JWT"}))
                    await websocket.close()
                    return

                result = await db.execute(select(Agent).where(Agent.id == agent_id))
                agent = result.scalar_one_or_none()
                if agent is None:
                    await websocket.send_text(json.dumps({"type": "error", "message": "Agent not found"}))
                    await websocket.close()
                    return

                agent_id = str(agent.id)
                agent.status = "connected"
                agent.last_seen = datetime.now(timezone.utc)
                await db.commit()
                await websocket.send_text(json.dumps({"type": "authenticated", "agent_id": agent_id}))

            else:
                await websocket.send_text(json.dumps({"type": "error", "message": "Expected register or auth message"}))
                await websocket.close()
                return

        if agent_id is None:
            return

        await manager.connect(agent_id, websocket)
        emit_agent_changed()
        logger.info("Agent %s connected", agent_id)

        # Replay active port forwards + wg peers to server agents on
        # (re)connect so rules are applied even if the agent restarted or
        # missed earlier commands. Both walks pivot off attachments now —
        # each attachment is one peering with this server.
        async with SessionLocal() as db:
            from app.services.agent_replay import replay_agent_runtime, site_link_teardown_pending
            runtime_replay_deferred = not await replay_agent_runtime(agent_id, db)

        # Main message loop
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if runtime_replay_deferred:
                async with SessionLocal() as db:
                    if not await site_link_teardown_pending(agent_id, db):
                        runtime_replay_deferred = not await replay_agent_runtime(agent_id, db)
            if msg.get("type") == "agent_ping":
                await websocket.send_text(
                    json.dumps({"type": "agent_pong", "nonce": msg.get("nonce", "")})
                )
                continue
            async with SessionLocal() as db:
                await dispatch(agent_id, msg, db)
                if runtime_replay_deferred and not await site_link_teardown_pending(agent_id, db):
                    runtime_replay_deferred = not await replay_agent_runtime(agent_id, db)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.exception("WebSocket error for agent %s: %s", agent_id, exc)
    finally:
        if agent_id:
            disconnected_current = manager.disconnect(agent_id, websocket)
            if not disconnected_current and manager.is_connected(agent_id):
                logger.info(
                    "Stale WebSocket for agent %s closed; current connection remains active",
                    agent_id,
                )
            else:
                logger.info("Agent %s disconnected", agent_id)
                async with SessionLocal() as db:
                    from sqlalchemy import select
                    from app.models.agent import Agent
                    result = await db.execute(select(Agent).where(Agent.id == agent_id))
                    agent = result.scalar_one_or_none()
                    if agent:
                        agent.status = "disconnected"
                        await db.commit()
                        emit_agent_changed()


@app.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    """Real-time push channel to dashboard tabs.

    Auth: `?token=<jwt>` query param. JWT is the same one issued by
    /api/auth/login (subject = username). EventSource doesn't support
    custom headers but we use a WS not SSE, so this is just to match
    the /ws/agent posture (no cookie infra) — TLS protects the token
    in transit. The token is short-lived enough for this to be fine.

    Protocol: server pushes JSON `{type, ...payload}` events, never
    receives anything from the client. The frontend uses each event
    as an invalidation hint and refetches via the existing REST
    endpoints. Drop events are signalled with `{type:"desync"}`.
    """
    from app.auth import decode_token, TYP_USER
    from app.models.user import User
    from sqlalchemy import select

    await websocket.accept()
    token = websocket.query_params.get("token", "")
    if not token:
        await websocket.send_text(json.dumps({"type": "error", "message": "missing token"}))
        await websocket.close(code=1008)
        return
    try:
        username = decode_token(token, expected_typ=TYP_USER)
    except Exception:
        await websocket.send_text(json.dumps({"type": "error", "message": "invalid token"}))
        await websocket.close(code=1008)
        return

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.username == username))
    if user is None or not user.is_active:
        await websocket.send_text(json.dumps({"type": "error", "message": "unknown or disabled user"}))
        await websocket.close(code=1008)
        return

    await websocket.send_text(json.dumps({"type": "ready"}))
    logger.info("Dashboard WS connected (user=%s)", username)

    try:
        async for event in bus.subscribe():
            await websocket.send_text(json.dumps(event))
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("Dashboard WS error (user=%s)", username)
    finally:
        logger.info("Dashboard WS disconnected (user=%s)", username)


# Serve React dashboard static files
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

if STATIC_DIR.is_dir():
    # Serve assets (JS/CSS/images)
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="static-assets")

    _STATIC_BASE = STATIC_DIR.resolve()

    @app.get("/{path:path}")
    async def spa_fallback(path: str):
        # Resolve the requested path against STATIC_DIR and reject anything
        # that escapes the base — `..` segments would otherwise leak source
        # files (alembic.ini, services/*.py) or arbitrary readable files
        # to unauthenticated callers. SPA routes (no matching file) fall
        # back to index.html, same as before.
        if path:
            try:
                candidate = (STATIC_DIR / path).resolve()
                candidate.relative_to(_STATIC_BASE)
            except (ValueError, OSError):
                return FileResponse(STATIC_DIR / "index.html")
            if candidate.is_file():
                return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")

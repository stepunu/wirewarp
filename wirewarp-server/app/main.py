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
from app.routers import auth, agents, tunnel_servers, tunnel_clients, port_forwards, service_templates
from app.websocket.hub import manager
from app.websocket.handlers import dispatch

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (migrations handle production schema)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
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
app.include_router(agents.router, prefix="/api/agents", tags=["agents"])
app.include_router(tunnel_servers.router, prefix="/api/tunnel-servers", tags=["tunnel-servers"])
app.include_router(tunnel_clients.router, prefix="/api/tunnel-clients", tags=["tunnel-clients"])
app.include_router(port_forwards.router, prefix="/api/port-forwards", tags=["port-forwards"])
app.include_router(service_templates.router, prefix="/api/service-templates", tags=["service-templates"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket):
    from app.auth import decode_token
    from app.models.agent import Agent
    from app.models.registration_token import RegistrationToken
    from app.models.tunnel_server import TunnelServer
    from app.models.tunnel_client import TunnelClient
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
                    select(RegistrationToken).where(RegistrationToken.token == token_str)
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
                    db.add(TunnelServer(agent=agent))
                elif token.agent_type == "client":
                    db.add(TunnelClient(agent=agent))

                await db.commit()
                await db.refresh(agent)
                agent_id = str(agent.id)

                from app.auth import create_access_token
                jwt = create_access_token(agent_id)
                await websocket.send_text(json.dumps({"type": "registered", "agent_id": agent_id, "jwt": jwt}))

            elif msg_type == "auth":
                # Reconnect: validate JWT
                jwt = msg.get("jwt", "")
                try:
                    agent_id = decode_token(jwt)
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

                agent.status = "connected"
                agent.last_seen = datetime.now(timezone.utc)
                await db.commit()
                await websocket.send_text(json.dumps({"type": "authenticated"}))

            else:
                await websocket.send_text(json.dumps({"type": "error", "message": "Expected register or auth message"}))
                await websocket.close()
                return

        if agent_id is None:
            return

        await manager.connect(agent_id, websocket)
        logger.info("Agent %s connected", agent_id)

        # Main message loop
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            async with SessionLocal() as db:
                await dispatch(agent_id, msg, db)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.exception("WebSocket error for agent %s: %s", agent_id, exc)
    finally:
        if agent_id:
            manager.disconnect(agent_id)
            logger.info("Agent %s disconnected", agent_id)
            async with SessionLocal() as db:
                from sqlalchemy import select
                from app.models.agent import Agent
                result = await db.execute(select(Agent).where(Agent.id == agent_id))
                agent = result.scalar_one_or_none()
                if agent:
                    agent.status = "disconnected"
                    await db.commit()


# Serve React dashboard static files
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

if STATIC_DIR.is_dir():
    # Serve assets (JS/CSS/images)
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="static-assets")

    @app.get("/{path:path}")
    async def spa_fallback(path: str):
        # Try serving the exact file first (e.g. favicon.ico, vite.svg)
        file = STATIC_DIR / path
        if path and file.is_file():
            return FileResponse(file)
        # Fall back to index.html for SPA routing
        return FileResponse(STATIC_DIR / "index.html")

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.database import engine, Base
from app.routers import auth, agents, tunnel_servers, tunnel_clients, port_forwards, service_templates


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

# WireWarp

Self-hosted WireGuard tunnel management platform. Deploy tunnel servers on VPS instances, connect gateway clients from your LAN, manage port forwarding — all from a single dashboard.

## Architecture

```
┌──────────────────────────────────────┐
│  Control Server (your home server)   │
│  FastAPI + PostgreSQL + React        │
│  docker compose up                   │
└──────────────┬───────────────────────┘
               │ wss:// (agents phone home)
       ┌───────┴────────┐
       ▼                ▼
┌──────────────┐  ┌──────────────────┐
│  VPS         │  │  Gateway LXC/VM  │
│  Tunnel      │◄─┤  Tunnel Client   │
│  Server      │  │  Agent           │
│  Agent       │  │                  │
│  (WireGuard  │  │  (WireGuard      │
│   + iptables │  │   + policy       │
│   DNAT)      │  │   routing)       │
└──────────────┘  └──────────────────┘
```

Three components:
- **Control Server** (`wirewarp-server/`) — Python/FastAPI + PostgreSQL + React dashboard, runs in Docker
- **Go Agent** (`wirewarp-agent/`) — single binary with `--mode server|client`, runs as systemd service
- **Web Dashboard** (`wirewarp-web/`) — React 18 + TypeScript + Tailwind CSS, built into the server container

## Quick Start

### 1. Start the control server

```bash
cd wirewarp-server
docker compose up -d --build
```

The dashboard is available at `http://localhost:8100`.

### 2. Create an admin user

```bash
docker compose exec api python -c "
import asyncio
from app.database import SessionLocal
from app.models.user import User
from passlib.context import CryptContext

pwd = CryptContext(schemes=['bcrypt'])

async def create():
    async with SessionLocal() as db:
        db.add(User(username='admin', email='admin@wirewarp.local', password_hash=pwd.hash('changeme'), role='admin'))
        await db.commit()
        print('Admin user created')

asyncio.run(create())
"
```

Login with `admin` / `changeme`.

### 3. Deploy a tunnel server agent

In the dashboard: **Agents** → **Add Agent** → select **Tunnel Server** → **Generate Token**.

Copy the install command and run it on your VPS as root:

```bash
curl -fsSL -o /usr/local/bin/wirewarp-agent \
  https://github.com/stepunu/wirewarp/raw/main/wirewarp-agent/dist/wirewarp-agent \
  && chmod +x /usr/local/bin/wirewarp-agent \
  && wirewarp-agent --mode server --url https://your-control-server:8100 --token XXXX-XXXX-XXXX
```

The agent registers, appears in the dashboard as "Connected", and waits for commands.

### 4. Deploy a tunnel client agent

Same flow: **Add Agent** → **Tunnel Client** → **Generate Token** → run on gateway LXC/VM.

Then go to **Tunnel Clients** in the dashboard to:
- Select which tunnel server to connect to
- Assign a tunnel IP (e.g. `10.0.0.2`)
- Enable **Is Gateway** if this machine routes traffic for other LAN devices
- Set the LAN network and LAN IP when gateway mode is enabled

### 5. Add port forwarding rules

Go to **Port Forwards** → **Add Forward**:
- Select the tunnel server and client
- Set protocol, public port, destination IP/port
- Use templates (DayZ, Minecraft, Web, RDP) for common setups

## Running the agent as a systemd service

A service template is included at `wirewarp-agent/scripts/wirewarp-agent.service`. After the first run (which creates the config at `/etc/wirewarp/agent.yaml`):

```bash
cp wirewarp-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wirewarp-agent
```

## Development

### Control server

```bash
cd wirewarp-server
docker compose up -d --build
```

### Web dashboard (dev mode with hot reload)

```bash
cd wirewarp-web
npm install
npm run dev
```

Vite proxies `/api` and `/ws` to `localhost:8100` automatically.

### Go agent

```bash
cd wirewarp-agent
make build    # builds to dist/wirewarp-agent (linux/amd64)
```

## Tech Stack

| Component | Stack |
|-----------|-------|
| Control Server | Python 3.11, FastAPI, SQLAlchemy 2.0 (async), PostgreSQL 16, Alembic |
| Web Dashboard | React 18, TypeScript, Tailwind CSS, React Query, Zustand, Vite |
| Go Agent | Go 1.22+, single binary, WebSocket client, WireGuard/iptables wrappers |
| Deployment | Docker Compose (server), systemd (agents) |

## Key Design Decisions

- **Agents phone home** — agents connect outbound to the control server via WebSocket. The control server never initiates connections to agents.
- **Private keys never leave the agent** — WireGuard keypairs are generated locally. Only public keys are sent to the control server.
- **Offline resilience** — agents apply last-known config from disk on startup before connecting. Tunnels survive control server outages.
- **No arbitrary shell execution** — agents only execute whitelisted command types. No eval, no bash -c.
- **Single binary** — the Go agent uses `--mode server|client` to select behavior. Same binary, different codepath.

## Project Structure

```
wirewarp/
├── wirewarp-server/          # Control server (FastAPI + PostgreSQL)
│   ├── app/
│   │   ├── main.py           # App entrypoint, WebSocket handler, SPA serving
│   │   ├── models/           # SQLAlchemy ORM models
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── routers/          # REST API endpoints
│   │   ├── websocket/        # WebSocket hub + message handlers
│   │   └── services/         # Command dispatch service
│   ├── alembic/              # Database migrations
│   ├── Dockerfile            # Multi-stage build (frontend + backend)
│   └── docker-compose.yml
├── wirewarp-web/             # React dashboard
│   └── src/
│       ├── pages/            # Login, Dashboard, Agents, Tunnels, Port Forwards
│       ├── components/       # Layout, StatusBadge
│       └── lib/              # API client, WebSocket store, types
├── wirewarp-agent/           # Go agent
│   ├── cmd/agent/main.go     # Entrypoint (--mode flag)
│   └── internal/
│       ├── config/           # YAML config persistence
│       ├── websocket/        # Persistent WebSocket connection
│       ├── executor/         # Command dispatcher
│       ├── handlers/         # Server + client command handlers
│       ├── wireguard/        # WireGuard + gateway routing wrappers
│       └── iptables/         # iptables DNAT/FORWARD wrappers
├── legacy/                   # Original bash scripts (reference)
└── ARCHITECTURE.md           # Full system design document
```

## Prerequisites

- **Control server**: Docker + Docker Compose
- **VPS (tunnel server)**: WireGuard, iptables, netfilter-persistent
- **Gateway (tunnel client)**: WireGuard, iptables, iproute2, netfilter-persistent

## License

Private project.

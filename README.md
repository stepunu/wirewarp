# WireWarp

Self-hosted WireGuard tunnel management platform. Deploy tunnel servers on VPS instances, connect gateway clients from your LAN, manage port forwarding — all from a single dashboard.

## Architecture

```
┌──────────────────────────────────────┐
│  Control Server (VPS or home server) │
│  FastAPI + PostgreSQL + React        │
│  docker compose up                   │
└──────────────┬───────────────────────┘
               │ WebSocket (agents phone home)
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

### 1. Deploy the Control Server

On a VPS or server with Docker installed:

```bash
git clone https://github.com/stepunu/wirewarp.git
cd wirewarp/wirewarp-server

# Set a secure secret key
export SECRET_KEY=$(openssl rand -hex 32)

# Start the control server
docker compose up -d --build
```

The dashboard is available at `http://<your-server-ip>:8100`.

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

### 3. Stamp the database migration version

```bash
docker compose exec api alembic stamp 0002
```

This marks the auto-created schema so future migrations work correctly.

### 4. Deploy a Tunnel Server agent

In the dashboard: **Agents** > **Add Agent** > select **Tunnel Server** > **Generate Token**.

Copy the install command and run it on your VPS as root. The install script handles all dependencies (WireGuard, iptables, iproute2):

```bash
curl -fsSL https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh | bash -s -- \
  --mode server --url http://<control-server-ip>:8100 --token XXXX-XXXX-XXXX
```

> If not running as root, prefix with `sudo`.

Once the agent shows as **Connected** in the dashboard, go to **Tunnel Servers** and click **Edit** to configure:
- **Public IP** — the VPS public IP (used as WireGuard endpoint)
- **WG Port** — WireGuard listen port (default: 51820)
- **Public Interface** — the VPS public network interface (usually `eth0`)
- **Tunnel Network** — the WireGuard subnet (default: `10.0.0.0/24`)

Click **Save** to push the `wg_init` command to the agent.

### 5. Deploy a Tunnel Client agent

Same flow: **Add Agent** > **Tunnel Client** > **Generate Token** > run the install command on the gateway LXC/VM.

Then go to **Tunnel Clients** in the dashboard and click **Edit** to configure:
- **Connect to Server** — select the tunnel server from step 4
- **Tunnel IP** — assign a tunnel IP (e.g. `10.0.0.3`)
- **Is Gateway** — enable if this machine routes traffic for other LAN devices
- **LAN Network** — the local network (e.g. `192.168.20.0/24`)
- **LAN IP** — the gateway's LAN IP (e.g. `192.168.20.110`)

Click **Save** to push `wg_configure` to the client agent. The tunnel will establish automatically:
1. Client agent configures WireGuard and applies gateway routing
2. Client reports its public key back to the control server
3. Control server sends `wg_add_peer` to the tunnel server
4. Handshake completes, traffic flows

### 6. Add port forwarding rules (optional)

Go to **Port Forwards** > **Add Forward**:
- Select the tunnel server and client
- Set protocol, public port, destination IP/port
- Use templates (DayZ, Minecraft, Web, RDP) for common setups

## Verifying the Gateway

Run the verification script on the gateway to check all routing rules are applied:

```bash
curl -fsSL https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/verify-gateway.sh | bash
```

## Updating Agents

```bash
systemctl stop wirewarp-agent
curl -fsSL -o /usr/local/bin/wirewarp-agent \
  https://github.com/stepunu/wirewarp/raw/main/wirewarp-agent/dist/wirewarp-agent
chmod +x /usr/local/bin/wirewarp-agent
systemctl start wirewarp-agent
```

The agent tears down WireGuard and routing on stop, and restores everything on start from saved config.

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
- **Clean shutdown** — agents tear down WireGuard interfaces and routing rules on stop, preventing leftover rules from breaking connectivity.
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
│   ├── scripts/              # install.sh, verify-gateway.sh, systemd service
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
- **Agents**: The install script handles all dependencies automatically. Supports Debian/Ubuntu, RHEL/Fedora, and Alpine.

## License

Private project.

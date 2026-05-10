# WireWarp

Self-hosted WireGuard tunnel management. Replace ad-hoc bash scripts with a single dashboard: deploy a Go agent on any VPS, register it from the web UI, manage port forwards, gateway routing, and per-user VPN access — without touching config files by hand.

## Why

Managing WireGuard across a homelab — multiple VPS exit nodes, gateway LXCs, port forwards, per-user VPN profiles — usually means SSH'ing around editing `wg0.conf`, `iptables -t nat`, and `ip rule`. WireWarp pushes everything from one control server over WebSocket: agents phone home, take whitelisted commands, and apply WireGuard + iptables changes locally. Private keys never leave the agent, and tunnels stay up if the control server goes down.

## Features

- **Tunnel servers and clients** — register VPS or gateway agents, push initial config, edit live. No SSH after install.
- **Multi-server gateways** — one gateway client can peer with N tunnel servers simultaneously; each attachment gets its own `wgN` interface, fwmark, and routing table.
- **Multi-IP per tunnel server** — bind port forwards to a specific public IP; DNAT rules disambiguate by destination IP.
- **Port forwarding** — TCP/UDP DNAT with templates (DayZ, Minecraft, Web, RDP). Live iptables preview.
- **VPN endpoints + per-user permissions** — admins configure a VPN endpoint per gateway; users get device profiles + QR code at `/vpn`. Per-(user, endpoint) firewall rules.
- **Auth** — local users (bcrypt), OIDC (Google/GitHub/generic), and LDAP. Roles: `admin`, `operator`, `viewer`.
- **Audit log** — every dispatched command logged with actor, type, and details. Visible in dashboard.
- **Real-time updates** — single WebSocket hub fan-out; no polling. Dashboard reacts within ~50 ms of a server-side change.
- **LAN client discovery + DNS sync** — gateway agents scrape conntrack for LAN hosts; DNS records sync to Cloudflare automatically when egress IP changes (or surface a manual-update notice).
- **Mobile-responsive dashboard** — phone-first layout with bottom-tab nav, full-screen sheets for dialogs, table-as-card lists. Viewer role lands on `/vpn` directly.
- **One-command install** — `curl … | bash -s -- --mode <s|c>`. Idempotent. Supports Debian/Ubuntu, RHEL/Fedora, Alpine.
- **In-place agent update** — dashboard "Update Agent" button. SHA256-verified, restart via systemd.
- **Offline resilience** — agents apply last-known config from disk before the WS connection completes; tunnels survive control-server outages.

## Architecture

```
┌──────────────────────────────────────┐
│  Control Server                      │
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

- **Control Server** (`wirewarp-server/`) — Python/FastAPI + PostgreSQL + React dashboard, runs in Docker. Only piece with a public address.
- **Go Agent** (`wirewarp-agent/`) — single static binary with `--mode server|client`, runs as systemd service.
- **Web Dashboard** (`wirewarp-web/`) — React 19 + TypeScript + plain CSS (OKLCH design tokens), built into the server image.

Full design: [`ARCHITECTURE.md`](./ARCHITECTURE.md). Per-feature specs: [`docs/superpowers/specs/`](./docs/superpowers/specs/).

## Quick Start

### 1. Deploy the Control Server

On a VPS or server with Docker installed:

```bash
cd /opt
git clone https://github.com/stepunu/wirewarp.git
cd wirewarp/wirewarp-server

export SECRET_KEY=$(openssl rand -hex 32)
docker compose up -d --build
```

Dashboard at `http://<your-server-ip>:8100`. Front it with Traefik / Caddy / nginx for TLS.

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

### 3. Configure the public URL

In the dashboard, **Settings → General → Public URL**: the address agents reach the control server at (e.g. `https://wirewarp.example.com`). Used in the install command and on agent reconnect. Empty value = use the browser origin.

### 4. Deploy a Tunnel Server agent

In the dashboard: **Agents → Add Agent → Tunnel Server → Generate Token**.

Copy and run on your VPS as root:

```bash
curl -fsSL https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh | bash -s -- \
  --mode server --url http://<control-server>:8100 --token XXXX-XXXX-XXXX
```

> **Co-located setup**: control server (Docker, port 8100) and tunnel server agent (systemd, WireGuard 51820) can share the same VPS. Use `--url http://localhost:8100`.

Once **Connected**, open **Tunnel Servers → Edit** to set Public IP / WG port / Public interface / Tunnel network. Save → control server pushes `wg_init` (IP forwarding + MASQUERADE applied automatically).

### 5. Deploy a Tunnel Client agent

**Add Agent → Tunnel Client → Generate Token**, run on the gateway LXC/VM. Then **Tunnel Clients → Edit**:

- Connect to the tunnel server from step 4
- Tunnel IP (e.g. `10.21.0.3`)
- Is Gateway (enable to route LAN traffic via the VPS)
- LAN Network + LAN IP

Save → control server orchestrates the handshake automatically:

1. Client agent applies WireGuard + gateway routing
2. Client reports its public key
3. Control server pushes `wg_add_peer` to the tunnel server
4. Handshake completes, traffic flows

### 6. Add port forwards (optional)

**Port Forwards → New Forward**: pick attachment, public IP (multi-IP setups), protocol, ports. Use a template for common setups. Live iptables preview shows you the rule that will be installed.

### 7. Issue VPN profiles to users (optional)

**VPN Endpoints → New Endpoint** on a gateway client → **Permissions** to grant access per user. End-users log in and visit `/vpn` to download their `.conf` or scan a QR code from a phone.

## Verifying a gateway

```bash
curl -fsSL https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/verify-gateway.sh | bash
```

Walks through the 7-step policy-routing assertion and prints what's missing.

## LAN device setup (gateway mode)

When a tunnel client is configured as a gateway, other LAN devices route through the VPS by setting their default gateway to the tunnel client's LAN IP.

On each LAN device:
- **Default Gateway** — the tunnel client's LAN IP (e.g. `192.168.1.10`)
- **DNS** — a public resolver (`1.1.1.1` or `8.8.8.8`); the tunnel doesn't carry DNS

Proxmox LXC example: edit `/etc/network/interfaces`, set `gateway 192.168.1.10`.

## Updating agents

**From the dashboard** (recommended): **Agents → [name] → Update Agent**. Downloads the latest binary from GitHub, verifies SHA256, restarts via systemd. No SSH.

**Manually**:

```bash
systemctl stop wirewarp-agent
curl -fsSL -o /usr/local/bin/wirewarp-agent \
  https://github.com/stepunu/wirewarp/raw/main/wirewarp-agent/dist/wirewarp-agent
chmod +x /usr/local/bin/wirewarp-agent
systemctl start wirewarp-agent
```

The agent tears down WireGuard and routing on stop, restores from saved config on start.

CI rebuilds the binary on every push to `main` and commits it back. Agents report their git-SHA version in the **Version** column.

## Troubleshooting

**Agent can't reach the internet after stopping:** older agents left routing rules behind. `wg-quick down wg0` and delete ip rules at priorities 99, 100, 200, 5000, 5100, 30000.

**Tunnel handshake but no internet on LAN devices:** the tunnel server is missing IP forwarding or MASQUERADE. Re-save the tunnel server config to re-fire `wg_init`.

**`wg show` shows 0 B received:** the tunnel server doesn't have the client as a peer. Check the tunnel server agent logs for `wg_add_peer` errors; re-save the tunnel client config.

**Install script hangs on Debian:** older script versions waited on the `iptables-persistent` interactive prompt. Current script sets `DEBIAN_FRONTEND=noninteractive`.

**Control server unreachable after gateway routing applies:** the agent adds an exception at priority 99 for the control server IP. Older agents without this fix will rip themselves off the network — update.

## Development

### Control server

```bash
cd wirewarp-server
docker compose up -d --build
```

Migrations run automatically (`alembic upgrade head`) before `uvicorn` starts.

### Web dashboard (hot reload)

```bash
cd wirewarp-web
npm install
npm run dev
```

Vite proxies `/api` and `/ws` to `localhost:8100`.

### Go agent

```bash
cd wirewarp-agent
make build    # → dist/wirewarp-agent (linux/amd64, static)
```

## Tech Stack

| Component | Stack |
|-----------|-------|
| Control server | Python 3.11+, FastAPI, SQLAlchemy 2.0 async, asyncpg, Alembic, Pydantic v2, python-jose, passlib+bcrypt, authlib (OIDC), ldap3 (LDAP) |
| Web dashboard | React 19, TypeScript 5.9, Vite 7, plain CSS (OKLCH tokens), TanStack Query v5, Zustand, React Router v7 |
| Go agent | Go 1.22+, `nhooyr.io/websocket`, `gopkg.in/yaml.v3` — single static binary |
| Database | PostgreSQL 16 |
| Deployment | Docker Compose (server), systemd (agents) |

## Key design decisions

- **Agents phone home** — outbound WebSocket only. The control server never connects to agents.
- **Private keys never leave the agent** — WireGuard keypairs are generated on-host; only public keys hit the control server.
- **Offline resilience** — agents read disk config and bring up tunnels before the WS connection completes. Tunnels survive control-server outages.
- **Clean shutdown** — agents tear down WireGuard + routing on stop. No leftover rules.
- **No arbitrary shell execution** — agents execute whitelisted command types only. No `eval`, no `bash -c`.
- **Single binary** — `--mode server|client` selects behavior. Same binary either way.
- **Gateways are inbound-only** — gateway clients DNAT inbound traffic to LAN hosts. They do not route LAN-originated outbound traffic through any tunnel; the LAN's normal default router does.
- **Each tunnel server gets a unique `/24`** — auto-allocated from `10.21.0.0/24`, `10.22.0.0/24`, … on registration. Cross-server routing and rebase rely on it.

## Project structure

```
wirewarp/
├── wirewarp-server/          # Control server (FastAPI + PostgreSQL)
│   ├── app/
│   │   ├── main.py           # App entrypoint, WebSocket handler, SPA serving
│   │   ├── models/           # SQLAlchemy ORM models
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── routers/          # REST API endpoints (auth, agents, tunnels,
│   │   │                     #   port-forwards, vpn-endpoints, oidc, ldap, …)
│   │   ├── websocket/        # WebSocket hub + agent message handlers
│   │   ├── realtime/         # Event bus + typed dashboard emitters
│   │   └── services/         # Command dispatch, network alloc, dns_sync, secrets
│   ├── alembic/              # Migrations 0001 … current head
│   ├── Dockerfile            # Multi-stage build (frontend + backend)
│   └── docker-compose.yml
├── wirewarp-web/             # React dashboard
│   └── src/
│       ├── pages/            # Login, Dashboard, Agents, TunnelServers,
│       │                     #   TunnelClients, PortForwards, VpnEndpoints,
│       │                     #   MyVpn, Users, Settings, …
│       ├── components/       # Layout, BottomNav, ui.tsx, icons.tsx,
│       │                     #   CommandPalette, HelpOverlay, Toasts
│       └── lib/              # api.ts, realtime.ts, types.ts
├── wirewarp-agent/           # Go agent
│   ├── cmd/agent/main.go     # Entrypoint (--mode flag)
│   ├── scripts/              # install.sh, verify-gateway.sh, systemd unit
│   └── internal/
│       ├── config/           # YAML config persistence
│       ├── websocket/        # Persistent WebSocket connection
│       ├── executor/         # Command dispatcher
│       ├── handlers/         # Server + client command handlers
│       ├── wireguard/        # WireGuard + gateway routing wrappers
│       └── iptables/         # iptables DNAT/FORWARD wrappers
├── legacy/                   # Original bash scripts (reference only)
├── docs/superpowers/specs/   # Per-feature design specs
├── ARCHITECTURE.md           # Full system design
├── CLAUDE.md                 # Project instructions for Claude Code
└── tasks.md                  # Phase-by-phase task list
```

## Prerequisites

- **Control server**: Docker + Docker Compose
- **Agents**: nothing — the install script handles WireGuard, iptables, iproute2 on Debian/Ubuntu, RHEL/Fedora, Alpine.

## License

Private project.

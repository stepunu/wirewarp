# WireWarp — System Architecture & Project Structure

**Version:** 0.4 (Implementation snapshot)
**Date:** 2026-05-31

> This began as a planning document. It has been updated for the current
> implementation where practical, but the concise source-of-truth snapshot
> is now `CODEBASE_GUIDE.md`, `MODULE_MAP.md`, and `DOMAIN_MODEL.md`.

---

## Overview

WireWarp is a self-hosted WireGuard tunnel management platform. It consists of three components:

1. **Control Server** — Web dashboard + API + database, runs on your home server
2. **Tunnel Server Agent** — Runs on each VPS, manages WireGuard server,
   iptables, and optional Security Edge services
3. **Tunnel Client Agent** — Runs on each gateway LXC/VM, manages WireGuard client config

Agents connect **outbound** to the control server via persistent WebSocket connections. The control server never initiates connections to agents — agents phone home.

---

## High-Level Architecture

```
┌────────────────────────────────────────────────────────────┐
│  HOME SERVER                                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  WireWarp Control Server                             │  │
│  │  - Web Dashboard (React)                             │  │
│  │  - REST API (FastAPI)                                │  │
│  │  - WebSocket Hub (agents connect here)               │  │
│  │  - PostgreSQL Database                               │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────┬────────────────────────┬─────────────┘
                      │  wss:// (agents         │
                      │  phone home)            │
         ┌────────────┘                         └────────────┐
         ▼                                                    ▼
┌─────────────────────┐                      ┌──────────────────────┐
│  VPS                │                      │  Gateway LXC/VM      │
│                     │                      │                      │
│  Tunnel Server      │◄─── WireGuard ──────►│  Tunnel Client       │
│  Agent              │     Tunnel           │  Agent               │
│                     │                      │                      │
│  - WireGuard server │                      │  - WireGuard client  │
│  - iptables / DNAT  │                      │  - LAN forwarding    │
│  - Public IP mgmt   │                      │  - Egress pins       │
│  - Peer management  │                      │  - Reports status    │
│  - Optional edge    │                      │                      │
│    stack            │                      │                      │
└─────────────────────┘                      └──────────────────────┘
```

---

## Component Details

### 1. Control Server (`wirewarp-server/`)

The brain of the operation. Runs on any always-on machine (home server, Proxmox LXC, etc.). Must be accessible from the internet for agents to reach it (can be fronted by Traefik/Cloudflare).

**Responsibilities:**
- Serve the web dashboard
- Expose REST API for the dashboard
- Maintain WebSocket connections with all registered agents
- Store all configuration, state, and history in PostgreSQL
- Generate registration tokens for new agents
- Push commands to agents, receive status/metrics back

**Stack:**
- Python 3.11+ / FastAPI
- PostgreSQL (via SQLAlchemy ORM)
- WebSocket hub (FastAPI native WebSockets)
- React 19 + TypeScript + plain CSS (built into `wirewarp-server/static`
  and served by FastAPI)

---

### 2. Tunnel Server Agent (`wirewarp-agent/ --mode server`)

Runs on each VPS that acts as a WireGuard endpoint. Single Go binary managed by systemd.

**Responsibilities:**
- Register with control server on first run using a token
- Maintain persistent WebSocket connection to control server
- Execute commands received from control server:
  - Initialize WireGuard interface
  - Add / remove peers
  - Add / remove iptables DNAT rules
  - Reconcile Security Edge desired state when enabled
  - Stop Security Edge services on reversible disable
  - Render and health-check local Nginx proxy cache when configured
  - Save iptables rules (netfilter-persistent)
- Collect and report metrics (peer status, bandwidth, system stats)
- Manage `/etc/wireguard/` config files
- Optionally manage Traefik, CrowdSec/AppSec, Traefik JSON access logs, and
  local Nginx `proxy_cache`

**Stack:**
- Go (single binary, ~10MB, <30MB RAM idle)
- systemd service
- Requires root/systemd service privileges with `CAP_NET_ADMIN` and `CAP_NET_RAW`.

---

### 3. Tunnel Client Agent (`wirewarp-agent/ --mode client`)

Runs on each gateway LXC or VM that needs to connect through a VPS tunnel. Single Go binary managed by systemd.

**Responsibilities:**
- Register with control server on first run using a token
- Maintain persistent WebSocket connection to control server
- Execute commands received from control server:
  - Configure one WireGuard client interface per attachment (`wg0`, `wg1`, ...)
  - Bring interface up/down
  - Update peer endpoint if tunnel server changes
  - Apply policy-based routing for gateway mode (see [Gateway Routing](#gateway-routing-policy-based-routing))
- Report connection status and basic metrics back to control server

**Stack:**
- Go (same binary as server agent, different mode flag)
- systemd service
- Requires root/systemd service privileges with `CAP_NET_ADMIN` and `CAP_NET_RAW`.

**Note on shared binary:** The server agent and client agent share a binary but have substantially different codepaths — the server agent manages iptables DNAT rules and peer lists, while the client agent manages policy routing, fwmark/CONNMARK rules, and MSS clamping. The `--mode` flag selects which executor modules are loaded at startup. Shared code is limited to WebSocket connection management, registration, config persistence, and metrics collection.

---

## Agent Registration Flow

```
1. Admin generates a registration token in the dashboard
   (token is single-use; expiry is configurable)

2. Dashboard shows a single copy-paste command with everything baked in:
   curl -fsSL https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh | bash -s -- \
     --mode server --url https://wirewarp.example.com \
     --token ABRM-7XK2-9QLP
   # or for clients:
   curl -fsSL https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh | bash -s -- \
     --mode client --url https://wirewarp.example.com \
     --token CXNP-3YT8-1MWZ

   No prompts, no manual input. One command, paste and go.

3. Install script:
   - Detects OS (Debian/Ubuntu, RHEL/Fedora, Alpine)
   - Installs WireGuard if missing
   - Downloads the agent binary
   - Creates systemd service with the provided URL + token
   - Starts service

4. Agent starts → dials wss://wirewarp.example.com/ws/agent
   → sends { type: "register", token: "ABRM-7XK2-9QLP", hostname: "vps-nyc-01" }

5. Control server:
   - Validates token
   - Creates agent record in DB
   - Marks token as used
   - Agent now appears in dashboard as "Connected"
```

---

## WebSocket Message Protocol

All control server ↔ agent communication happens over WebSocket using JSON messages.

### Control Server → Agent (Commands)

```json
{
  "id": "cmd-uuid-here",
  "type": "wg_add_peer",
  "params": {
    "peer_name": "home_server",
    "public_key": "abc123...",
    "tunnel_ip": "10.0.0.2",
    "allowed_ips": ["10.0.0.2/32", "192.168.1.0/24"]
  }
}
```

```json
{
  "id": "cmd-uuid-here",
  "type": "iptables_add_forward",
  "params": {
    "protocol": "tcp",
    "public_port": 25565,
    "destination_ip": "10.0.0.2",
    "destination_port": 25565
  }
}
```

### Agent → Control Server (Responses & Events)

```json
{
  "command_id": "cmd-uuid-here",
  "type": "command_result",
  "success": true,
  "output": "Peer added successfully"
}
```

```json
{
  "type": "metrics",
  "timestamp": "2026-02-15T10:00:00Z",
  "peers": [
    {
      "public_key": "abc123...",
      "endpoint": "1.2.3.4:51820",
      "last_handshake": "2026-02-15T09:58:00Z",
      "rx_bytes": 104857600,
      "tx_bytes": 52428800
    }
  ],
  "system": {
    "cpu_percent": 2.1,
    "mem_used_mb": 128,
    "disk_used_percent": 45.2
  }
}
```

```json
{
  "type": "heartbeat",
  "timestamp": "2026-02-15T10:00:00Z"
}
```

---

## Node Edge / Security Edge

Tunnel server nodes carry an explicit edge capability:

- `tcp_udp_only`: WireGuard, attachments, raw TCP/UDP forwards, healing, and
  route restore only.
- `security_edge`: Traefik, CrowdSec/AppSec, live access events, route/profile
  policy, rendered config history, and optional local Nginx cache.

New server nodes default to `tcp_udp_only`. Existing nodes are migrated to
`security_edge` only when they already have Traefik/CrowdSec snapshots, HTTP
routes, or edge policy. Edge APIs are guarded; TCP/UDP-only or disabled nodes
return machine-readable `edge_feature_disabled` errors.

Security Edge disable is stop-only and reversible. The agent disables/stops
Traefik, CrowdSec, and Nginx cache services, while preserving route definitions,
generated configs, packages, secrets, and ACME state. Enabling later dispatches
the saved desired state again.

Policy resolves in this order:

```text
global edge defaults -> node defaults -> route profile -> route override -> path rule override
```

The public edge path for cached routes is:

```text
client -> Traefik security edge -> local Nginx proxy_cache -> origin over WireGuard
```

Nginx cache availability is gated by agent health proof: either `MISS -> HIT` or
a valid `BYPASS`. Full-node and exact host/path purge are implemented; broader
host/prefix/route purge scopes require a cache index.

---

## Database Schema

The current schema source of truth is the SQLAlchemy model set in
`wirewarp-server/app/models/` plus Alembic migrations through
`0038_edge_upstream_pools`. The SQL below is the original planning sketch and
is kept only as historical context; it omits later tables such as
attachments, tunnel server IPs, users/roles, VPN endpoints/profiles,
LAN clients, WireGuard peer snapshots, traffic samples, CrowdSec/Traefik
snapshots, security events, Node Edge component state, profiles, policies, path
rules, config versions, fragments, upstream pools, access events, cache
snapshots, and edge route config.

```sql
-- Agents (tunnel servers and clients)
CREATE TABLE agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    type        TEXT CHECK(type IN ('server', 'client')) NOT NULL,
    hostname    TEXT,
    public_ip   TEXT,
    status      TEXT CHECK(status IN ('connected', 'disconnected', 'pending')) DEFAULT 'pending',
    version     TEXT,
    last_seen   TIMESTAMP,
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Registration tokens (single-use)
CREATE TABLE registration_tokens (
    token       TEXT PRIMARY KEY,
    agent_type  TEXT CHECK(agent_type IN ('server', 'client')) NOT NULL,
    used        BOOLEAN DEFAULT FALSE,
    expires_at  TIMESTAMP NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Tunnel Servers (VPS-specific config, extends agents)
CREATE TABLE tunnel_servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID REFERENCES agents(id) ON DELETE CASCADE,
    wg_port         INTEGER DEFAULT 51820,
    wg_interface    TEXT DEFAULT 'wg0',
    public_ip       TEXT,
    public_iface    TEXT DEFAULT 'eth0',
    wg_public_key   TEXT,
    tunnel_network  TEXT DEFAULT '10.0.0.0/24',
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Tunnel Clients (LXC/VM-specific config, extends agents)
CREATE TABLE tunnel_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID REFERENCES agents(id) ON DELETE CASCADE,
    tunnel_server_id UUID REFERENCES tunnel_servers(id),
    tunnel_ip       TEXT,                    -- e.g. 10.0.0.2
    vm_network      TEXT,                    -- e.g. 192.168.1.0/24
    lan_ip          TEXT,                    -- e.g. 192.168.1.10 (this machine's LAN IP)
    is_gateway      BOOLEAN DEFAULT FALSE,   -- true = accepts inbound forwarding to LAN devices
    wg_public_key   TEXT,
    status          TEXT DEFAULT 'disconnected',
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Port Forwarding Rules
CREATE TABLE port_forwards (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tunnel_server_id UUID REFERENCES tunnel_servers(id) ON DELETE CASCADE,
    tunnel_client_id UUID REFERENCES tunnel_clients(id) ON DELETE CASCADE,
    protocol        TEXT CHECK(protocol IN ('tcp', 'udp')) NOT NULL,
    public_port     INTEGER NOT NULL,
    destination_ip  TEXT NOT NULL,           -- can be tunnel IP or a LAN IP behind the peer
    destination_port INTEGER NOT NULL,
    description     TEXT,                    -- optional label, e.g. "DayZ Server 2"
    active          BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE(tunnel_server_id, protocol, public_port)
);

-- Service Templates (presets for common port sets)
CREATE TABLE service_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT UNIQUE NOT NULL,    -- e.g. "DayZ", "Minecraft", "Web"
    protocol        TEXT CHECK(protocol IN ('tcp', 'udp', 'both')) NOT NULL,
    ports           TEXT NOT NULL,           -- e.g. "2302-2305,27016"
    is_builtin      BOOLEAN DEFAULT FALSE,   -- true = shipped with WireWarp
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Command History / Audit Log
CREATE TABLE command_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID REFERENCES agents(id),
    command_type TEXT NOT NULL,
    params      JSONB,
    success     BOOLEAN,
    output      TEXT,
    executed_at TIMESTAMP DEFAULT NOW()
);

-- Metrics (time-series, consider partitioning by month)
CREATE TABLE metrics (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID REFERENCES agents(id) ON DELETE CASCADE,
    timestamp   TIMESTAMP NOT NULL,
    data        JSONB NOT NULL
);

-- Users (dashboard authentication)
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        TEXT UNIQUE NOT NULL,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT CHECK(role IN ('admin', 'viewer')) DEFAULT 'admin',
    created_at      TIMESTAMP DEFAULT NOW()
);
```

---

## Project Repository Structure

```
wirewarp/
├── wirewarp-server/              # Control server (Python/FastAPI)
│   ├── app/
│   │   ├── main.py               # FastAPI app entrypoint
│   │   ├── config.py             # Settings (env vars)
│   │   ├── database.py           # SQLAlchemy setup
│   │   ├── models/               # ORM models, split per table/domain
│   │   ├── schemas/              # Pydantic request/response schemas
│   │   ├── routers/
│   │   │   ├── auth.py           # Login, token endpoints
│   │   │   ├── users.py          # Admin user management
│   │   │   ├── agents.py         # Agent registration + management
│   │   │   ├── tunnel_servers.py # VPS tunnel server endpoints
│   │   │   ├── tunnel_server_ips.py
│   │   │   ├── tunnel_clients.py # Client endpoints
│   │   │   ├── tunnel_client_attachments.py
│   │   │   ├── port_forwards.py  # Port forwarding CRUD
│   │   │   ├── vpn_endpoints.py
│   │   │   ├── vpn_profiles.py
│   │   │   ├── security.py
│   │   │   ├── nodes.py          # Unified node + edge capability APIs
│   │   │   ├── edge.py           # Route/profile/path/upstream APIs
│   │   │   ├── edge_node.py      # Node-scoped edge runtime APIs
│   │   │   ├── settings.py
│   │   │   └── audit.py
│   │   ├── websocket/
│   │   │   ├── hub.py            # WebSocket connection manager
│   │   │   └── handlers.py       # Message type handlers
│   │   ├── realtime/             # Dashboard event bus
│   │   └── services/
│   │       ├── agent_commands.py # Build + send commands to agents
│   │       ├── tunnel_server_ops.py
│   │       ├── vpn_ops.py
│   │       ├── traefik_ops.py
│   │       ├── crowdsec_ops.py
│   │       ├── edge_ops.py
│   │       ├── edge_resources.py
│   │       ├── edge_runtime.py
│   │       ├── edge_cache_ops.py
│   │       └── traffic_sampler.py
│   ├── alembic/                  # DB migrations through 0038
│   ├── requirements.txt
│   ├── Dockerfile
│   └── docker-compose.yml        # Full stack (api + postgres + web)
│
├── wirewarp-web/                 # Dashboard (React/TypeScript)
│   ├── src/
│   │   ├── pages/                # Dashboard, Nodes, Agents, Tunnels, LAN,
│   │   │                         # PortForwards, VPN, Users, Security
│   │   ├── components/           # Layout, UI primitives, tables, cards
│   │   └── lib/
│   │       ├── api.ts            # API client
│   │       ├── realtime.ts       # Active dashboard WS invalidation
│   │       └── types.ts
│   ├── package.json
│   └── Dockerfile
│
├── wirewarp-agent/               # Go agent (server + client modes)
│   ├── cmd/
│   │   └── agent/
│   │       └── main.go           # Entrypoint, reads --mode flag
│   ├── internal/
│   │   ├── config/               # YAML config + env
│   │   ├── websocket/            # Persistent WS connection + reconnect
│   │   ├── executor/             # Command dispatcher
│   │   ├── handlers/             # Server/client/VPN/edge/heal commands
│   │   │                         # edge_desired, edge_lifecycle,
│   │   │                         # edge_cache, server_edge_reconciler
│   │   ├── wireguard/            # wg / wg-quick wrappers
│   │   ├── iptables/             # iptables wrappers
│   │   ├── lanscan/              # LAN client discovery
│   │   └── validate/             # Payload validation
│   ├── scripts/
│   │   ├── install.sh            # curl | bash installer
│   │   ├── verify-gateway.sh
│   │   └── wirewarp-agent.service
│   ├── go.mod
│   └── Makefile
│
├── legacy/                        # Original bash scripts (reference)
│   ├── wirewarp.sh               # Server management script v2
│   ├── wirewarp-client.sh        # Client setup script v2
│   ├── wirewarp-client.uninstall.sh
│   ├── plans/                    # Earlier improvement plans
│   └── README.md                 # Original usage docs
└── ARCHITECTURE.md               # This file
```

---

## Docker Compose (Control Server)

```yaml
# wirewarp-server/docker-compose.yml
services:
  api:
    build:
      context: ..
      dockerfile: wirewarp-server/Dockerfile
    ports:
      - "8100:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://wirewarp:secret@db:5432/wirewarp
      - SECRET_KEY=${SECRET_KEY}
      - AGENT_TOKEN_EXPIRY_HOURS=24
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=wirewarp
      - POSTGRES_USER=wirewarp
      - POSTGRES_PASSWORD=secret
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U wirewarp"]
      interval: 5s
      retries: 5

volumes:
  postgres_data:
```

---

## Agent Install Flow (End-to-End)

```
Admin in Dashboard:
  1. Go to "Agents" → "Add Agent"
  2. Select type: Tunnel Server
  3. Dashboard generates a single command with the token embedded
  4. Click "Copy" to copy it to clipboard

On VPS (single command, no prompts):
  curl -fsSL https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh | bash -s -- \
    --mode server --url https://wirewarp.example.com --token ABRM-7XK2-9QLP
  > Detecting OS... Ubuntu 22.04
  > Installing WireGuard...
  > Downloading WireWarp agent...
  > Creating systemd service...
  > Registering with control server...
  > ✅ Connected! Agent appears in your dashboard.

On Gateway LXC (same idea):
  curl -fsSL https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/install.sh | bash -s -- \
    --mode client --url https://wirewarp.example.com --token CXNP-3YT8-1MWZ
  > ...
  > ✅ Connected!

Back in Dashboard:
  - Both agents appear as "Connected"
  - Configure the tunnel server public interface/IPs
  - Mark the tunnel client as a gateway if it forwards inbound traffic to LAN devices
  - Add an attachment between the client and server
  - Add port forwards from the port forwarding tab
  - Everything is applied live via WebSocket commands
```

---

## Build Order (What to Build First)

1. **DB schema + FastAPI skeleton** — models, auth, basic CRUD endpoints
2. **WebSocket hub** — agent connection management, command dispatch
3. **Go agent skeleton** — connects, registers, heartbeats, executes no-ops
4. **WireGuard + iptables wrappers in agent** — the actual system operations
5. **React dashboard** — starts minimal (agent list, status), grows from there
6. **Install scripts** — last, once agent binary is stable

---

## Security Considerations

- Production agents should use WSS/TLS; HTTP requires explicit `--insecure`.
- Registration tokens are single-use, expiry is configurable, and tokens are stored hashed.
- Agents authenticate subsequent connections with a long-lived JWT issued at registration or manually reissued by an admin.
- TLS verification uses the standard Go verifier unless `--insecure` is enabled.
- Agent command whitelist — only specific operations allowed, no arbitrary remote shell.
- The systemd service runs the agent with `CAP_NET_ADMIN` and `CAP_NET_RAW`; package install flows that need broader privileges escape through controlled `systemd-run` units.
- Security Edge services are optional per server node. Disable is intentionally
  non-destructive so certificates, generated config, package state, and route
  definitions survive toggles.
- Edge access events never include request bodies. Query/header capture follows
  conservative API defaults.
- Control server behind Traefik with rate limiting on the WebSocket endpoint

### Key Generation & Privacy Constraint

Mesh WireGuard private keys are **generated on the agent and never transmitted**. Road-warrior VPN profile private keys are generated server-side, returned once in the rendered client config, and not stored. For mesh interfaces, the flow is:

1. On `wg_init` or `wg_attach`, the agent creates or reuses a local key for that interface.
2. Private key files are stored under `/etc/wireguard/` with restrictive permissions.
3. Agent derives the public key (`wg pubkey`) and returns **only the public key** in the command result.
4. Control server stores the public key in `tunnel_servers.wg_public_key`, `tunnel_client_attachments.wg_public_key`, or `vpn_endpoints.wg_public_key` as appropriate.

A compromised control server cannot decrypt tunnel traffic because it never holds any private key.

---

## Agent Resilience (Offline Mode)

Agents must remain functional if the control server is unreachable (outage, network partition, reboot order).

**Rules:**
- After successful WireGuard commands, the agent persists interface config and attachment state under `/etc/wireguard/` and `/etc/wirewarp/`.
- After iptables/routing changes, the agent persists what it can through `netfilter-persistent` and the boot-time `wirewarp-routing.service`.
- On agent startup:
  1. Apply the last known config from disk immediately (bring up the WireGuard interface)
  2. Attempt WebSocket connection to control server in the background
  3. If connection fails, keep retrying with exponential backoff — tunnel stays up throughout

This means a VPS or gateway reboot survives a control server outage with zero tunnel downtime.

### WebSocket Reconnection Strategy

When the WebSocket connection drops (server restart, network blip, etc.), the agent reconnects automatically:

- **Initial retry:** 1 second after disconnect
- **Exponential backoff:** each subsequent retry doubles the wait (1s → 2s → 4s → 8s → ...)
- **Max backoff cap:** 60 seconds (never waits longer than this)
- **Jitter:** add ±25% random jitter to prevent all agents reconnecting simultaneously after a control server restart
- **Reconnect vs re-register:** Agents authenticate reconnections using their JWT from the initial registration. If the JWT is expired, the agent requests a refresh. Full re-registration (with a new token) is only needed if the agent record is deleted from the control server.
- **Heartbeat interval:** 30 seconds. If the control server receives no heartbeat for 90 seconds, it marks the agent as `disconnected`.
- **Agent-side timeout:** If no message (including pong frames) is received from the control server for 90 seconds, the agent considers the connection dead and initiates reconnect.

---

## Gateway Routing (Policy-Based Routing)

Standard `wg-quick` is insufficient for WireWarp's gateway scenario. The current implementation is inbound-only by default: a gateway handles reply routing for inbound DNAT'd flows and does not install the old blanket `ip rule from <LANNetwork> table <wg>` rule. Optional LAN-originated egress through a VPS is explicit per LAN client via `set_lan_egress`.

This is the most complex part of the client agent. The legacy bash scripts solved this through trial and error — the Go agent must replicate this logic precisely.

### Why it's complex

A gateway LXC sits between a LAN (e.g. `192.168.1.0/24`) and one or more WireGuard tunnel attachments. Inbound traffic arrives from a VPS through a `wgN` interface and is forwarded to a LAN host. Return traffic must go back through the same attachment, but:
- Traffic **to the VPS endpoint itself** must use the normal route (not the tunnel), or the tunnel breaks
- Traffic **to the local LAN** must stay local
- **Return traffic** arriving from the tunnel must be routed back through the tunnel (not the default gateway)
- If Docker is running on the gateway, its `DOCKER-USER` chain will block forwarded traffic unless explicitly allowed

### Required setup (applied by the agent, not wg-quick hooks)

The agent sets `Table = off` in `wg0.conf` to disable wg-quick's automatic routing, then applies all rules programmatically.

**Step 1: Prerequisites**

```bash
# Ensure routing table exists (some minimal LXCs lack /etc/iproute2/)
if [ ! -d /etc/iproute2 ]; then
    mkdir -p /etc/iproute2
    # Write standard tables + custom tunnel table
    cat > /etc/iproute2/rt_tables <<EOF
255 local
254 main
253 default
0 unspec
100 tunnel
EOF
elif ! grep -q "100 tunnel" /etc/iproute2/rt_tables; then
    echo "100 tunnel" >> /etc/iproute2/rt_tables
fi
```

**Step 2: Kernel settings**

```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0       # Required: strict RP filter breaks asymmetric routing
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.eth0.rp_filter=0      # Must also disable per-interface
sysctl -w net.ipv4.conf.wg0.rp_filter=0
```

**Step 3: Routing tables**

```bash
WG_TABLE_ID="51820"
REPLY_TABLE_NAME="tunnel"

# Main forwarding table — all tunnel-bound traffic uses this
ip route add default dev wg0 table ${WG_TABLE_ID}

# Reply table — return traffic from the tunnel goes back through it
ip route add default via <vps_tunnel_ip> dev wg0 table ${REPLY_TABLE_NAME}
```

**Step 4: Policy routing rules (order matters — lower priority = higher precedence)**

```bash
# Priority 100: VPS endpoint traffic stays on main table (prevents tunnel loop)
ip rule add to <vps_endpoint_ip> table main priority 100

# Priority 200: LAN traffic stays local
ip rule add to <lan_network> table main priority 200

# Priority 5000: only for explicit LAN egress pins, not blanket gateway mode
ip rule add from <lan_client_ip> table ${WG_TABLE_ID} priority 5000

# Priority 5100: Forward traffic from this machine through the tunnel
ip rule add from <gateway_tunnel_ip> table ${WG_TABLE_ID} priority 5100
ip rule add from <gateway_lan_ip> table ${WG_TABLE_ID} priority 5100

# Priority 30000: Return traffic marked by mangle rules goes back via tunnel
ip rule add fwmark 0x1 table ${REPLY_TABLE_NAME} priority 30000
```

**Step 5: Mangle rules (connection tracking for return traffic)**

```bash
# Mark packets arriving from the tunnel so return traffic uses the tunnel table
iptables -t mangle -A PREROUTING -i wg0 -j MARK --set-mark 0x1
iptables -t mangle -A PREROUTING -i wg0 -j CONNMARK --save-mark
iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark
```

**Step 6: NAT and forwarding**

Use `iptables -C` (check) before inserting to make the script idempotent — safe to re-run without creating duplicate rules:

```bash
iptables -P FORWARD ACCEPT

# NAT
iptables -C -t nat POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE

# Docker compatibility (only if Docker is present and DOCKER-USER chain exists)
iptables -C DOCKER-USER -i wg0 -o eth0 -j ACCEPT 2>/dev/null || \
    iptables -I DOCKER-USER -i wg0 -o eth0 -j ACCEPT
iptables -C DOCKER-USER -i eth0 -o wg0 -j ACCEPT 2>/dev/null || \
    iptables -I DOCKER-USER -i eth0 -o wg0 -j ACCEPT
```

**Step 7: MSS clamping (prevents MTU-related connection hangs)**

```bash
iptables -C -t mangle POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o wg0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o wg0 -j TCPMSS --clamp-mss-to-pmtu
```

### Implementation rules

- All of the above must be applied **after** `wg-quick up` (or equivalent `wg syncconf`)
- On teardown, flush all custom rules and tables
- On every apply, **flush first then re-apply** to prevent duplicate rules — this includes:
  - `ip route flush table <WG_TABLE_ID>` and `ip route flush table <REPLY_TABLE_NAME>`
  - Delete all ip rules by priority number
  - Delete mangle rules (`iptables -t mangle -D ...`) before re-adding
- Persist iptables rules via `netfilter-persistent save` after every change
- The `wireguard/` package in the Go agent is responsible for this logic — it must not rely on `PostUp`/`PostDown` wg-quick hooks since the agent manages config programmatically
- Standard gateway setup skips the priority-5000 rule. That rule is only added later for explicit per-LAN-client egress pins.

---

## Agent Update Mechanism

Since agents are compiled binaries (not scripts), updates require an explicit mechanism. The control server pushes an `agent_update` command via the existing WebSocket protocol — no polling required.

### Update Command

```json
{
  "id": "cmd-uuid-here",
  "type": "agent_update",
  "params": {}
}
```

### Agent Update Flow

1. Agent receives `agent_update` command
2. Downloads binary to a temp file (e.g. `/tmp/wirewarp-agent-new`)
3. Replaces `/usr/local/bin/wirewarp-agent` with the downloaded file
4. Sends `command_result` with `success: true` back to control server
5. Restarts `wirewarp-agent` through systemd after the result frame has a chance to flush

SHA256 verification and automatic rollback are not implemented yet.

### Update Rollback

If the new binary fails to start (crashes, panics, can't connect), the systemd service will fail. The desired hardening path is:

- The systemd unit should set `RestartSec=5` and `Restart=on-failure` with `StartLimitBurst=3`
- If the service fails 3 times in a row, systemd stops retrying
- An `ExecStartPre` script checks: if the agent binary's version doesn't match what was last reported as healthy, and a `.bak` file exists, restore the backup automatically
- Alternatively, the install script can set up a systemd `OnFailure=` unit that restores the `.bak` binary and restarts

This is not implemented in the current updater yet.

The dashboard exposes per-agent and bulk "Update" actions that trigger this command.

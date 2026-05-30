# WireWarp

Self-hosted WireGuard tunnel management. Replace ad-hoc bash scripts with a single dashboard: deploy a Go agent on any VPS, register it from the web UI, manage port forwards, gateway routing, and per-user VPN access — without touching config files by hand.

## Why

Managing WireGuard across a homelab — multiple VPS exit nodes, gateway LXCs, port forwards, per-user VPN profiles — usually means SSH'ing around editing `wg0.conf`, `iptables -t nat`, and `ip rule`. WireWarp pushes everything from one control server over WebSocket: agents phone home, take whitelisted commands, and apply WireGuard + iptables changes locally. Mesh private keys stay on the agent; VPN profile private keys are returned once and not stored. Tunnels stay up if the control server goes down.

## Features

### Tunnel management

- **Tunnel servers and clients** — register VPS or gateway agents, push initial config, edit live. No SSH after install.
- **Multi-server gateways** — one gateway client can peer with N tunnel servers simultaneously; each attachment gets its own `wgN` interface, fwmark, and routing table.
- **Multi-IP per tunnel server** — bind port forwards to a specific public IP; DNAT rules disambiguate by destination IP.
- **Port forwarding** — TCP/UDP DNAT with templates (DayZ, Minecraft, Web, RDP). Live iptables preview.
- **VPN endpoints + per-user permissions** — admins configure a VPN endpoint on a gateway client; users get device profiles + QR code at `/vpn`. Per-(user, endpoint) firewall rules.
- **LAN client discovery + DNS sync** — gateway agents scrape conntrack for LAN hosts; DNS records sync to Cloudflare automatically when egress IP changes (or surface a manual-update notice).

### Observability

- **Per-server / per-client detail pages** — `/tunnel-servers/:id` and `/tunnel-clients/:id` aggregate peer count, total RX/TX, recent heal events, and active forwards. Four tabs: Overview, Peers, Heal events, Forwards.
- **wg-easy-style peer tables** — every WireGuard interface (mesh `wg0/wgN` + road-warrior `wg-vpnN`) ships per-peer RX/TX, endpoint, allowed IPs, persistent-keepalive, and a handshake-recency status dot. Same component on tunnel-server detail, tunnel-client detail, and `VPN endpoints`.
- **Heal events feed** — when the agent's 60s self-healer re-installs missing routing state, the event lands in `agent_heal_events`; the agent detail page grows a warn badge with the count of last-24h drift incidents.
- **CrowdSec status card** — tunnel-server detail surfaces `cscli` version, active decisions, top scenarios, top banned IPs. Polled every 5 min by the agent.
- **Real-time updates** — dashboard state is primarily invalidated through `/ws/dashboard`; selected security/status views keep short scoped polling or a fallback poll for offline WebSocket recovery.

### Resilience

- **Self-healing routing** — every 60 s the agent verifies each piece of per-attachment state (`ip rule fwmark`, custom-table routes, mangle `CONNMARK --set/--restore`, MSS clamp, MASQUERADE, DOCKER-USER) and re-installs only what's missing. Silent when healthy; logs `[heal] re-installed: …` and pushes a `heal_event` frame on drift. Server-side state (`ip_forward` sysctl, MASQUERADE on the public iface, MSS clamp on the tunnel iface) gets the same treatment.
- **Reboot-safe routing** — first successful `wg_init` / `wg_attach` writes `/etc/systemd/system/wirewarp-routing.service`, a oneshot unit ordered before `network-pre.target` that calls the agent in `--restore-routing` mode. iptables + ip rules survive reboots even when the agent isn't yet up.
- **MSS clamp on the tunnel server** — `iptables -t mangle -A POSTROUTING -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu` is installed alongside the gateway-side clamp so PMTUD-blackholed clients (mobile carriers, strict NATs) don't stall mid-TLS.
- **Offline resilience** — agents apply last-known config from disk before the WS connection completes; tunnels survive control-server outages.
- **Clean shutdown** — agents tear down WireGuard + routing on stop. No leftover rules.

### Security

- **CrowdSec one-click install** — admin opens the tunnel-server detail page → CrowdSec card → "Install CrowdSec". The agent runs the apt install, registers with the CrowdSec Central API (free community blocklist), installs `crowdsecurity/linux`, and writes an auto-whitelist parser covering every IP and subnet known to the control server (other agents' public IPs, mesh + VPN subnets, gateway LAN subnets, every discovered LAN client). Whitelist re-syncs on hash drift via the same 5-min poll cycle, so adding a LAN client auto-allows it within minutes.
- **Sensitive-port advisory** — the "New port forward" dialog runs the chosen (protocol, port) through a server-side classifier and renders a tip card before submit. Catalogue covers SSH, Telnet, MySQL, Postgres, MongoDB, Redis, Memcached, Elasticsearch, CouchDB, RDP, VNC, Webmin, mail submission, admin HTTP. Tip copy stays narrow on purpose — recommends host-local mitigations (CrowdSec, fail2ban, hide behind WireWarp), no third-party CDN / edge service.
- **Auth** — local users (bcrypt), OIDC (Google/GitHub/generic), and LDAP. Roles: `admin`, `operator`, `viewer`, plus a `vpn_user` role whose only access is `/vpn`.
- **Audit log** — every dispatched command logged with actor, type, and details. Visible in dashboard.
- **No arbitrary remote shell execution** — agents execute whitelisted command types only. No `eval` or user-supplied shell snippets. Privileged installer subcommands (apt, cscli) escape the agent's restricted `CapabilityBoundingSet` via `systemd-run` transient units, not by relaxing the agent itself.

### Operator UX

- **Mobile-responsive dashboard** — phone-first layout with bottom-tab nav, full-screen sheets for dialogs, table-as-card lists. Viewer role lands on `/vpn` directly.
- **One-command install** — `curl … | bash -s -- --mode <s|c>`. Idempotent. Supports Debian/Ubuntu, RHEL/Fedora, Alpine.
- **In-place agent update** — dashboard "Update Agent" button downloads the checked-in agent binary from GitHub and restarts via systemd. Hash verification is still a hardening task.

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

**Add Agent → Tunnel Client → Generate Token**, run on the gateway LXC/VM. Then open **Tunnel Clients → [client]**:

- Enable **Is Gateway** if this client forwards inbound traffic to LAN services.
- Set LAN Network + LAN IP when gateway mode is enabled.
- Add an attachment to the tunnel server from step 4.
- Leave Tunnel IP blank to auto-allocate, or set one manually inside the server network.

Save/create the attachment → control server orchestrates the handshake automatically:

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

When a tunnel client is configured as a gateway, inbound port forwards can reach LAN devices behind it. LAN-originated outbound traffic is not sent through a VPS by default; pin a discovered LAN client in the dashboard when that host should egress through a specific tunnel server/public IP.

For LAN egress pinning, the LAN host must send traffic through the gateway client, usually by setting:
- **Default Gateway** — the tunnel client's LAN IP (e.g. `192.168.1.10`) or equivalent split-default routes.
- **DNS** — whatever resolver your LAN policy requires.

Proxmox LXC example: edit `/etc/network/interfaces`, set `gateway 192.168.1.10`.

## Updating agents

**From the dashboard** (recommended): **Agents → [name] → Update Agent**. Downloads the latest checked-in binary from GitHub and restarts via systemd. No SSH. SHA256 verification is not implemented yet.

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

**LAN egress pin active but no internet on that LAN device:** confirm the LAN host routes through the gateway client, then check the gateway attachment and server-side forwarding state. Re-save the relevant tunnel server config to re-fire `wg_init` if server IP forwarding or MASQUERADE drifted.

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
| Go agent | Go toolchain must match `wirewarp-agent/go.mod`; CI currently pins Go 1.22 and should be reconciled with the module directive. Uses `nhooyr.io/websocket`, `gopkg.in/yaml.v3` — single static binary |
| Database | PostgreSQL 16 |
| Deployment | Docker Compose (server), systemd (agents) |

## Key design decisions

- **Agents phone home** — outbound WebSocket only. The control server never connects to agents.
- **Mesh private keys never leave the agent** — site-to-site WireGuard keypairs are generated on-host; only public keys hit the control server. VPN profile private keys are returned once in generated configs and not stored.
- **Offline resilience** — agents read disk config and bring up tunnels before the WS connection completes. Tunnels survive control-server outages.
- **Clean shutdown** — agents tear down WireGuard + routing on stop. No leftover rules.
- **No arbitrary remote shell execution** — agents expose whitelisted command types only. No `eval` or user-supplied shell snippets.
- **Single binary** — `--mode server|client` selects behavior. Same binary either way.
- **Gateways are inbound-only by default** — gateway clients DNAT inbound traffic to LAN hosts. LAN-originated outbound through a VPS is opt-in per LAN client/attachment.
- **Each tunnel server gets a unique `/24`** — auto-allocated from `10.21.0.0/24`, `10.22.0.0/24`, … on registration. Cross-server routing and rebase rely on it.

## Project structure

```
wirewarp/
├── wirewarp-server/          # Control server (FastAPI + PostgreSQL)
│   ├── app/
│   │   ├── main.py           # App entrypoint, WebSocket handler, SPA serving
│   │   ├── models/           # SQLAlchemy ORM. Notable tables:
│   │   │                     #   agent_heal_events     (drift audit)
│   │   │                     #   wg_peer_snapshots     (unified mesh+VPN)
│   │   │                     #   wg_traffic_samples    (traffic charts)
│   │   │                     #   crowdsec_snapshots    (per-agent)
│   │   │                     #   traefik_snapshots     (edge proxy status)
│   │   │                     #   security_events       (edge/security feed)
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── routers/          # REST API. Per-entity dashboards live at
│   │   │                     #   /tunnel-servers/{id}/{summary,wg-peers,crowdsec,crowdsec/install}
│   │   │                     #   /tunnel-clients/{id}/{summary,wg-peers}
│   │   │                     #   /vpn-endpoints/{id}/wg-peers
│   │   │                     #   /agents/{id}/heal-events
│   │   │                     #   /port-forwards/classify  (sensitive-service)
│   │   │                     #   /security/*              (overview, events, sites)
│   │   ├── websocket/        # WS hub + dispatch (heartbeat, command_result,
│   │   │                     #   metrics, heal_event, crowdsec_status,
│   │   │                     #   traefik_status, security_events)
│   │   ├── realtime/         # Event bus + typed dashboard emitters
│   │   └── services/         # Command dispatch, network alloc, dns_sync,
│   │                         #   port_security, crowdsec_ops, traefik_ops,
│   │                         #   vpn_ops, traffic_sampler, secrets
│   ├── alembic/              # Migrations 0001 ... 0030_security_events
│   ├── Dockerfile            # Multi-stage build (frontend + backend)
│   └── docker-compose.yml
├── wirewarp-web/             # React dashboard
│   └── src/
│       ├── pages/            # Login, Dashboard, Agents, AgentDetail,
│       │                     #   TunnelServers, TunnelServerDetail,
│       │                     #   TunnelClients, TunnelClientDetail,
│       │                     #   PortForwards, VpnEndpoints, MyVpn,
│       │                     #   LanClients, Users, Settings, …
│       ├── components/       # Layout, BottomNav, ui.tsx, icons.tsx,
│       │                     #   WgPeerTable, CrowdSecCard, Toasts,
│       │                     #   CommandPalette, HelpOverlay
│       └── lib/              # api.ts, realtime.ts, types.ts
├── wirewarp-agent/           # Go agent
│   ├── cmd/agent/main.go     # Entrypoint (--mode, --restore-routing flags)
│   ├── scripts/              # install.sh, verify-gateway.sh, systemd unit
│   └── internal/
│       ├── config/           # YAML config persistence
│       ├── websocket/        # Persistent WS + heartbeat (wg peer scrape,
│       │                     #   LAN client scrape) + Emit() unsolicited push
│       ├── executor/         # Command dispatcher
│       ├── handlers/         # Server + client command handlers, plus
│       │                     #   client_heal.go      (60s drift heal)
│       │                     #   server_heal.go      (server-side heal)
│       │                     #   crowdsec.go         (5min cscli poll)
│       │                     #   crowdsec_install.go (one-click installer)
│       │                     #   routing_restore.go  (boot-time --restore)
│       │                     #   systemd_unit.go     (writes wirewarp-routing.service)
│       ├── wireguard/        # WireGuard + gateway routing wrappers,
│       │                     #   HealAttachment() check-or-add inspector
│       └── iptables/         # iptables wrappers + HealServerNetwork()
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

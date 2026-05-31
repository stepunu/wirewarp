# Codebase Guide

Generated on 2026-05-30 from files that are not gitignored, excluding `docs/` as requested.
Updated on 2026-05-31 for the Node Edge / Cloudflare-parity implementation.

## What This Project Does

WireWarp is a self-hosted control plane for WireGuard-based tunnel management. It coordinates:

- VPS-style tunnel servers with public IPs.
- Gateway/tunnel clients installed inside private networks.
- Site-to-site attachments between clients and servers.
- Port forwards from server public IPs into LAN services behind gateways.
- Road-warrior VPN endpoints and user profiles.
- An optional per-node security edge built around Traefik, CrowdSec/AppSec,
  live access events, route/profile policy resources, and local Nginx cache.
- A React dashboard for operators and VPN users.

The root `README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, and `tasks.md` contain useful intent, but some details are stale compared with the current code. Treat this guide and the files it links to as the current implementation snapshot.

## Runtime Topology

There are three main applications:

1. `wirewarp-server`
   FastAPI control plane. It serves REST APIs under `/api`, WebSocket endpoints under `/ws`, the built frontend from `static/`, and runs Alembic migrations on container startup.

2. `wirewarp-agent`
   Go daemon installed on Linux tunnel servers and gateway clients. It connects to `/ws/agent`, registers or authenticates, receives commands, executes root-level networking/systemd operations, reports command results, heartbeats, peer state, and security status.

3. `wirewarp-web`
   React/Vite dashboard. It calls the REST API, keeps UI state fresh through `/ws/dashboard`, and builds into `wirewarp-server/static` for the production image.

Supporting services:

- PostgreSQL stores persistent state.
- Alembic owns schema evolution. Current migration head in code is
  `0038_edge_upstream_pools`.
- GitHub Actions builds tests, the web bundle, the Go agent, and the server Docker image.

## Control Flow

Typical flow:

1. An admin creates a registration token.
2. A Linux host starts `wirewarp-agent` with that token and mode `server` or `client`.
3. The agent registers through `/ws/agent`; the server stores an `Agent` plus a type-specific `TunnelServer` or `TunnelClient`.
4. The server sends commands such as `wg_init`, `wg_attach`, `wg_add_peer`, `iptables_add_forward`, `vpn_endpoint_up`, `edge_desired_state`, `edge_cache_purge`, or `edge_cache_test`.
5. The agent executes commands and sends `command_result`.
6. The server updates models and emits dashboard events through the realtime bus.
7. The React app invalidates relevant TanStack Query keys and refetches current state.

See `DOMAIN_MODEL.md` for the domain relationships and lifecycle details.

## Local Development

Backend:

```bash
cd wirewarp-server
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[test]"
pytest
uvicorn app.main:app --reload --port 8100
```

Frontend:

```bash
cd wirewarp-web
npm install
npm run dev
npm run build
```

Agent:

```bash
cd wirewarp-agent
go test ./...
go build ./cmd/agent
make build
```

Container stack:

```bash
cd wirewarp-server
docker compose up --build
```

The production container listens on port `8000`; the compose file maps host port `8100`. Vite proxies `/api` and `/ws` to `http://localhost:8100`.

## Testing Surface

Server tests are broad and live in `wirewarp-server/tests`. They use SQLite with custom type compilation and dependency overrides. Coverage includes auth, RBAC, tunnel allocations, attachments, port forwards, LAN egress, VPN, realtime invalidation, CrowdSec, Traefik, node edge capabilities, edge routes/profiles/path rules/upstreams, desired-state dispatch, access events, cache APIs, command result binding, and SPA fallback behavior.

Agent tests cover pure command parsing, CrowdSec/Traefik helpers, edge desired-state handling, reversible edge lifecycle, Nginx cache rendering/status probes, and deterministic cache purge helpers. The Go code still wraps Linux networking, WireGuard, iptables, systemd, package installation, and host inspection, so host-level behavior also requires integration or careful manual verification on real nodes.

Frontend currently has build-time validation through TypeScript/Vite. There are no frontend test files in the non-ignored tree.

## Operational Requirements

The agent assumes a Linux host with root privileges and common networking tools:

- `wg`, `wg-quick`, and WireGuard kernel/userland support.
- `ip`, `iptables`, `sysctl`, and usually `netfilter-persistent`.
- `systemd` for service management and boot-time route restoration.
- Package installation support for Traefik, CrowdSec/AppSec, and Nginx when a
  server node is enabled as a Security Edge node.

Server-side secrets are based on `SECRET_KEY`. JWT signing and encrypted settings both depend on it, so rotating it invalidates tokens and encrypted settings values.

## Source Of Truth Notes

Current implementation caveats:

- The Alembic migration chain reaches `0038_edge_upstream_pools`.
- Agent self-update currently downloads the raw binary and replaces the executable without a hash check.
- `wirewarp-agent/go.mod` declares `go 1.25.6`, while CI currently pins Go 1.22. Verify toolchain expectations before changing CI or releases.
- `wirewarp-web/src/lib/websocket.ts` appears to be a legacy store. The active dashboard realtime path is `src/lib/realtime.ts`.
- Security overview APIs and pages exist, but several aggregate metrics are
  still placeholders. The node-scoped live access feed is wired through
  Traefik JSON logs, agent batching, `edge_access_events`, and `edge.access`
  invalidation.
- Edge cache is implemented as a local Nginx `proxy_cache` behind Traefik.
  Availability is gated on agent health probes proving `MISS -> HIT` or a
  valid `BYPASS`. Full-node and exact host/path purge are implemented; wider
  host/prefix/route purge scopes need a cache index before they can be safe.

## Change Strategy

For backend changes:

- Update SQLAlchemy models and Alembic migrations together.
- Keep router behavior aligned with service helpers.
- Add or update pytest coverage near the behavior being changed.
- Watch command-result and realtime invalidation paths, because many UI states depend on async agent feedback.

For agent changes:

- Preserve command payload compatibility with `wirewarp-server/app/services/agent_commands.py`.
- Keep saved config migrations in `internal/config/config.go` backward compatible.
- Treat iptables/routing changes as high risk. Prefer idempotent handlers and add explicit healing or restore behavior.

For frontend changes:

- Update `src/lib/types.ts` and `src/lib/api.ts` with API shape changes.
- Add realtime invalidation in `src/lib/realtime.ts` when new server events affect visible state.
- Keep the dashboard role model in sync with backend RBAC.

# WireWarp — Claude Code Instructions

## Project Overview

WireWarp is a self-hosted WireGuard tunnel management platform. See
[ARCHITECTURE.md](./ARCHITECTURE.md) for the system design and
[docs/superpowers/specs/](./docs/superpowers/specs/) for in-flight design
work.

Three components:
- **Control Server** (`wirewarp-server/`) — Python/FastAPI + PostgreSQL + React dashboard, runs in Docker
- **Go Agent** (`wirewarp-agent/`) — single binary with `--mode server|client`, runs as systemd service on VPS/LXC (no Docker)
- **Web Dashboard** (`wirewarp-web/`) — React 19 + TypeScript + plain CSS (OKLCH design tokens, JetBrains Mono / IBM Plex Sans)

## Deployment & operations

Reference deployment topology (replace placeholders below with your own
values when running operational commands).

- **Control server**: `<control-host>` (e.g. an LXC, VM, or VPS).
  Compose file at `/opt/wirewarp/docker-compose.yml`, image
  `ghcr.io/<gh-org>/wirewarp:latest`. The container runs
  `alembic upgrade head && uvicorn` on start; the DB is a separate
  `wirewarp-db` container using `postgres:16-alpine`.
- **Public URL**: `https://wirewarp.example.com` (front with
  Traefik/Caddy/nginx for TLS). Internal port: `8100`.
- **Database access** (read-only inspection or one-off fixes):
  ```
  ssh root@<control-host> 'docker exec wirewarp-db psql -U wirewarp -d wirewarp -c "..."'
  ```
- **Admin auth**: dashboard JWT, creds in `/opt/wirewarp/.env`
  (`ADMIN_USER`, `ADMIN_PASSWORD`). Login via `POST /api/auth/login`.
- **Redeploying after a CI build**: invoke `/rebuild`
  (`.claude/commands/rebuild.md`). It pulls the latest image, recreates
  the `wirewarp` container, prunes dangling images, polls
  `/api/health`, and reports the new image digest. Only ever touches
  the control host; does not touch volumes or the DB container.

### Agent binary distribution

- CI builds `wirewarp-agent/dist/wirewarp-agent` (Linux amd64, static)
  and **commits it back to main** with `[skip ci]`. The Dockerfile
  copies it into the server image so installs use the build that
  matches the running control server.
- `wirewarp-agent/scripts/install.sh` is fetched from
  `https://raw.githubusercontent.com/<gh-org>/wirewarp/main/wirewarp-agent/scripts/install.sh`.
  **GitHub raw is fronted by Fastly with a 5-minute cache** — fresh
  pushes take ~5 min to reach the install URL. For instant freshness,
  `https://cdn.jsdelivr.net/gh/<gh-org>/wirewarp@main/...` works
  without delay.
- The installer is idempotent across re-runs: it stops any existing
  systemd service, removes the old binary (avoiding ETXTBSY), and
  resets the agent's WireGuard config. Private keys at
  `/etc/wireguard/wgN.key` are preserved.

### CI / commit conventions

- `.github/workflows/docker-image.yml` has two jobs: `build-agent`
  (commits binary back) and `build-server` (pushes to GHCR).
- Add `[skip ci]` to a commit message to skip both jobs (matches the
  workflow's own convention for the agent rebuild commits).
- Always create new commits rather than amending pushed history.

## Task tracking

Long-term work is tracked in [tasks.md](./tasks.md). Design specs for
larger features live in `docs/superpowers/specs/<date>-<topic>-design.md`.

Within a session, use `TaskCreate` / `TaskUpdate` for the current
session's plan — set tasks `in_progress` before starting, `completed`
when done, one at a time.

For tasks.md:
- Read it before starting any phase work.
- Work in phase order; within a phase, top-to-bottom unless a
  dependency dictates otherwise.
- Mark `[ ]` → `[~]` when starting, `[x]` when done, `[-]` (with note)
  when dropped.

## Tech stack & conventions

### Control server (Python)
- Python 3.11+, FastAPI, async throughout.
- SQLAlchemy 2.0 with async engine (asyncpg driver).
- Alembic for migrations — never modify schema without a migration. Current head is `0024` (data fix: split comma-joined `vpn_permissions.destination` rows; the API now rejects joined values at the boundary, see `app/schemas/vpn.py::VpnPermissionInput`).
- Pydantic v2 for all request/response schemas.
- JWT (python-jose); passwords bcrypt-hashed.
- FastAPI native WebSockets at `/ws/agent` (no socket.io, no
  separate dashboard WS).
- Tests: pytest + httpx.
- Sensitive helpers: `app/services/network_alloc.py` (per-server
  `/24` allocator), `app/services/tunnel_server_ops.py`
  (`dispatch_wg_init`, `dispatch_wg_configure` shared between PATCH /
  register / rebase), `app/services/primary_ip.py`
  (`get_primary_ip` / `resolve_public_ip` for multi-IP).

### Go agent
- Go 1.22+, single binary, minimal deps.
- `cmd/agent/main.go` is the entrypoint; `--mode` selects
  server/client behavior.
- All system operations (`wg`, `iptables`, `ip rule`) go through
  wrapper packages in `internal/`.
- Never shell out with `exec.Command("bash", "-c", ...)` — explicit
  command + arg list only.
- Config stored as YAML at `/etc/wirewarp/agent.yaml`.
- WireGuard private keys generated locally; only public keys leave
  the agent.
- Offline resilience: apply last-known config from disk on startup,
  then try to connect.
- Heartbeat enumerates every routable IPv4 on local interfaces and
  reports them as `public_ips: [..]` so multi-homed VPSes register
  every public IP they hold.

### Web dashboard (React)
- Vite + React 19 + TypeScript (strict mode).
- **Plain CSS** at `src/styles.css` (template-derived, OKLCH tokens, dark/light themes via `data-theme` on `<html>`). No Tailwind, no CSS modules.
- React Query for server state (5s `refetchInterval` for live-feeling lists).
- Zustand for client-side state (used minimally — most state is React Query).
- React Router v7 with `BrowserRouter` and a `ProtectedRoute` wrapper.
- UI primitives in `src/components/ui.tsx`; icons in `src/components/icons.tsx`. CommandPalette (`⌘K`), HelpOverlay (`?`), and global hotkeys (`g d/g a/g s/g c/g p`) wired in `Layout.tsx`.

### Database
- PostgreSQL 16, all IDs are UUIDs.
- Schema defined in ARCHITECTURE.md § Database Schema.
- Always use Alembic, never raw SQL against the live DB (with the
  obvious exception of one-off operator fixes documented in commits).
- `command_log` is the audit trail; every agent command is logged.
  `GET /api/audit?limit=50&agent_id=...` exposes it to the dashboard.

## Architecture rules

Non-negotiable:

1. **Agents phone home** — outbound WS connection from agent to control server. The control server never initiates connections to agents.
2. **Private keys never leave the agent** — only public keys are sent to the control server.
3. **Offline resilience** — agents must work if the control server is down. Apply disk config first, then try to connect.
4. **No arbitrary shell execution** — agents only execute whitelisted command types. No eval, no `bash -c`, no remote code execution.
5. **Install is one command** — `curl ... | bash -s -- --mode <s|c> --url <ctrl> --token <tok>`. No interactive prompts on the target machine.
6. **Gateways are inbound-only** — a tunnel client with `is_gateway=true` accepts inbound DNAT'd traffic from VPSes and forwards to LAN devices. It does **not** route LAN-originated outbound traffic through any tunnel; the LAN's normal default router handles that. The legacy `from <LANNetwork> table <wg>` rule that did the opposite is being removed (see the multi-server gateway spec).
7. **Each tunnel server gets a unique `/24`** — the `network_alloc.py` helper picks the next free network from `10.21.0.0/24`, `10.22.0.0/24`, … on registration. Cross-server routing, log attribution, and client rehoming all rely on this. Existing servers can be moved with `POST /api/tunnel-servers/{id}/rebase` (renumbers clients + port forwards atomically; refuses 503 if any participant agent is offline).
8. **Multi-IP per tunnel server is first-class** — a server can hold N IPs in `tunnel_server_ips`, one is `is_primary`. Port forwards bind to a specific IP via `tunnel_server_ip_id`. iptables DNAT rules always include `-d <publicIP>` so disambiguation by destination IP works at the netfilter layer.
9. **Control server runs in Docker** — FastAPI + PostgreSQL via docker-compose on the control host. Agents run as systemd services, never in Docker.

## Code style

- Keep it simple. Don't over-abstract or over-engineer.
- No unnecessary comments. Code should be self-explanatory; add a
  comment only when the *why* is non-obvious (gateway routing
  priorities, fwmark allocation, the `tunnel_server_ips.is_primary`
  partial unique index).
- No docstrings on obvious functions. Do add them on public API
  endpoints and complex internal functions.
- Error messages should be actionable — what went wrong and what to
  do about it.
- Don't add features that aren't in the task list without asking
  first.
- For React 19, watch out for the `react-hooks/set-state-in-effect`
  rule — most violations from React-Query→form-state sync are
  legitimate; suppress with a targeted `eslint-disable-next-line`
  rather than restructuring the hook.

## File references

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — system design, DB schema, WebSocket protocol, gateway routing.
- [`tasks.md`](./tasks.md) — task list and progress.
- [`docs/superpowers/specs/`](./docs/superpowers/specs/) — design specs for in-flight or shipped features. Latest: `2026-05-09-multi-server-gateway-design.md`.
- [`legacy/`](./legacy/) — original bash scripts. The Go agent's gateway module is *informed by* `legacy/gateway-up.sh` but **deliberately diverges** from it on the LAN-egress rule (see Architecture Rule 6).
- `.claude/commands/rebuild.md` — `/rebuild` slash command spec.

## Git

- Commit after completing each task or logical unit of work.
- Commit messages: imperative mood, concise, reference the change (e.g.,
  "Add multi-IP support per tunnel server (Phase 9.1)").
- Don't commit broken code — each commit should build/run cleanly.
- `[skip ci]` skips the docker-image workflow; useful for doc-only or
  install-script-only commits.
- Pull/rebase before push; the CI's agent-binary commits race with
  human pushes.

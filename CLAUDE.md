# WireWarp — Claude Code Instructions

## Project Overview

WireWarp is a self-hosted WireGuard tunnel management platform. See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full system design.

Three components:
- **Control Server** (`wirewarp-server/`) — Python/FastAPI + PostgreSQL + React dashboard, runs in Docker
- **Go Agent** (`wirewarp-agent/`) — single binary with `--mode server|client`, runs as systemd service on VPS/LXC (no Docker)
- **Web Dashboard** (`wirewarp-web/`) — React 18 + TypeScript + Tailwind CSS

## Task Tracking

All tasks are tracked in [tasks.md](./tasks.md). Follow these rules:

- **Before starting work**, read `tasks.md` to understand what's done and what's next
- **Work in phase order** — don't jump ahead (e.g., don't build the dashboard before the API exists)
- **Within a phase**, work top-to-bottom unless a dependency requires otherwise
- **Mark tasks as you go**: change `[ ]` to `[~]` when starting, `[x]` when done
- **One task at a time** — complete and verify before moving on
- **After completing a task**, update `tasks.md` immediately
- **If a task needs to be added**, add it in the correct phase with context
- **If a task turns out to be unnecessary**, mark it `[-]` with a brief note why

## Tech Stack & Conventions

### Control Server (Python)
- Python 3.11+, FastAPI, async throughout
- SQLAlchemy 2.0 with async engine (asyncpg driver)
- Alembic for database migrations — never modify the DB schema without a migration
- Pydantic v2 for all request/response schemas
- Authentication: JWT (python-jose), passwords hashed with bcrypt
- WebSocket: FastAPI native WebSockets, not socket.io
- Testing: pytest + httpx for API tests

### Go Agent
- Go 1.22+, single binary, minimal dependencies
- `cmd/agent/main.go` is the entrypoint, `--mode` flag selects server or client behavior
- All system operations (wg, iptables, ip rule) go through wrapper packages in `internal/`
- Never shell out with raw `exec.Command("bash", "-c", ...)` — use specific commands with explicit arguments
- Config stored in YAML, persisted to `/etc/wirewarp/agent.yaml`
- WireGuard private keys generated locally, never transmitted to the control server
- Agent must function offline — apply last known config from disk on startup

### Web Dashboard (React)
- Vite + React 18 + TypeScript (strict mode)
- Tailwind CSS for styling
- React Query for API data fetching
- Zustand for client-side state
- React Router for navigation

### Database
- PostgreSQL 16, all IDs are UUIDs
- Schema defined in ARCHITECTURE.md § Database Schema
- Always use Alembic migrations, never raw SQL against the DB
- The `command_log` table is the audit trail — log every command sent to agents

## Architecture Rules

These are non-negotiable design decisions:

1. **Agents phone home** — agents connect outbound to the control server via WebSocket. The control server never initiates connections to agents.
2. **Private keys never leave the agent** — agents generate their own WireGuard keypairs. Only public keys are sent to the control server.
3. **Offline resilience** — agents must work if the control server is down. On startup: apply config from disk first, then try to connect.
4. **No arbitrary shell execution** — agents only execute whitelisted command types. No eval, no bash -c, no remote code execution.
5. **Install is one command** — the dashboard generates a single copy-paste command with `--url` and `--token` baked in. No interactive prompts on the target machine.
6. **Gateway routing is complex** — see ARCHITECTURE.md § Gateway Routing for the full 7-step setup. The Go agent must replicate the working `legacy/gateway-up.sh` logic exactly.
7. **Control server runs in Docker** — FastAPI + PostgreSQL via docker-compose. Agents run as systemd services, never in Docker.

## Code Style

- Keep it simple. Don't over-abstract or over-engineer.
- No unnecessary comments — code should be self-explanatory. Add comments only for non-obvious logic (like the gateway routing priority values).
- No docstrings on obvious functions. Do add them on public API endpoints and complex internal functions.
- Error messages should be actionable — tell the user what went wrong and what to do about it.
- Don't add features that aren't in the task list without asking first.

## File References

- `ARCHITECTURE.md` — full system design, DB schema, WebSocket protocol, gateway routing details
- `tasks.md` — task list with progress tracking
- `legacy/` — original bash scripts for reference (working gateway-up.sh, wirewarp.sh, wirewarp-client.sh)
- `legacy/gateway-up.sh` — the proven working gateway routing script. The Go agent's gateway module must produce identical system state.

## Git

- Commit after completing each task or logical unit of work
- Commit messages: imperative mood, concise, reference the task (e.g., "Add agent ORM models and initial migration")
- Don't commit broken code — each commit should build/run cleanly

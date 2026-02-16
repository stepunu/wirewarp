# WireWarp — Task List

Reference: [ARCHITECTURE.md](./ARCHITECTURE.md)

Status key: `[ ]` pending | `[~]` in progress | `[x]` done | `[-]` skipped

---

## Phase 1: Control Server — Database & API Skeleton

### 1.1 Project scaffolding
- [x] Create `wirewarp-server/` directory structure per ARCHITECTURE.md
- [x] Initialize Python project with `pyproject.toml` (Python 3.11+)
- [x] Create `requirements.txt` (fastapi, uvicorn, sqlalchemy, asyncpg, alembic, pydantic, python-jose, passlib, bcrypt)
- [x] Create `app/main.py` FastAPI entrypoint with CORS and lifespan
- [x] Create `app/config.py` with Pydantic Settings (DATABASE_URL, SECRET_KEY, AGENT_TOKEN_EXPIRY_HOURS)

### 1.2 Database setup
- [x] Create `app/database.py` — async SQLAlchemy engine + session factory
- [x] Initialize Alembic for migrations
- [x] Create ORM models in `app/models/`
- [x] Create initial Alembic migration and verify it applies cleanly

### 1.3 Pydantic schemas
- [x] Create `app/schemas/` with request/response schemas for each model

### 1.4 Authentication
- [x] Create `app/routers/auth.py` — login endpoint, returns JWT
- [x] JWT utility functions, password hashing, `get_current_user` dependency

### 1.5 REST API endpoints
- [x] Agents, tunnel servers, tunnel clients, port forwards, service templates CRUD
- [x] Seed builtin service templates on first run

### 1.6 Docker setup
- [x] Dockerfile (multi-stage: Node frontend + Python backend)
- [x] docker-compose.yml (api + postgres)

---

## Phase 2: Control Server — WebSocket Hub

- [x] 2.1 Connection manager (`app/websocket/hub.py`)
- [x] 2.2 Agent WebSocket endpoint with registration flow
- [x] 2.3 Message handlers (heartbeat, command_result, metrics)
- [x] 2.4 Command dispatch service

---

## Phase 3: Go Agent — Skeleton

- [x] 3.1 Project scaffolding
- [x] 3.2 WebSocket client with reconnect, heartbeat, registration
- [x] 3.3 Command executor framework
- [x] 3.4 Build, systemd service template, verify connectivity

---

## Phase 4: Go Agent — WireGuard & iptables

- [x] 4.1 WireGuard wrappers (server mode) — keypair, init, add/remove peers, syncconf
- [x] 4.2 iptables wrappers (server mode) — DNAT, FORWARD, MASQUERADE
- [x] 4.3 WireGuard wrappers (client mode) — keypair, wg0.conf, up/down, update endpoint
- [x] 4.4 Gateway routing (client mode) — full 7-step policy routing setup
- [x] 4.5 Offline resilience — apply saved config on startup, persist after every change

---

## Phase 5: React Dashboard

- [x] 5.1 Project scaffolding (Vite + React 18 + TypeScript + Tailwind CSS)
- [x] 5.2 Authentication UI (login, JWT, protected routes)
- [x] 5.3 Dashboard overview (summary cards, live agent status)
- [x] 5.4 Agent management (list, add, detail, delete)
- [x] 5.5 Tunnel server management (config view/edit, peer list)
- [x] 5.6 Tunnel client management (server selection, gateway config)
- [x] 5.7 Port forwarding (CRUD, templates, enable/disable)
- [x] 5.8 Build integration (static files served by FastAPI)

---

## Phase 6: Install, Deploy & Polish

### 6.1 Install & deploy
- [x] One-command install script (`install.sh`) — handles deps, binary, systemd, registration
- [x] Supports Debian/Ubuntu, RHEL/Fedora, Alpine (noninteractive)
- [x] Dashboard generates copy-paste install command
- [-] Serve install scripts and binary from control server — using GitHub raw URLs instead

### 6.2 Command dispatch from dashboard
- [x] Tunnel server save → sends `wg_init` to agent
- [x] Tunnel client save → sends `wg_configure` to client + `wg_add_peer` to server
- [x] Public key extraction from command results, auto peer addition
- [x] Server-side ip_forward + MASQUERADE on `wg_init`

### 6.3 Bug fixes & operational improvements
- [x] Fix `wg syncconf` rejecting wg-quick directives (use `wg-quick strip`)
- [x] Fix gateway routing killing control server connectivity (priority 99 exception)
- [x] Fix empty Endpoint crash in client wg0.conf
- [x] Fix install script hanging on iptables-persistent interactive prompt
- [x] Fix agent deletion blocked by FK constraints (migration 0002)
- [x] Fix alembic using localhost instead of DATABASE_URL in Docker
- [x] Fix systemd `StartLimitIntervalSec` in wrong section
- [x] Clean shutdown — tear down WireGuard + routing on agent stop

### 6.4 Dashboard improvements
- [x] Delete buttons for tunnel servers and tunnel clients (in edit form)
- [x] Public IP field in tunnel server edit form
- [x] Gateway verification script (`verify-gateway.sh`)

### 6.5 Remaining
- [ ] Agent update mechanism (download new binary, verify hash, restart)
- [ ] Dashboard "Update Agent" button
- [ ] Command history view in dashboard (per agent)
- [ ] API endpoint tests (pytest + httpx)
- [ ] Go agent unit tests

---

## Future (not in scope now)

- [ ] Multi-IP support (IP pool per VPS, DNAT binding to specific public IP)
- [ ] Metrics dashboard with charts (CPU, bandwidth, peer status over time)
- [ ] Agent uninstall command via WebSocket
- [ ] Multi-user with granular permissions
- [ ] CrowdSec integration on tunnel servers
- [ ] DNS configuration option for tunnel clients

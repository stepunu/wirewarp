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
- [x] Create ORM models in `app/models/`:
  - [x] `agent.py` — Agent model (id, name, type, hostname, public_ip, status, version, last_seen)
  - [x] `registration_token.py` — RegistrationToken (token, agent_type, used, expires_at)
  - [x] `tunnel_server.py` — TunnelServer (agent_id, wg_port, wg_interface, public_ip, public_iface, wg_public_key, tunnel_network)
  - [x] `tunnel_client.py` — TunnelClient (agent_id, tunnel_server_id, tunnel_ip, vm_network, lan_ip, is_gateway, wg_public_key, status)
  - [x] `port_forward.py` — PortForward (tunnel_server_id, tunnel_client_id, protocol, public_port, destination_ip, destination_port, description, active)
  - [x] `service_template.py` — ServiceTemplate (name, protocol, ports, is_builtin)
  - [x] `command_log.py` — CommandLog (agent_id, command_type, params, success, output)
  - [x] `metric.py` — Metric (agent_id, timestamp, data)
  - [x] `user.py` — User (username, email, password_hash, role)
- [x] Create initial Alembic migration and verify it applies cleanly

### 1.3 Pydantic schemas
- [x] Create `app/schemas/` with request/response schemas for each model
- [x] Include: AgentCreate, AgentRead, TokenCreate, TokenRead, TunnelServerRead, TunnelClientCreate, TunnelClientRead, PortForwardCreate, PortForwardRead, ServiceTemplateRead, UserCreate, UserRead, LoginRequest, TokenResponse

### 1.4 Authentication
- [x] Create `app/routers/auth.py` — login endpoint, returns JWT
- [x] JWT utility functions (create_token, verify_token) in `app/auth.py`
- [x] Password hashing with bcrypt
- [x] Dependency `get_current_user` for protected routes
- [x] Seed script or CLI command to create initial admin user

### 1.5 REST API endpoints
- [x] `app/routers/agents.py` — list agents, get agent detail, delete agent, generate registration token
- [x] `app/routers/tunnel_servers.py` — get/update tunnel server config
- [x] `app/routers/tunnel_clients.py` — get/update tunnel client config (including is_gateway toggle)
- [x] `app/routers/port_forwards.py` — CRUD for port forwarding rules
- [x] `app/routers/service_templates.py` — list templates, create custom template
- [x] Seed builtin service templates (DayZ, Minecraft, Web, RDP) on first run

### 1.6 Docker setup
- [x] Create `wirewarp-server/Dockerfile` (Python slim, uvicorn)
- [x] Create `wirewarp-server/docker-compose.yml` (api + postgres as per ARCHITECTURE.md)
- [x] Verify the stack starts, migrations run, and API responds on :8000

---

## Phase 2: Control Server — WebSocket Hub

### 2.1 Connection manager
- [x] Create `app/websocket/hub.py` — ConnectionManager class
  - Track connected agents by agent_id
  - Handle connect/disconnect lifecycle
  - Send command to specific agent by ID
  - Broadcast to all agents of a type

### 2.2 Agent WebSocket endpoint
- [x] Create WebSocket route `/ws/agent` in `app/main.py`
- [x] Authentication: agent sends JWT on connect, validate before accepting
- [x] Registration flow: if agent sends `type: "register"` with token, validate token, create agent record, issue JWT
- [x] On connect: update agent status to `connected`, update `last_seen`
- [x] On disconnect: update agent status to `disconnected`

### 2.3 Message handlers
- [x] Create `app/websocket/handlers.py` — dispatch incoming messages by type
- [x] Handle `heartbeat` — update `last_seen`
- [x] Handle `command_result` — log to `command_log` table, update relevant state
- [x] Handle `metrics` — store in `metrics` table

### 2.4 Command dispatch service
- [x] Create `app/services/agent_commands.py`
  - Build command messages (wg_init, wg_add_peer, wg_remove_peer, iptables_add_forward, iptables_remove_forward)
  - Send via ConnectionManager
  - Log command to `command_log` with pending status
  - Track pending commands and match responses by command ID

---

## Phase 3: Go Agent — Skeleton

### 3.1 Project scaffolding
- [x] Create `wirewarp-agent/` directory structure per ARCHITECTURE.md
- [x] Initialize Go module (`go mod init github.com/wirewarp/agent`)
- [x] Create `cmd/agent/main.go` — entrypoint with `--mode` flag (server/client), `--config` flag
- [x] Create `internal/config/` — YAML config struct (control_server_url, agent_token, mode)

### 3.2 WebSocket client
- [x] Create `internal/websocket/client.go` — persistent WebSocket connection
  - Connect to control server URL
  - Send registration message on first run (with token)
  - Store JWT after successful registration in config file
  - Reconnect with JWT on subsequent connections
  - Exponential backoff with jitter (1s initial, 60s cap, ±25% jitter)
  - Heartbeat every 30 seconds
  - 90-second read deadline for detecting dead connections

### 3.3 Command executor framework
- [x] Create `internal/executor/executor.go` — command dispatcher interface
- [x] Register command handlers by message type
- [x] For now: log received commands and return success (no-op handlers)
- [x] Send `command_result` responses back via WebSocket

### 3.4 Build and test
- [x] Create `Makefile` with build targets (linux/amd64)
- [x] Create systemd unit file template (`wirewarp-agent.service`)
- [x] Verify: agent connects to control server, registers, sends heartbeats, appears as "Connected"

---

## Phase 4: Go Agent — WireGuard & iptables

### 4.1 WireGuard wrappers (server mode)
- [x] Create `internal/wireguard/server.go`
  - Generate keypair (`wg genkey` / `wg pubkey`), store private key in `/etc/wireguard/`
  - Initialize wg0 interface with server config
  - Add/remove peers via `wg set` or config file rewrite + `wg syncconf`
  - Save config to disk after every change

### 4.2 iptables wrappers (server mode)
- [x] Create `internal/iptables/server.go`
  - Add/remove DNAT PREROUTING rules
  - Add/remove FORWARD rules
  - Add MASQUERADE for NAT
  - Save rules via `netfilter-persistent save`
  - Use `iptables -C` check before adding to prevent duplicates

### 4.3 WireGuard wrappers (client mode)
- [x] Create `internal/wireguard/client.go`
  - Generate keypair, store private key
  - Write `wg0.conf` with `Table = off`
  - Bring interface up/down via `wg-quick`
  - Update peer endpoint if server changes

### 4.4 Gateway routing (client mode)
- [x] Create `internal/wireguard/gateway.go` — the full policy routing setup
  - Ensure `/etc/iproute2/rt_tables` has tunnel table entry
  - Apply kernel sysctl settings (ip_forward, rp_filter per-interface)
  - Set up routing tables (WG_TABLE_ID=51820, REPLY_TABLE_NAME=tunnel)
  - Apply ip rules with correct priorities (100, 200, 5000, 5100, 30000)
  - Apply mangle rules (MARK, CONNMARK save/restore)
  - Apply NAT (MASQUERADE on wg0)
  - Apply MSS clamping
  - Docker compatibility (DOCKER-USER chain, only if Docker present)
  - Flush-before-apply pattern for idempotency
  - Save iptables via `netfilter-persistent save`
  - Teardown function that cleans everything up
- [x] Skip priority-5000 and Docker rules when `is_gateway=false`

### 4.5 Offline resilience
- [x] On startup: apply last known config from disk before connecting to control server
- [x] After every config change: persist to disk immediately
- [x] WireGuard interface stays up regardless of WebSocket connection state

---

## Phase 5: React Dashboard

### 5.1 Project scaffolding
- [ ] Create `wirewarp-web/` with Vite + React 18 + TypeScript + Tailwind CSS
- [ ] Set up React Router (pages: Login, Dashboard, Agents, TunnelServers, TunnelClients, PortForwards)
- [ ] Set up API client (`src/lib/api.ts`) with auth token handling
- [ ] Set up WebSocket client (`src/lib/websocket.ts`) for live dashboard updates
- [ ] Set up React Query for data fetching

### 5.2 Authentication UI
- [ ] Login page with username/password form
- [ ] JWT storage in localStorage, auto-redirect on expiry
- [ ] Protected route wrapper

### 5.3 Dashboard overview
- [ ] Summary cards: total agents, connected/disconnected counts, active port forwards
- [ ] Agent status list with live connection indicators (via WebSocket)

### 5.4 Agent management
- [ ] Agent list page with status badges (connected/disconnected/pending)
- [ ] "Add Agent" button → generates registration token → shows copy-paste install command
- [ ] Agent detail page with config, last seen, version, metrics

### 5.5 Tunnel server management
- [ ] Tunnel server config view/edit (public interface, WireGuard port, tunnel network)
- [ ] Peer list showing connected clients

### 5.6 Tunnel client management
- [ ] Client config view/edit
- [ ] "Connect to" dropdown to select tunnel server
- [ ] "Is Gateway" checkbox with tooltip explaining what it does
- [ ] LAN network and LAN IP fields (shown when is_gateway is checked)

### 5.7 Port forwarding
- [ ] Port forward list per tunnel server
- [ ] Add port forward form (protocol, public port, destination IP, destination port, description)
- [ ] "Apply Template" button — select from service templates (DayZ, Minecraft, etc.)
- [ ] Enable/disable toggle per rule
- [ ] Delete rule

### 5.8 Build and integrate
- [ ] Production build outputs to `wirewarp-server/static/`
- [ ] FastAPI serves static files at `/` (or Nginx in docker-compose)
- [ ] Create `wirewarp-web/Dockerfile` if serving separately

---

## Phase 6: Install Scripts & Polish

### 6.1 Install scripts
- [ ] Create `wirewarp-agent/scripts/install-server.sh`
  - Accepts `--url` and `--token` flags (no interactive prompts)
  - Detects OS (Debian/Ubuntu/Alpine)
  - Installs WireGuard if missing
  - Downloads agent binary from control server
  - Creates systemd service with config
  - Starts service
- [ ] Create `wirewarp-agent/scripts/install-client.sh` (same pattern)
- [ ] Control server serves install scripts at `/install/server` and `/install/client`
- [ ] Control server serves agent binary at `/releases/`

### 6.2 Agent update mechanism
- [ ] Implement `agent_update` command handler in Go agent
  - Download new binary to temp file
  - Verify SHA256 hash
  - Backup current binary to `.bak`
  - Replace and restart via systemd
- [ ] Implement rollback: systemd `ExecStartPre` or `OnFailure` unit restores `.bak` on repeated crash
- [ ] Dashboard "Update" button per agent
- [ ] `/api/version` endpoint for agents to self-report outdated status

### 6.3 Audit logging
- [ ] Ensure all command dispatches are logged to `command_log` table
- [ ] Dashboard page or section showing recent command history per agent

### 6.4 Testing
- [ ] API endpoint tests (pytest + httpx)
- [ ] WebSocket connection tests (pytest)
- [ ] Go agent unit tests (command execution, config persistence)
- [ ] Integration test: full flow from dashboard → API → WebSocket → agent → system command

---

## Future (not in scope now)

- [ ] Multi-IP support (IP pool per VPS, DNAT binding to specific public IP)
- [ ] Metrics dashboard with charts (CPU, bandwidth, peer status over time)
- [ ] Agent uninstall command via WebSocket
- [ ] Multi-user with granular permissions
- [ ] CrowdSec integration on tunnel servers

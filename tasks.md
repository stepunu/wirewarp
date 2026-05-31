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

- [x] 5.1 Project scaffolding (Vite + React 19 + TypeScript + plain CSS)
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
- [x] Tunnel client attachment create → sends `wg_attach` to client + `wg_add_peer` to server after public key return
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
- [x] Fix VPS can't reach LAN — add `ip route add <lan_subnet> dev wg0` on server after `wg_add_peer`
- [x] Fix gateway missing MASQUERADE for VPS→LAN traffic (`-s <vps_tunnel_ip> -o eth0`)
- [x] Remove wg0 MASQUERADE — preserve real source IPs for port-forwarded traffic

### 6.4 Dashboard improvements
- [x] Delete buttons for tunnel servers and tunnel clients (in edit form)
- [x] Public IP field in tunnel server edit form
- [x] Gateway verification script (`verify-gateway.sh`)

### 6.5 Remaining
- [x] Agent update mechanism (downloads checked-in binary, replaces executable, restarts)
- [x] Dashboard "Update Agent" button and bulk update action
- [x] Command history view in dashboard (dashboard activity + per-agent audit tab)
- [x] API endpoint tests (pytest + httpx coverage across core routers)
- [ ] Agent update hardening: SHA256 verification + rollback
- [ ] Go agent unit tests beyond current validation/CrowdSec parsing coverage

---

## Phase 7: Agent Lifecycle & DNS

### 7.1 Agent uninstall command
- [ ] Add `wg_uninstall` command type to agent executor
- [ ] Agent tears down WireGuard, routing, removes binary/service/config
- [ ] Dashboard "Uninstall Agent" button (sends command, then deletes agent record)

### 7.2 DNS configuration for tunnel clients
- [ ] Add DNS field to tunnel client model + migration
- [ ] Pass DNS to agent in attachment params if tunnel-client DNS config returns
- [ ] Agent writes `DNS =` line into `wg0.conf`
- [ ] Dashboard DNS field in tunnel client edit form

### 7.3 Agent update mechanism
- [x] Agent `agent_update` command: download checked-in binary, replace, restart via systemd
- [ ] Verify SHA256 before replace and keep rollback backup
- [ ] Server endpoint to serve latest binary + hash
- [x] Dashboard "Update Agent" button per agent

---

## Phase 8: OAuth & Multi-User

### 8.1 OAuth / SSO login
- [x] Add OIDC provider config (Google/GitHub/generic style) to server settings
- [x] OIDC login flow — exchange code for token, map to local user, issue JWT
- [x] Login page: show configured OIDC/LDAP options alongside username/password form
- [x] Settings page for admin to configure OIDC and LDAP providers

### 8.2 Multi-user with granular permissions
- [x] Roles model: admin, operator, viewer, vpn_user
- [-] Per-resource ownership (not implemented; current model is role-based access)
- [x] Permission checks on API endpoints
- [x] Dashboard UI: show/hide actions based on role
- [x] User management page (admin only): list, create, change role/access, delete

---

## Phase 9: Multi-IP & Port Forwarding Enhancements

### 9.1 Multi-IP support
- [x] IP pool model: assign multiple public IPs to a tunnel server
- [x] Migration + API endpoints for IP pool CRUD
- [x] Port forward rules can bind to a specific public IP (not just the primary)
- [x] Agent `iptables_add_forward` accepts public IP and DNAT scopes by destination IP
- [x] Dashboard: IP pool management, IP selector in port forward form

---

## Phase 10: Monitoring & Security

### 10.1 Metrics collection
- [~] Agent periodically sends heartbeat/peer state via WebSocket; raw metrics handler exists, CPU/memory coverage is not complete
- [x] `metrics`, `wg_peer_snapshots`, and `wg_traffic_samples` tables exist
- [~] API endpoints expose peer snapshots and security traffic aggregates; general per-agent metric ranges are still incomplete

### 10.2 Metrics dashboard
- [~] Dashboard has operational summaries and uPlot-backed security charts, not a complete standalone metrics page
- [~] Per-agent/detail pages show peer status and traffic counters; CPU/memory charts are not implemented
- [x] Overview shows connected agents, tunnel servers, clients, and active forwards

### 10.3 CrowdSec integration
- [x] Agent command `crowdsec_install`: install CrowdSec + firewall bouncer on tunnel server
- [~] Agent command `crowdsec_sync_whitelist`: desired whitelist sync exists; full ban/scenario configuration is not complete
- [x] Dashboard install/status card per tunnel server

---

## Phase 11: Testing & Polish

### 11.1 Command history
- [x] Dashboard command history view per agent (query `command_log` table)
- [~] Filtering exists at API level for agent/event type; richer dashboard filtering still pending

### 11.2 API tests
- [x] pytest + httpx test suite for core REST endpoints
- [x] Auth tests (login, JWT, protected routes, OIDC/LDAP support)
- [~] WebSocket handler tests exist; full connection-level coverage remains limited

### 11.3 Go agent unit tests
- [~] Unit tests for validation and CrowdSec parsing exist
- [ ] Mock wireguard/iptables for broader handler testability

---

## Phase 12: Security Edge Console

Self-hosted, Cloudflare-like security edge for the HTTP(S) services
WireWarp exposes. Design:
[`docs/superpowers/specs/2026-05-29-security-edge-console-design.md`](docs/superpowers/specs/2026-05-29-security-edge-console-design.md).
Engines: Traefik (managed systemd binary) + CrowdSec AppSec (Coraza +
OWASP CRS) via `crowdsec-bouncer-traefik-plugin`. UI inspired by
SafeLine; config model by BunkerWeb. Each phase ends with: migration
applied, tests green, `/rebuild`, manual gate verified, commit.

### 12.0 CrowdSec reliability fix
- [x] Split `installed` vs `running`; PATH-independent cscli/systemctl detection; surface service errors (commit `212eb1b`)

### 12.1 Security Overview + charting layer
- [x] `wg_traffic_samples` append-only table sampled from `wg_peer_snapshots` + retention
- [~] Aggregate endpoints over CrowdSec snapshots + traffic samples exist, but several access/visitor/HTTP series are placeholders
- [~] `/security` Overview page, uPlot layer, KPI tiles, top attackers, and Security sidebar exist; real aggregate completeness still pending. Node-scoped access data is now implemented in `edge_access_events`.
- [ ] Gate: Overview renders real aggregates with a working time-range toggle

### 12.2 Events / Reports
- [~] `security_events` table/API/feed exists; CrowdSec/Traefik normalization and drill-down payloads are still partial
- [x] `edge_access_events` table/API/feed exists for Traefik JSON access logs with host/path/status/action/IP/country/method/route/time filters
- [x] `/security/events` page exists
- [ ] Gate: a triggered detection appears with full drill-down

### 12.3 Traefik edge + Sites
- [x] Agent: `traefik_install` + `traefik_sync_config` commands; file-provider config under `/etc/traefik/dynamic/`; offline-resilient
- [x] `port_forwards.service_kind` (http|raw) + `domain`; new `edge_route_config` table
- [x] HTTP-service CRUD → Traefik routers (Host rule → upstream over tunnel); raw stays DNAT
- [x] `/security/sites` page with run-mode + feature-toggle chips
- [x] Route-shaped Node Edge APIs and UI exist as the preferred interface while legacy Sites APIs remain compatible
- [ ] Gate: an HTTP service is reachable through Traefik+TLS; raw forward still works; Traefik survives agent restart from disk

### 12.4 WAF (CrowdSec AppSec via Traefik plugin)
- [~] Agent: AppSec enable command and Traefik middleware rendering exist; collection/bouncer lifecycle needs more hardening
- [x] Per-route WAF mode (off/observe/block) on `edge_route_config`, Sites run-mode, profiles/routes/path-policy resources, and Node Edge UI
- [ ] Gate: simulated SQLi/XSS blocked (block) or logged (observe) → appears in Events

### 12.5 Protections (edge rules)
- [~] Per-route middlewares exist for rate limit, IP allowlist, auth, WAF/bouncer paths, headers/transforms, TLS/origin options, and inherited node/profile/path policy; antibot/geo/dnsbl remain partial/local-only
- [x] `/security/protections` page exists
- [ ] Gate: each toggle visibly takes effect on a test request

### 12.6 Bans + Certs + polish + alerts
- [~] `/security/bans` and `/security/certs` pages/API placeholders exist; manual mutation and alert hooks remain pending
- [ ] Gate: manual ban blocks an IP; cert status shown; threshold alert fires

---

## Phase 13: Self-healing edge + unified console IA

Supersedes the operator-driven install model from Phase 12 (12.3/12.4/12.5
fold in here). Design:
[`docs/superpowers/specs/2026-05-30-self-healing-edge-and-console-ia-design.md`](docs/superpowers/specs/2026-05-30-self-healing-edge-and-console-ia-design.md).
The edge is provisioned + healed automatically (no install clicks), and the
dashboard reorganizes around one node-with-a-role model.

### 13.A Self-healing edge (agent reconciler + backend)
- [x] Add server `edge_mode`, `edge_state`, install phase, enabled/disabled audit timestamps, component desired state, and default migration behavior (`tcp_udp_only` unless existing edge state is detected)
- [x] Add node edge capability APIs: get/put capabilities, install, enable, disable, reconcile; edge-only APIs return `edge_feature_disabled` when unsupported
- [x] Dispatch `edge_desired_state` only for `security_edge` + `enabled`; TCP/UDP-only nodes skip Traefik/CrowdSec/AppSec/Nginx desired state
- [x] Agent handles reversible `edge_disable` by stopping/disabling services while preserving files, packages, route rows, secrets, and ACME state
- [x] Agent reconciles saved desired state for Traefik, CrowdSec/AppSec, access logs, and Nginx cache
- [~] Per-component health is surfaced from CrowdSec/Traefik snapshots, component desired rows, and Nginx cache snapshots; richer degraded/backoff escalation still needs real-host hardening
- [ ] Gates: fresh TCP/UDP-only server does not install edge services; enabling Security Edge installs/reconciles services; disabling stops services and preserves config; re-enable restores routes

### 13.B Unified console IA (frontend)
- [x] Nodes list exists with role filter, gateway treatment, mode/state badges, and component health summary
- [x] Role-adaptive node detail exists with Overview, Routes, Security, Rate Limits, Access, TLS, Origin, Headers & Transforms, Cache, Import/Diff, Advanced, plus existing Forwards/Peers/Activity/Audit surfaces
- [x] TCP/UDP-only server nodes show a concise Security Edge enable panel instead of broken route/cache/WAF controls
- [x] Security Edge node tabs manage route/profile/path policy, upstream pools, access feed, cache status/test/purge, import/diff, and rendered config
- [~] Legacy `/security/sites` and `/security/protections` pages remain for compatibility; Node Edge is the preferred route/profile surface
- [ ] Gates: browser QA on desktop/mobile for TCP/UDP-only enable panel, Security Edge tabs, live feed filtering, import/diff, and cache unavailable/available states

### 13.C Node Edge API parity
- [x] Profiles CRUD, node policy, effective policy, routes by ID/domain, path rules, upstream pools, fragments, rendered/effective config, config versions, access events, cache status/stats/purge/test, Traefik import preview/apply/upsert, and full desired-state snapshots exist
- [x] Secrets remain write-only with `*_set` readback fields where exposed
- [x] `dry_run`, `apply=false`, `prune`, and `return_diff` are supported on the bulk/import surfaces implemented for UI and automation
- [~] Compatibility with existing `port_forwards` + `edge_route_configs` is preserved; Ansible examples/docs are still pending

### 13.D Local Nginx cache
- [x] Add headers/cache policy to node and route policy
- [x] Render managed Nginx `proxy_cache` backend, install/reload service, report status snapshots, and route Traefik to `127.0.0.1:18080` when cache is active
- [x] Gate cache availability on `MISS -> HIT` or valid `BYPASS`
- [x] Implement cache test command and safe full-node/exact host-path purge helper without NGINX Plus
- [~] Host/prefix/route purge scopes return unsupported until a cache index exists
- [ ] Gates: live route proves `MISS -> HIT`; auth/API path proves `BYPASS`; purge causes next request to `MISS`

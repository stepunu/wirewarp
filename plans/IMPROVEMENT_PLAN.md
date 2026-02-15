# WireWarp Improvement Plan
**Version:** 1.0
**Date:** 2025-10-14
**Status:** Planning Phase

---

## Executive Summary

WireWarp is positioned to become **the leading self-hosted solution for exposing home servers safely**, targeting users with powerful hardware but dynamic/residential IPs who want to avoid exposing their home network.

**Key Improvements:**
1. **Multi-IP Support** - Allow VPSes to manage multiple public IPs for load distribution and isolation
2. **Central Administration System** - Web-based control panel with automated VPS/Proxmox provisioning
3. **Enhanced Monitoring** - Real-time metrics, alerts, and observability
4. **Enterprise Features** - Multi-VPS clustering, HA, and team collaboration

**Target Market:** Home lab enthusiasts, game server hosters, self-hosters, developers with dynamic IPs or CGNAT

**Competitive Advantage:**
- Supports ALL protocols (UDP for gaming, unlike Cloudflare Tunnel)
- Self-hosted (privacy-first, unlike ngrok)
- One-time VPS cost ($3-5/mo) vs recurring subscriptions
- Full control over infrastructure

---

## Current State Analysis

### Strengths
- ✅ Clean bash-based implementation with TUI (whiptail)
- ✅ Automated peer management with sequential numbering
- ✅ Flexible port forwarding (ranges, bulk operations)
- ✅ Solid NAT architecture (10.0.0.0/24 tunnel + 10.99.X.0/24 per-peer VMs)
- ✅ Works perfectly for single-VPS, single-IP scenarios
- ✅ Client auto-setup script minimizes manual configuration

### Limitations
- ❌ Single public IP binding per VPS
- ❌ No centralized management (requires SSH access)
- ❌ Flat file storage (peer configs as individual files)
- ❌ No authentication or access control
- ❌ Limited monitoring (only `wg show`)
- ❌ No redundancy or failover
- ❌ Manual operations only (no API)
- ❌ Sensitive keys in plaintext in setup commands

### Technical Debt
- Hard-coded network ranges
- No database backend
- No structured logging
- No automated testing
- No disaster recovery mechanism

---

## Target Market & Positioning

### Primary Audiences

**1. Game Server Hosters** (High Priority)
- **Profile:** Own powerful gaming PCs or old hardware, want to host Minecraft/Palworld/CS2 for friends
- **Pain Points:** Dynamic IP changes weekly, don't want to expose home address, expensive game hosting ($15-30/mo)
- **Solution:** WireWarp + $4/mo VPS = static IP, hidden home network, support for all game protocols
- **Market Size:** 500K+ members on r/admincraft, r/palworldserver, etc.

**2. Home Lab Enthusiasts** (High Priority)
- **Profile:** Run Proxmox/VMware with multiple VMs, self-host services
- **Pain Points:** CGNAT prevents port forwarding, dynamic IPs, privacy concerns
- **Solution:** WireWarp's multi-VM support, per-peer isolation
- **Market Size:** r/homelab (500K), r/selfhosted (400K)

**3. Privacy-Conscious Self-Hosters** (Medium Priority)
- **Profile:** Don't trust commercial services, want full control
- **Pain Points:** ngrok/Cloudflare see all traffic, subscription costs add up
- **Solution:** Self-hosted WireWarp on owned VPS
- **Market Size:** Growing (privacy movement, degoogle)

**4. Developers with Home Workstations** (Medium Priority)
- **Profile:** Powerful dev machine at home, need remote access, webhooks
- **Pain Points:** Dynamic IP, can't receive webhooks, VPN too complex
- **Solution:** Permanent SSH/RDP access via VPS, webhook endpoints
- **Market Size:** Significant (remote work trend)

**5. Small Teams & Content Creators** (Low Priority)
- **Profile:** Need Plex/Jellyfin, file sharing, internal tools
- **Pain Points:** Don't want to pay for cloud storage, need controlled access
- **Solution:** Self-host on home hardware, expose via WireWarp
- **Market Size:** Niche but growing

### Competitive Analysis

| Solution | Cost | Protocols | Setup | Privacy | Gaming Support |
|----------|------|-----------|-------|---------|----------------|
| **WireWarp (Current)** | $3-5/mo VPS | ALL | Medium | Full | ✅ Yes |
| **WireWarp (Improved)** | $3-5/mo VPS | ALL | Easy | Full | ✅ Yes |
| Cloudflare Tunnel | Free | HTTP/S only | Easy | Cloudflare sees traffic | ❌ No |
| ngrok | $8-20/mo | ALL | Very Easy | ngrok sees traffic | ⚠️ Yes (expensive) |
| Tailscale Funnel | $6/user/mo | ALL | Easy | Tailscale network | ✅ Yes |
| Manual WireGuard | $3-5/mo VPS | ALL | Hard | Full | ✅ Yes |

**WireWarp's Sweet Spot:** Full protocol support + privacy + affordable + easier than manual setup

### Marketing Positioning

**Tagline:** "Self-hosted tunnel service for gamers and homelabbers"

**Key Messages:**
- "Expose your home server without exposing your home"
- "Run game servers safely with dynamic IPs"
- "$5/month VPS instead of $30/month game hosting"
- "Full control, zero subscriptions, all protocols"

**Target Platforms:**
- Reddit: r/homelab, r/selfhosted, r/admincraft, r/Proxmox
- YouTube: Tutorial videos ("Host Minecraft without port forwarding")
- GitHub: Star campaign, get on trending
- Forums: ServTheHome, LowEndTalk, LinusTechTips forums

---

## Improvement Phases

### Phase 1: Multi-IP Support (Priority: CRITICAL)
**Timeline:** 2-3 weeks
**Effort:** Medium
**Dependencies:** None

#### Objectives
- Support VPSes with multiple public IP addresses
- Per-peer IP assignment (isolation, load balancing)
- Automatic load distribution across available IPs
- Separate iptables chains per IP for clean management

#### Implementation Tasks

**1.1 IP Pool Management**
- [ ] Create `/etc/wireguard/ip-pools/` directory structure
- [ ] Create `pool.conf` format:
  ```ini
  [IP:1.2.3.4]
  interface=eth0
  status=active

  [IP:1.2.3.5]
  interface=eth0:1
  status=active
  ```
- [ ] Create `assignments.db` (SQLite) schema:
  ```sql
  CREATE TABLE ip_assignments (
    peer_id INTEGER,
    peer_name TEXT,
    assigned_ip TEXT,
    assigned_at TIMESTAMP
  );
  ```
- [ ] Add IP pool initialization function in wirewarp.sh
- [ ] Add IP validation and availability checking

**1.2 VPS Initialization Updates**
- [ ] Modify `vps_init()` to support multiple IPs
- [ ] Add whiptail menu: "How many IPs does this VPS have?"
- [ ] Loop to collect IP addresses and their interfaces
- [ ] Detect IPs automatically from `ip addr show`
- [ ] Save IP pool to `/etc/wireguard/ip-pools/pool.conf`

**1.3 Peer Assignment Logic**
- [ ] Modify `add_peer_vps()` to assign IP from pool
- [ ] Add IP selection strategies:
  - Round-robin (default)
  - Least-used (count peers per IP)
  - Manual selection (user chooses)
- [ ] Update peer info files to include assigned IP
- [ ] Add IP to peer `.info` file: `ASSIGNED_PUBLIC_IP=1.2.3.4`

**1.4 Port Forwarding Updates**
- [ ] Modify `manage_ports_vps()` to use assigned IP
- [ ] Create separate iptables chains per IP:
  ```bash
  iptables -t nat -N WIREWARP_IP_1_2_3_4
  iptables -t nat -A PREROUTING -i eth0 -d 1.2.3.4 -j WIREWARP_IP_1_2_3_4
  ```
- [ ] Update port forward rules to target specific chains
- [ ] Add validation to prevent port conflicts on same IP

**1.5 Viewing and Management**
- [ ] Add "View IP Pool Status" menu option
- [ ] Show IP utilization (peers per IP)
- [ ] Add "Migrate Peer to Different IP" function
- [ ] Add "Add/Remove IP from Pool" functions

**1.6 Documentation**
- [ ] Update README with multi-IP setup instructions
- [ ] Add troubleshooting guide for IP routing issues
- [ ] Create example configurations for common VPS providers

#### Success Criteria
- ✅ VPS can manage 2+ public IPs successfully
- ✅ Peers distributed evenly across IPs
- ✅ Port forwarding works correctly per IP
- ✅ No port conflicts between peers on same IP
- ✅ Clean iptables chain management

---

### Phase 2: Database Backend (Priority: HIGH)
**Timeline:** 1-2 weeks
**Effort:** Low-Medium
**Dependencies:** None

#### Objectives
- Replace flat file storage with SQLite database
- Enable complex queries (reporting, filtering)
- Improve data integrity and atomic operations
- Foundation for API and web GUI

#### Implementation Tasks

**2.1 Database Schema Design**
```sql
-- VPS/Server Configuration
CREATE TABLE vpses (
    id INTEGER PRIMARY KEY,
    hostname TEXT UNIQUE,
    public_key TEXT,
    private_key_path TEXT,
    tunnel_network TEXT,
    wireguard_port INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IP Pools
CREATE TABLE ip_pools (
    id INTEGER PRIMARY KEY,
    vps_id INTEGER,
    ip_address TEXT,
    interface TEXT,
    status TEXT CHECK(status IN ('active', 'disabled')),
    created_at TIMESTAMP,
    FOREIGN KEY(vps_id) REFERENCES vpses(id)
);

-- Peers/Clients
CREATE TABLE peers (
    id INTEGER PRIMARY KEY,
    vps_id INTEGER,
    peer_number INTEGER,
    peer_name TEXT,
    public_key TEXT,
    private_key_encrypted TEXT,
    tunnel_ip TEXT,
    vm_network TEXT,
    vm_gateway_ip TEXT,
    vm_private_ip TEXT,
    assigned_public_ip TEXT,
    status TEXT CHECK(status IN ('active', 'inactive', 'suspended')),
    created_at TIMESTAMP,
    last_handshake TIMESTAMP,
    FOREIGN KEY(vps_id) REFERENCES vpses(id)
);

-- Port Forwards
CREATE TABLE port_forwards (
    id INTEGER PRIMARY KEY,
    peer_id INTEGER,
    protocol TEXT CHECK(protocol IN ('tcp', 'udp')),
    public_port INTEGER,
    private_port INTEGER,
    created_at TIMESTAMP,
    created_by TEXT,
    FOREIGN KEY(peer_id) REFERENCES peers(id),
    UNIQUE(peer_id, protocol, public_port)
);

-- Audit Log
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT,
    resource_type TEXT,
    resource_id INTEGER,
    user TEXT,
    details TEXT
);

-- Metrics (for monitoring)
CREATE TABLE metrics (
    id INTEGER PRIMARY KEY,
    peer_id INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    FOREIGN KEY(peer_id) REFERENCES peers(id)
);
```

**2.2 Migration Script**
- [ ] Create `migrate-to-db.sh` script
- [ ] Read existing `.info` and `.conf` files
- [ ] Populate database from flat files
- [ ] Create backup of flat files before migration
- [ ] Validate migration (compare counts, checksums)

**2.3 Update wirewarp.sh Functions**
- [ ] Replace file reads with SQL queries
- [ ] Replace file writes with SQL inserts/updates
- [ ] Add database helper functions:
  ```bash
  db_query() { sqlite3 /etc/wireguard/wirewarp.db "$1"; }
  db_get_peers() { db_query "SELECT * FROM peers WHERE vps_id=1"; }
  ```
- [ ] Add transaction support for atomic operations

**2.4 Backward Compatibility**
- [ ] Auto-detect if flat files exist, prompt migration
- [ ] Keep flat file export option for debugging
- [ ] Add `--legacy-mode` flag to use flat files

#### Success Criteria
- ✅ All peer data stored in SQLite
- ✅ Zero data loss during migration
- ✅ Faster peer lookups (especially with 100+ peers)
- ✅ Audit log captures all changes

---

### Phase 3: REST API (Priority: HIGH)
**Timeline:** 2-3 weeks
**Effort:** Medium
**Dependencies:** Phase 2 (Database Backend)

#### Objectives
- Provide programmatic access to WireWarp
- Foundation for web GUI
- Enable automation and integrations
- Support for CLI tool and future mobile apps

#### Technology Stack
**Option A: Python (FastAPI)** - Recommended
- Pros: Fast development, great async, auto OpenAPI docs
- Cons: Requires Python 3.7+

**Option B: Go**
- Pros: Single binary, fast, low memory
- Cons: More verbose, longer development

**Decision: FastAPI** (faster iteration, better for MVP)

#### Implementation Tasks

**3.1 API Server Setup**
- [ ] Create new repository: `wirewarp-api`
- [ ] Setup FastAPI project structure:
  ```
  wirewarp-api/
  ├── app/
  │   ├── __init__.py
  │   ├── main.py
  │   ├── config.py
  │   ├── database.py
  │   ├── models/
  │   ├── routers/
  │   ├── schemas/
  │   └── services/
  ├── tests/
  ├── requirements.txt
  └── Dockerfile
  ```
- [ ] Setup database connection (SQLAlchemy ORM)
- [ ] Configure CORS for web frontend

**3.2 Authentication System**
- [ ] Implement JWT-based authentication
- [ ] Create users table in database:
  ```sql
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT CHECK(role IN ('admin', 'operator', 'viewer')),
    created_at TIMESTAMP
  );
  ```
- [ ] Add `/auth/login` and `/auth/register` endpoints
- [ ] Create API key system for programmatic access
- [ ] Implement role-based access control (RBAC)

**3.3 Core API Endpoints**

**VPS Management:**
- [ ] `GET /api/vpses` - List all VPSes
- [ ] `POST /api/vpses` - Register new VPS
- [ ] `GET /api/vpses/{id}` - Get VPS details
- [ ] `PUT /api/vpses/{id}` - Update VPS config
- [ ] `DELETE /api/vpses/{id}` - Remove VPS
- [ ] `GET /api/vpses/{id}/status` - Get WireGuard status

**IP Pool Management:**
- [ ] `GET /api/vpses/{id}/ips` - List IPs for VPS
- [ ] `POST /api/vpses/{id}/ips` - Add IP to pool
- [ ] `DELETE /api/vpses/{id}/ips/{ip}` - Remove IP
- [ ] `GET /api/vpses/{id}/ips/{ip}/peers` - Show peers on IP

**Peer Management:**
- [ ] `GET /api/peers` - List all peers (with filtering)
- [ ] `POST /api/peers` - Create new peer
- [ ] `GET /api/peers/{id}` - Get peer details
- [ ] `PUT /api/peers/{id}` - Update peer config
- [ ] `DELETE /api/peers/{id}` - Remove peer
- [ ] `GET /api/peers/{id}/metrics` - Get bandwidth stats
- [ ] `POST /api/peers/{id}/suspend` - Temporarily disable
- [ ] `POST /api/peers/{id}/resume` - Re-enable peer

**Port Forwarding:**
- [ ] `GET /api/peers/{id}/ports` - List port forwards
- [ ] `POST /api/peers/{id}/ports` - Add port forward
- [ ] `DELETE /api/peers/{id}/ports/{port_id}` - Remove port
- [ ] `POST /api/peers/{id}/ports/bulk` - Bulk add/remove

**Monitoring:**
- [ ] `GET /api/metrics/bandwidth` - Aggregate bandwidth stats
- [ ] `GET /api/metrics/peers/active` - Count active peers
- [ ] `GET /api/health` - API health check

**3.4 Agent Communication**
- [ ] Design agent registration protocol
- [ ] Create `/api/agent/register` endpoint
- [ ] Create `/api/agent/heartbeat` endpoint (agent status)
- [ ] Create `/api/agent/execute` endpoint (send commands to agent)
- [ ] Implement WebSocket endpoint for real-time communication

**3.5 API Documentation**
- [ ] Auto-generated OpenAPI/Swagger docs (FastAPI automatic)
- [ ] Add example requests/responses
- [ ] Create Postman collection
- [ ] Write API usage guide

**3.6 Security Hardening**
- [ ] Rate limiting (10 requests/second per user)
- [ ] Input validation and sanitization
- [ ] SQL injection prevention (using ORM)
- [ ] Encrypt sensitive data (private keys) in database
- [ ] Add HTTPS requirement
- [ ] Implement request logging

**3.7 Deployment**
- [ ] Create systemd service file
- [ ] Create Docker image
- [ ] Add docker-compose.yml for easy deployment
- [ ] Setup log rotation
- [ ] Add production configuration (gunicorn/uvicorn)

#### API Example Usage
```bash
# Login
curl -X POST https://api.wirewarp.io/auth/login \
  -d '{"username":"admin","password":"xxx"}' \
  -H "Content-Type: application/json"

# Returns: {"access_token": "eyJ...", "token_type": "bearer"}

# Create peer
curl -X POST https://api.wirewarp.io/api/peers \
  -H "Authorization: Bearer eyJ..." \
  -d '{
    "vps_id": 1,
    "peer_name": "home_server",
    "vm_network": "10.99.5.0/24"
  }'

# Add port forward
curl -X POST https://api.wirewarp.io/api/peers/5/ports \
  -H "Authorization: Bearer eyJ..." \
  -d '{
    "protocol": "tcp",
    "public_port": 25565,
    "private_port": 25565
  }'
```

#### Success Criteria
- ✅ All core operations available via API
- ✅ API documentation complete and accurate
- ✅ Authentication working with JWT
- ✅ Rate limiting prevents abuse
- ✅ API responds in < 100ms for simple queries

---

### Phase 4: VPS Agent System (Priority: HIGH)
**Timeline:** 3-4 weeks
**Effort:** Medium-High
**Dependencies:** Phase 3 (API)

#### Objectives
- Secure alternative to SSH-based management
- Enable automated VPS provisioning from web GUI
- Real-time bidirectional communication with control panel
- Self-updating capabilities

#### Technology Stack
**Language: Go** (single binary, low resource usage, cross-platform)

#### Implementation Tasks

**4.1 Agent Core Development**
- [ ] Create new repository: `wirewarp-agent`
- [ ] Project structure:
  ```
  wirewarp-agent/
  ├── cmd/
  │   └── agent/
  │       └── main.go
  ├── internal/
  │   ├── config/
  │   ├── api/
  │   ├── executor/
  │   ├── metrics/
  │   └── updater/
  ├── scripts/
  │   └── install.sh
  └── Makefile
  ```
- [ ] Implement configuration management (YAML config file)
- [ ] Setup logging (structured logs to file + stdout)

**4.2 Registration & Authentication**
- [ ] Generate unique agent ID on first run (UUID)
- [ ] Create registration code system (6-character code)
- [ ] Implement mTLS certificate exchange with control panel
- [ ] Store JWT token for API authentication
- [ ] Add token refresh logic

**4.3 Command Execution**
- [ ] Implement safe command executor:
  - Whitelist of allowed commands (wirewarp, iptables, wg, etc.)
  - Input sanitization
  - Timeout protection
  - Resource limits (CPU, memory)
- [ ] Stream command output back to API in real-time
- [ ] Support interactive commands via WebSocket

**4.4 WireGuard Management Interface**
- [ ] Create wirewarp.sh wrapper functions
- [ ] `InitServer(interface string) error`
- [ ] `AddPeer(name, ip string) (PeerConfig, error)`
- [ ] `RemovePeer(peerID string) error`
- [ ] `AddPortForward(protocol, port, targetIP string) error`
- [ ] `RemovePortForward(protocol, port string) error`
- [ ] `GetStatus() (StatusInfo, error)`

**4.5 Metrics Collection**
- [ ] Collect WireGuard stats (`wg show` parsing)
- [ ] Collect system metrics (CPU, RAM, disk, bandwidth)
- [ ] Send metrics to API every 60 seconds
- [ ] Store metrics buffer locally if API unreachable

**4.6 WebSocket Connection**
- [ ] Persistent WebSocket to control panel
- [ ] Auto-reconnect with exponential backoff
- [ ] Heartbeat/ping-pong to detect disconnections
- [ ] Handle commands received via WebSocket

**4.7 Self-Update Mechanism**
- [ ] Check for updates on startup and every 24 hours
- [ ] Download new binary from control panel
- [ ] Verify signature before updating
- [ ] Atomic update (rename, not overwrite)
- [ ] Restart agent after update

**4.8 Installation Script**
- [ ] Create `install.sh` script:
  ```bash
  curl -fsSL https://wirewarp.io/install-agent.sh | bash
  ```
- [ ] Detect Linux distro (Debian/Ubuntu/CentOS/etc.)
- [ ] Install dependencies (wireguard, iptables)
- [ ] Download agent binary
- [ ] Create systemd service
- [ ] Generate registration code
- [ ] Display next steps to user

**4.9 Systemd Integration**
- [ ] Create service file: `/etc/systemd/system/wirewarp-agent.service`
- [ ] Enable auto-start on boot
- [ ] Setup log collection (journalctl)
- [ ] Add restart policy (on-failure)

**4.10 Security Features**
- [ ] Run as non-root user (except for iptables commands)
- [ ] Use sudo with NOPASSWD for specific commands only
- [ ] Encrypt configuration file
- [ ] Clear private keys from memory after use
- [ ] Add fail2ban integration (block repeated failed commands)

#### Agent API Contract
```go
// Commands sent from control panel to agent
type Command struct {
    ID      string      `json:"id"`
    Type    string      `json:"type"`  // "init_server", "add_peer", etc.
    Params  interface{} `json:"params"`
}

// Response sent from agent to control panel
type CommandResponse struct {
    CommandID string `json:"command_id"`
    Success   bool   `json:"success"`
    Output    string `json:"output"`
    Error     string `json:"error,omitempty"`
}

// Metrics sent periodically
type Metrics struct {
    Timestamp     time.Time         `json:"timestamp"`
    SystemMetrics SystemMetrics     `json:"system"`
    WireGuard     WireGuardMetrics  `json:"wireguard"`
}
```

#### Installation Flow
```
1. User runs: curl -fsSL https://wirewarp.io/install-agent.sh | bash

2. Script output:
   Installing WireWarp Agent...
   ✓ Dependencies installed
   ✓ Agent downloaded and installed
   ✓ Service created

   Registration Code: ABC-XYZ-123

   Next steps:
   1. Go to https://wirewarp.io/dashboard
   2. Click "Add VPS"
   3. Enter the registration code above

   The agent will connect automatically once registered.

3. User enters code in web GUI

4. Agent receives activation signal

5. Connection established, VPS ready to manage
```

#### Success Criteria
- ✅ Agent installs with single command
- ✅ Registration flow works smoothly
- ✅ Commands execute successfully via WebSocket
- ✅ Metrics appear in control panel within 60 seconds
- ✅ Agent auto-updates without manual intervention
- ✅ Resource usage < 50MB RAM, < 1% CPU when idle

---

### Phase 5: Web Dashboard (Priority: HIGH)
**Timeline:** 4-6 weeks
**Effort:** High
**Dependencies:** Phase 3 (API), Phase 4 (Agent)

#### Objectives
- Intuitive visual interface for all WireWarp operations
- Real-time monitoring and status updates
- Automated provisioning workflow (zero terminal commands)
- Mobile-responsive design

#### Technology Stack
- **Frontend Framework:** React 18 with TypeScript
- **UI Library:** Tailwind CSS + shadcn/ui components
- **State Management:** Zustand or Redux Toolkit
- **API Client:** React Query (TanStack Query)
- **Charts:** Recharts or Chart.js
- **Terminal Emulator:** xterm.js
- **WebSocket:** Socket.io-client
- **Build Tool:** Vite

#### Implementation Tasks

**5.1 Project Setup**
- [ ] Create React app with TypeScript template
- [ ] Setup Tailwind CSS and component library
- [ ] Configure ESLint and Prettier
- [ ] Setup routing (React Router)
- [ ] Configure environment variables (.env)

**5.2 Authentication & User Management**
- [ ] Login page with form validation
- [ ] JWT token storage (secure httpOnly cookies)
- [ ] Protected route wrapper component
- [ ] User profile page
- [ ] Password reset flow
- [ ] Role-based UI visibility

**5.3 Dashboard Overview Page**
- [ ] Summary cards:
  - Total VPSes
  - Total Peers
  - Active Connections
  - Total Bandwidth (30d)
- [ ] Recent activity feed (audit log)
- [ ] System health indicators
- [ ] Quick action buttons (Add VPS, Add Peer)

**5.4 VPS Management Interface**

**VPS List View:**
- [ ] Table showing all VPSes
- [ ] Columns: Name, IP, Status, Peers, Uptime
- [ ] Search and filter functionality
- [ ] Status indicators (online/offline)
- [ ] Actions: View, Edit, Delete

**Add VPS Modal:**
- [ ] Two options: SSH Setup or Agent Code
- [ ] SSH Setup form:
  - VPS IP/hostname
  - SSH user (default: root)
  - SSH key upload or password
  - Test connection button
- [ ] Agent Code tab:
  - Display installation command
  - Show registration code input
  - Auto-refresh when agent connects
- [ ] Progress indicator during setup

**VPS Detail Page:**
- [ ] Overview tab: IP pools, system info, WireGuard status
- [ ] Peers tab: List of peers on this VPS
- [ ] Metrics tab: Bandwidth graphs, connection history
- [ ] Settings tab: Edit IP pools, WireGuard config
- [ ] Embedded terminal (xterm.js) for SSH access

**5.5 Peer Management Interface**

**Peer List View:**
- [ ] Table with columns: Name, VPS, Tunnel IP, VM IP, Status, Bandwidth
- [ ] Filter by VPS, status, date range
- [ ] Search by peer name
- [ ] Bulk actions (suspend, delete)
- [ ] Export to CSV

**Add Peer Wizard:**
- [ ] Step 1: Select VPS
- [ ] Step 2: Enter peer name
- [ ] Step 3: Choose IP assignment (auto or manual)
- [ ] Step 4: Review configuration
- [ ] Step 5: Automated setup options:
  - Manual: Show client command to copy
  - Proxmox: Enter Proxmox API credentials, auto-configure
  - SSH: Enter client SSH details, auto-setup
- [ ] Success screen with VM network details

**Peer Detail Page:**
- [ ] Overview: Connection status, IPs, configuration
- [ ] Port Forwards tab (see below)
- [ ] Metrics: Real-time bandwidth graph, connection history
- [ ] Logs: Recent events (connection, disconnection, errors)
- [ ] Actions: Suspend, Resume, Migrate IP, Delete

**5.6 Port Forwarding Interface**

**Visual Port Manager:**
- [ ] Two-column layout:
  - Left: VPS public IP with ports
  - Right: VM private IP with ports
- [ ] Drag-and-drop to create port forwards
- [ ] Click port number to add forward manually
- [ ] Port status indicators (active, inactive, conflict)
- [ ] Protocol badges (TCP, UDP, Both)

**Add Port Forward Modal:**
- [ ] Protocol selector (TCP/UDP/Both)
- [ ] Port input with validation
- [ ] Support ranges (e.g., "8000-8010")
- [ ] Support multiple (e.g., "80,443,8080")
- [ ] Conflict detection (show warning if port in use)
- [ ] Service templates dropdown:
  - Minecraft Server (25565 TCP/UDP)
  - Web Server (80, 443 TCP)
  - SSH (22 TCP)
  - Custom

**5.7 Monitoring Dashboard**

**Real-time Metrics:**
- [ ] Live connection count
- [ ] Bandwidth usage graphs (last hour, day, week, month)
- [ ] Per-peer bandwidth breakdown
- [ ] System resource usage (CPU, RAM, disk per VPS)
- [ ] Alert notifications panel

**Analytics:**
- [ ] Most used peers (by bandwidth)
- [ ] Peak usage times (heatmap)
- [ ] Port forwarding usage statistics
- [ ] Growth trends (peers over time)

**5.8 Proxmox Integration UI**

**Add Proxmox Host:**
- [ ] Form fields:
  - Proxmox API URL (e.g., https://192.168.1.100:8006)
  - Username (e.g., root@pam)
  - Password or API token
  - Node name
- [ ] Test connection button
- [ ] Auto-detect available VMs
- [ ] Offer to install WireWarp client

**VM Configuration Interface:**
- [ ] List VMs on Proxmox host
- [ ] Select VM to attach to tunnel
- [ ] One-click network configuration:
  - Creates bridge
  - Sets VM network adapter
  - Configures IP in VM (if possible)
- [ ] Progress indicator with terminal output

**5.9 Terminal Emulator Integration**

**Embedded Terminal (xterm.js):**
- [ ] WebSocket connection to backend
- [ ] Backend proxies SSH to VPS/Proxmox
- [ ] Full-featured terminal (colors, cursor, copy/paste)
- [ ] Terminal tabs (multiple sessions)
- [ ] Save session history
- [ ] Keyboard shortcuts

**5.10 Settings & Configuration**

**User Settings:**
- [ ] Profile information
- [ ] Change password
- [ ] Two-factor authentication (TOTP)
- [ ] API key generation
- [ ] Notification preferences

**System Settings (Admin only):**
- [ ] Global WireGuard defaults
- [ ] Alerting rules configuration
- [ ] Backup/restore
- [ ] Audit log viewer

**5.11 Mobile Responsive Design**
- [ ] Hamburger menu for navigation
- [ ] Touch-friendly buttons (44px min)
- [ ] Simplified tables (stacked layout)
- [ ] Mobile-optimized forms
- [ ] Swipe gestures for actions

**5.12 Notifications & Alerts**
- [ ] Toast notifications for actions (success/error)
- [ ] Bell icon with unread count
- [ ] Alert types:
  - Peer disconnected
  - VPS offline
  - High bandwidth usage
  - Agent update available
- [ ] Email notifications (optional)
- [ ] Webhook integrations (Discord, Slack)

**5.13 Help & Documentation**
- [ ] Contextual help tooltips
- [ ] Guided tours (Intro.js) for first-time users
- [ ] Link to documentation site
- [ ] FAQ section
- [ ] Support chat widget (optional)

#### UI Mockup Structure
```
┌─────────────────────────────────────────────────────────────┐
│  WireWarp    [Dashboard] [VPSes] [Peers] [Monitoring] 🔔 👤 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  📊 Overview                                                 │
│  ┌────────────┬────────────┬────────────┬────────────┐     │
│  │ 3 VPSes    │ 12 Peers   │ 11 Active  │ 45.2 GB    │     │
│  │ Online     │ Total      │ Now        │ This Month │     │
│  └────────────┴────────────┴────────────┴────────────┘     │
│                                                              │
│  📈 Bandwidth (Last 7 Days)                                  │
│  ┌──────────────────────────────────────────────────┐       │
│  │         [Line graph showing bandwidth]           │       │
│  └──────────────────────────────────────────────────┘       │
│                                                              │
│  🎯 Quick Actions                                            │
│  [+ Add VPS]  [+ Add Peer]  [+ Port Forward]               │
│                                                              │
│  📋 Recent Activity                                          │
│  • Peer "home_server" connected (2m ago)                    │
│  • Port 25565 added to "minecraft_vm" (15m ago)             │
│  • VPS "nyc-vps-01" came online (1h ago)                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Success Criteria
- ✅ Complete VPS setup without touching terminal
- ✅ Page load time < 2 seconds
- ✅ Works on mobile (iPhone, Android)
- ✅ Passes accessibility audit (WCAG 2.1 AA)
- ✅ Intuitive enough for non-technical users

---

### Phase 6: Enhanced Monitoring & Observability (Priority: MEDIUM)
**Timeline:** 2-3 weeks
**Effort:** Medium
**Dependencies:** Phase 4 (Agent)

#### Objectives
- Comprehensive metrics collection
- Alerting system for critical events
- Integration with industry-standard tools
- Historical data analysis

#### Implementation Tasks

**6.1 Metrics Collection Infrastructure**
- [ ] Setup Prometheus exporter in agent
- [ ] Expose metrics endpoint: `http://localhost:9090/metrics`
- [ ] Metrics to collect:
  ```
  # WireGuard
  wireguard_peer_up{peer="home_server"} 1
  wireguard_peer_rx_bytes{peer="home_server"} 1024000
  wireguard_peer_tx_bytes{peer="home_server"} 2048000
  wireguard_peer_last_handshake{peer="home_server"} 1634567890

  # System
  wirewarp_system_cpu_percent 15.3
  wirewarp_system_memory_used_bytes 1073741824
  wirewarp_system_disk_used_percent 45.2

  # Application
  wirewarp_peers_total 12
  wirewarp_peers_active 11
  wirewarp_port_forwards_total 45
  ```

**6.2 Alerting Rules**
- [ ] Define alert conditions in API:
  ```yaml
  alerts:
    - name: PeerDisconnected
      condition: wireguard_peer_up == 0
      duration: 5m
      severity: warning

    - name: HighBandwidth
      condition: rate(wireguard_peer_rx_bytes[5m]) > 100MB
      severity: info

    - name: VPSOffline
      condition: up{job="wirewarp-agent"} == 0
      duration: 2m
      severity: critical
  ```
- [ ] Implement alert evaluation engine
- [ ] Create alert notification system

**6.3 Notification Channels**
- [ ] Email notifications (SMTP)
- [ ] Discord webhooks
- [ ] Slack webhooks
- [ ] Telegram bot
- [ ] Custom webhooks (generic)
- [ ] Web UI notification center

**6.4 Grafana Dashboards**
- [ ] Create official Grafana dashboard JSON
- [ ] Panels:
  - Peer status overview
  - Bandwidth usage per peer
  - System resource usage
  - Alert history
  - Port forward traffic
- [ ] Publish to Grafana dashboard marketplace

**6.5 Logging Infrastructure**
- [ ] Structured logging in all components
- [ ] Centralized log collection (optional: Loki)
- [ ] Log levels: DEBUG, INFO, WARN, ERROR
- [ ] Log rotation (keep 7 days)
- [ ] Searchable logs in web UI

**6.6 Health Checks**
- [ ] API endpoint: `GET /health`
- [ ] Database connectivity check
- [ ] VPS agent connectivity check
- [ ] WireGuard interface status check
- [ ] Return 200 if healthy, 503 if degraded

**6.7 Performance Monitoring**
- [ ] API response time tracking
- [ ] Database query performance
- [ ] Slow query logging (> 1 second)
- [ ] Resource usage trends

#### Success Criteria
- ✅ Metrics visible in Prometheus within 1 minute
- ✅ Alerts trigger within defined duration
- ✅ Grafana dashboard shows live data
- ✅ Email notifications arrive within 30 seconds

---

### Phase 7: High Availability & Clustering (Priority: LOW)
**Timeline:** 4-6 weeks
**Effort:** High
**Dependencies:** All previous phases

#### Objectives
- Multi-VPS clustering for redundancy
- Automatic failover if VPS goes down
- Geographic distribution
- Load balancing across cluster

#### Implementation Tasks

**7.1 Cluster Architecture Design**
- [ ] Define cluster topology:
  ```
  Control Panel (Central)
      ├── VPS Cluster 1 (US East)
      │   ├── VPS 1 (Primary)
      │   └── VPS 2 (Backup)
      └── VPS Cluster 2 (EU West)
          ├── VPS 3 (Primary)
          └── VPS 4 (Backup)
  ```
- [ ] Database schema updates for cluster support
- [ ] Peer assignment strategies (geographic, load-based)

**7.2 Health Monitoring**
- [ ] Continuous VPS health checks
- [ ] Peer connectivity tests
- [ ] Latency measurements
- [ ] Failover trigger conditions

**7.3 Failover Mechanism**
- [ ] Detect VPS failure (missed 3 heartbeats)
- [ ] Select backup VPS from same cluster
- [ ] Migrate peer configuration to backup
- [ ] Update DNS/routing if needed
- [ ] Notify client to reconnect

**7.4 Configuration Sync**
- [ ] Replicate peer configs across cluster
- [ ] Consistent port forward rules
- [ ] Database replication (master-slave or multi-master)

**7.5 Testing**
- [ ] Chaos engineering tests (kill VPS randomly)
- [ ] Measure failover time (target: < 30 seconds)
- [ ] Ensure zero data loss

#### Success Criteria
- ✅ Peer reconnects automatically after VPS failure
- ✅ Failover completes in < 60 seconds
- ✅ No manual intervention required

---

### Phase 8: Advanced Features (Priority: LOW)
**Timeline:** Ongoing
**Effort:** Variable

#### Feature Backlog

**8.1 IPv6 Support**
- Dual-stack WireGuard configuration
- IPv6 port forwarding
- IPv6 address pools

**8.2 Split Tunneling**
- Route only specific traffic through VPS
- AllowedIPs customization per peer
- Use case: Route only game traffic, keep web browsing local

**8.3 QoS & Traffic Shaping**
- Bandwidth limits per peer
- Priority queues (game traffic > file downloads)
- Fair queuing

**8.4 Mesh Networking**
- Allow peer-to-peer connections
- Reduce latency for direct communication
- Complex routing topologies

**8.5 CLI Tool**
- `wirewarp` command-line interface
- Commands: `wirewarp peer add`, `wirewarp port add`, etc.
- API client library for scripting
- Autocomplete support (bash, zsh)

**8.6 Mobile Apps**
- iOS app (Swift)
- Android app (Kotlin)
- Features: View status, manage ports, alerts
- Push notifications

**8.7 Terraform Provider**
- Infrastructure as Code support
- Manage WireWarp resources via Terraform
- CI/CD integration

**8.8 Backup & Disaster Recovery**
- Automated configuration backups
- One-click restore
- Export/import functionality

**8.9 Multi-Protocol Support**
- OpenVPN as alternative to WireGuard
- IKEv2/IPsec support
- Protocol selection per peer

**8.10 Enterprise Features**
- SSO/OIDC integration (Okta, Auth0)
- Multi-tenancy (isolated customer environments)
- Detailed audit logs with compliance reports
- SLA monitoring

---

## Technical Architecture (Target State)

### High-Level Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                  Internet / End Users                       │
└────────────┬────────────────────────────┬───────────────────┘
             │                            │
             │ Access services            │ Access control panel
             │                            │
             ▼                            ▼
    ┌─────────────────┐         ┌─────────────────┐
    │  VPS Cluster    │         │ Control Panel   │
    │  (Multiple IPs) │◄────────│   (Web GUI)     │
    │                 │  Mgmt   │   + API         │
    │  WireGuard      │  API    │                 │
    │  + Agent        │         │  PostgreSQL DB  │
    └────────┬────────┘         └─────────────────┘
             │                            ▲
             │ WireGuard Tunnel           │ WebSocket
             │                            │
             ▼                            │
    ┌─────────────────┐                  │
    │ Client Machines │                  │
    │ (Proxmox/VMs)   │──────────────────┘
    │                 │   Agent (optional)
    │  WireGuard      │
    │  Client         │
    └─────────────────┘
```

### Component Interaction Flow
```
User Action (Web GUI): "Add new peer"
    ↓
Web Frontend sends: POST /api/peers
    ↓
API Server:
    1. Validates request
    2. Selects VPS with available capacity
    3. Assigns IP from pool
    4. Generates WireGuard keys
    5. Stores in database
    6. Sends command to VPS agent
    ↓
VPS Agent:
    1. Receives command via WebSocket
    2. Executes wirewarp.sh (add peer)
    3. Updates iptables rules
    4. Returns success/failure
    ↓
API Server:
    1. Updates database status
    2. Returns response to frontend
    ↓
Web Frontend:
    1. Shows success message
    2. Displays client setup command OR
    3. Triggers automated Proxmox setup
```

### Data Flow
```
Metrics Collection:
VPS Agent → Collects WireGuard stats (every 60s)
         ↓
         Sends to API → Stores in metrics table
                     ↓
                     Prometheus scrapes /metrics
                     ↓
                     Grafana visualizes
                     ↓
         Web Dashboard fetches via API
```

---

## Implementation Timeline

### Month 1
- ✅ Phase 1: Multi-IP Support (weeks 1-3)
- ✅ Phase 2: Database Backend (week 4)

### Month 2
- ✅ Phase 3: REST API (weeks 1-3)
- ✅ Phase 4: VPS Agent (week 4, start)

### Month 3
- ✅ Phase 4: VPS Agent (weeks 1-2, finish)
- ✅ Phase 5: Web Dashboard (weeks 3-4, start)

### Month 4-5
- ✅ Phase 5: Web Dashboard (finish)
- ✅ Integration testing
- ✅ Documentation

### Month 6
- ✅ Phase 6: Monitoring & Observability
- ✅ Beta testing
- ✅ Marketing materials

### Month 7+
- ✅ Phase 7: HA & Clustering (optional)
- ✅ Phase 8: Advanced features (ongoing)

---

## Success Metrics

### Technical Metrics
- **Setup Time:** User can go from zero to working tunnel in < 5 minutes
- **API Latency:** 95th percentile < 200ms
- **Uptime:** 99.9% availability (excluding VPS provider issues)
- **Agent Resource Usage:** < 50MB RAM, < 1% CPU
- **Failover Time:** < 60 seconds (if HA implemented)

### User Metrics
- **GitHub Stars:** 500+ in first 6 months
- **Active Installations:** 100+ VPSes managed
- **User Satisfaction:** 4.5+ stars on reviews
- **Support Requests:** < 5% of users need help with setup

### Business Metrics (if monetizing)
- **Conversion Rate:** 10% of free users upgrade to paid features
- **Monthly Recurring Revenue:** $1000+ within 12 months
- **Customer Retention:** 90%+ after 6 months

---

## Risk Assessment

### Technical Risks
| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| WireGuard kernel changes break compatibility | High | Low | Pin WireGuard version, automated testing |
| Database corruption | High | Low | Automated backups, transaction safety |
| Agent security vulnerability | High | Medium | Security audit, bug bounty program |
| API performance issues at scale | Medium | Medium | Load testing, caching, horizontal scaling |
| Complex iptables rules cause conflicts | Medium | Medium | Separate chains per IP, thorough testing |

### Market Risks
| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Cloudflare adds UDP tunnel support | High | Medium | Focus on self-hosted privacy angle |
| Low adoption due to complexity | High | Medium | Excellent documentation, video tutorials |
| VPS providers block WireGuard | Medium | Low | Multi-provider support, documentation |
| Competition from Tailscale/others | Medium | High | Differentiate: self-hosted, no per-user cost |

### Operational Risks
| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Maintainer burnout | High | Medium | Open source community, contributor onboarding |
| Support burden too high | Medium | Medium | Good docs, FAQ, community forum |
| Breaking changes alienate users | Medium | Low | Semantic versioning, migration guides |

---

## Marketing & Go-to-Market Strategy

### Pre-Launch (During Development)
- [ ] Create landing page (https://wirewarp.io)
- [ ] Start dev blog (document journey, technical decisions)
- [ ] Build email list (early access signup)
- [ ] Create social media accounts (Twitter, Reddit)

### Launch Strategy
- [ ] **Reddit:** Post to r/homelab, r/selfhosted, r/admincraft
- [ ] **YouTube:** Create tutorial video "Host Minecraft Without Port Forwarding"
- [ ] **Hacker News:** Submit "Show HN: WireWarp - Self-hosted tunnel for home servers"
- [ ] **Product Hunt:** Launch with demo video
- [ ] **LinusTechTips Forum:** Share in networking section

### Content Marketing
- [ ] Blog posts:
  - "Why I built WireWarp: The self-hosted ngrok alternative"
  - "Host game servers safely with dynamic IPs"
  - "Bypass CGNAT with WireGuard and a $5 VPS"
  - "Complete guide to Proxmox + WireWarp"
- [ ] Video tutorials:
  - 5-minute quickstart
  - Minecraft server setup walkthrough
  - Multi-VM Proxmox configuration
  - Port forwarding best practices

### Community Building
- [ ] Create Discord server for users
- [ ] Setup GitHub Discussions
- [ ] Community showcase (user configs, use cases)
- [ ] Contributor recognition program

### Monetization Options (Optional)
1. **Open Core Model:**
   - Free: Single VPS, unlimited peers, community support
   - Pro ($9/mo): Multi-VPS clustering, HA, priority support
   - Enterprise ($99/mo): SSO, audit logs, SLA

2. **Managed Hosting:**
   - Offer hosted control panel ($15/mo)
   - User brings their own VPS
   - We manage updates, backups, monitoring

3. **Support Services:**
   - Setup assistance ($50 one-time)
   - Custom integrations (hourly consulting)

4. **GitHub Sponsors:**
   - Tiers: $5, $10, $25, $100/mo
   - Perks: Priority support, feature voting, logo on site

---

## Documentation Plan

### User Documentation
- [ ] **Getting Started Guide**
  - Requirements
  - VPS provider recommendations
  - Installation (script method)
  - First peer setup
  - First port forward

- [ ] **User Manual**
  - Web dashboard tour
  - VPS management
  - Peer management
  - Port forwarding
  - Monitoring & alerts
  - Troubleshooting

- [ ] **Proxmox Integration Guide**
  - API setup
  - Automated configuration
  - VM network configuration
  - Best practices

- [ ] **Video Tutorials**
  - 5-minute quickstart
  - Complete walkthrough (30 min)
  - Common use cases (Minecraft, web hosting, etc.)

### Developer Documentation
- [ ] **API Reference**
  - OpenAPI/Swagger spec
  - Authentication guide
  - Rate limits
  - Examples for all endpoints

- [ ] **Agent Development**
  - Architecture overview
  - Command protocol
  - Adding new commands
  - Testing

- [ ] **Contributing Guide**
  - Code style
  - Pull request process
  - Testing requirements
  - Release process

### Operations Documentation
- [ ] **Deployment Guide**
  - Docker deployment
  - Systemd deployment
  - Kubernetes deployment (Helm)
  - Environment variables
  - Configuration options

- [ ] **Monitoring & Alerting**
  - Prometheus setup
  - Grafana dashboard import
  - Alert configuration
  - Log analysis

- [ ] **Backup & Recovery**
  - Database backup procedures
  - Configuration export/import
  - Disaster recovery steps

- [ ] **Security Hardening**
  - TLS/HTTPS setup
  - Firewall configuration
  - Security best practices
  - Audit logging

---

## Testing Strategy

### Unit Tests
- [ ] API endpoint tests (pytest)
- [ ] Database model tests
- [ ] Agent command execution tests
- [ ] Frontend component tests (Jest, React Testing Library)

### Integration Tests
- [ ] API → Database integration
- [ ] API → Agent communication
- [ ] End-to-end peer creation flow
- [ ] Port forwarding functionality

### System Tests
- [ ] Multi-VPS scenarios
- [ ] Multi-IP assignment
- [ ] Failover testing (if HA implemented)
- [ ] Load testing (100+ peers)

### Security Tests
- [ ] Penetration testing
- [ ] SQL injection prevention
- [ ] XSS prevention
- [ ] Authentication bypass attempts
- [ ] Rate limiting effectiveness

### User Acceptance Testing
- [ ] Beta user feedback
- [ ] Usability testing (5 users, observe setup)
- [ ] Mobile responsiveness testing
- [ ] Browser compatibility (Chrome, Firefox, Safari, Edge)

---

## Open Source Strategy

### License
**Recommendation: AGPL-3.0**
- Copyleft license (derivatives must be open source)
- Network use triggers share-alike (prevents SaaS without contribution)
- Alternative: MIT (more permissive, easier adoption)

### Repository Structure
```
wirewarp/
├── wirewarp-scripts/       # Current bash scripts (core)
├── wirewarp-api/           # Backend API (Python/Go)
├── wirewarp-agent/         # VPS agent (Go)
├── wirewarp-web/           # Web dashboard (React)
├── wirewarp-cli/           # CLI tool (Go)
├── docs/                   # Documentation site
└── examples/               # Example configs, Docker Compose, etc.
```

### Community Guidelines
- [ ] Code of Conduct (Contributor Covenant)
- [ ] Contributing guidelines
- [ ] Issue templates (bug report, feature request)
- [ ] Pull request template
- [ ] Security policy (responsible disclosure)

### Governance
- [ ] Define maintainer roles
- [ ] Decision-making process
- [ ] Release cycle (semantic versioning)
- [ ] Roadmap transparency (GitHub Projects)

---

## Conclusion

This improvement plan transforms WireWarp from a **utility script** into a **comprehensive infrastructure platform** for safely exposing home servers. The phased approach allows for:

1. **Immediate value:** Multi-IP support benefits current users
2. **Progressive enhancement:** Each phase builds on previous work
3. **Flexibility:** Can pause/skip phases based on feedback
4. **Sustainability:** Community-driven development ensures longevity

**Next Steps:**
1. ✅ Review and approve this plan
2. ✅ Prioritize phases (can adjust based on your goals)
3. ✅ Begin Phase 1 implementation (multi-IP support)
4. ✅ Set up project management (GitHub Projects, milestones)
5. ✅ Create initial marketing landing page
6. ✅ Start building community (Discord, social media)

**Estimated Time to MVP (Phases 1-5):** 4-5 months with dedicated part-time work

Would you like to proceed with implementation? I can start with any phase you prefer!

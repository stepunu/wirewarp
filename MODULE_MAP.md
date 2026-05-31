# Module Map

Generated on 2026-05-30 from non-gitignored files, excluding `docs/`.
Updated on 2026-05-31 for the Node Edge / Cloudflare-parity implementation.

## Root

- `README.md` - user-facing overview, features, quick start, and stack notes.
- `ARCHITECTURE.md` - older architecture/planning document. Useful for intent, but verify against code.
- `CLAUDE.md` - agent/developer guidance and project conventions. Some implementation details are stale.
- `tasks.md` - roadmap-style task list. Phase 12 and Phase 13 now reflect the implemented Node Edge surface plus remaining live-verification and cache-index work.
- `.github/workflows/tests.yml` - CI for server tests, Go checks, and frontend build.
- `.github/workflows/docker-image.yml` - builds the static agent artifact, commits it, and publishes the server image.
- `.claude/commands/rebuild.md` - deployment command notes for rebuilding the control server container.
- `.dockerignore` and `.gitignore` - important for understanding what was intentionally excluded from this exploration.

## Server: `wirewarp-server`

Entrypoints and configuration:

- `app/main.py` - FastAPI app, lifespan startup, REST router registration, agent/dashboard WebSocket endpoints, static SPA serving.
- `app/config.py` - Pydantic settings, database URL, JWT secret, token expiry.
- `app/database.py` - async SQLAlchemy engine, session factory, declarative base.
- `Dockerfile` - multi-stage image that builds the web app, installs Python deps, runs migrations, and starts uvicorn.
- `docker-compose.yml` - local API/Postgres stack.
- `requirements.txt` and `pyproject.toml` - Python dependencies and pytest config.

Auth and users:

- `app/auth.py` - password hashing, JWT creation/validation, role dependencies, auth audit events.
- `app/models/user.py` - user, role, auth provider, and VPN enablement fields.
- `app/routers/auth.py` - login/logout/register/providers/me endpoints.
- `app/routers/users.py` - admin user CRUD and role management.
- `app/routers/oidc.py`, `app/routers/ldap.py`, `app/services/oidc.py`, `app/services/ldap.py` - external auth provider wiring.
- `app/services/secrets.py` - registration token hashing and reversible encryption for provider secrets.

Core models:

- `app/models/agent.py` - agents, registration tokens, command log, metrics.
- `app/models/tunnel_server.py`, `tunnel_server_ip.py`, `tunnel_client.py`, `tunnel_client_attachment.py`, `port_forward.py` - tunnel topology and forwarding.
- `app/models/gateway_lan_client.py` - discovered/pinned LAN clients.
- `app/models/vpn_endpoint.py`, `vpn_profile.py`, `vpn_permission.py` - road-warrior VPN state.
- `app/models/system_settings.py` - singleton system settings.
- `app/models/crowdsec_snapshot.py`, `traefik_snapshot.py`, `security_event.py`, `edge_route_config.py` - legacy and compatibility security edge state.
- `app/models/edge_component_state.py`, `edge_node_policy.py`, `edge_profile.py`, `edge_path_rule.py`, `edge_config_version.py`, `edge_access_event.py`, `edge_cache_snapshot.py`, `edge_fragment.py`, `edge_upstream_pool.py` - Node Edge capability, policy, routing, access-feed, cache, and rendered-config state.
- `app/models/heal_event.py` - agent self-healing events.
- `app/models/wg_peer_snapshot.py`, `wg_traffic_sample.py` - WireGuard peer snapshots and traffic samples.

API routers:

- `app/routers/agents.py` - agent list/detail/delete, registration tokens, agent update commands, heal events.
- `app/routers/tunnel_servers.py` - tunnel server list/detail/summary, rebase, CrowdSec and Traefik install/status.
- `app/routers/tunnel_server_ips.py` - server IP management.
- `app/routers/tunnel_clients.py` - gateway client list/detail/summary.
- `app/routers/tunnel_client_attachments.py` - attach/detach clients to servers.
- `app/routers/lan_clients.py` - discovered LAN clients, pinning, egress routes, SNAT.
- `app/routers/port_forwards.py` - raw TCP/UDP forwards and HTTP edge forwards.
- `app/routers/nodes.py` - unified node inventory/detail plus node-scoped edge capabilities, policy, routes, install/enable/disable/reconcile actions.
- `app/routers/edge_node.py` - node-scoped edge runtime resources: access events, cache status/stats/purge/test, upstream pools, desired/rendered config, import, versions, fragments.
- `app/routers/edge.py` - global/route-shaped edge resources: profiles, routes by ID, path rules, fragments, access events, route cache actions, upstream pool updates.
- `app/routers/service_templates.py` - reusable service presets.
- `app/routers/vpn_endpoints.py` - VPN endpoint CRUD and per-user permissions.
- `app/routers/vpn_profiles.py` - admin and self-service VPN profiles.
- `app/routers/security.py` - security overview, events, sites, protections, bans, certificates.
- `app/routers/settings.py` - system settings and provider test endpoints.
- `app/routers/audit.py` - command/audit history.

Services:

- `app/services/agent_commands.py` - command validation, command log creation, and WebSocket send path.
- `app/services/tunnel_server_ops.py` - WireGuard init/attach/detach/peer commands and LAN routing commands.
- `app/services/network_alloc.py` - tunnel network, attachment IP, VPN IP, ordinal, fwmark, and route-table allocation.
- `app/services/vpn_ops.py` - VPN endpoint/profile config generation and agent command dispatch.
- `app/services/traefik_ops.py` - desired Traefik static/dynamic config generation and sync dispatch.
- `app/services/crowdsec_ops.py` - desired CrowdSec whitelist generation and sync dispatch.
- `app/services/edge_ops.py` - Security Edge capability guardrails, component desired state, full desired-state rendering, and edge command dispatch.
- `app/services/edge_resources.py` - profiles, node policy, effective-policy inheritance, route/path helpers, and policy writes.
- `app/services/edge_runtime.py` - rendered/effective config snapshots, config version rows, and desired-state document assembly.
- `app/services/edge_cache_ops.py` - node/route cache policy normalization and Nginx cache desired-state rendering.
- `app/services/traefik_importer.py` - Traefik import preview/apply/upsert mapping.
- `app/services/dns_sync.py` - Cloudflare DNS sync for LAN egress/service changes.
- `app/services/service_templates.py` - service template defaults and matching.
- `app/services/traffic_sampler.py` - background sampling of WireGuard peer counters.

WebSocket and realtime:

- `app/websocket/hub.py` - connected agent registry and send helpers.
- `app/websocket/handlers.py` - heartbeat, command result, metrics, healing, CrowdSec, Traefik, security event, edge access event, and edge cache status handlers.
- `app/websocket/schemas.py` - WebSocket message payload schemas.
- `app/realtime/bus.py` - bounded fanout bus for dashboard clients.
- `app/realtime/events.py` - typed dashboard event emitters.

Schema and tests:

- `alembic/versions/*.py` - migration chain through `0038_edge_upstream_pools`.
- `tests/conftest.py` - SQLite async test harness, dependency overrides, fake WebSocket manager, factories.
- `tests/test_*.py` - focused backend coverage for auth, tunnels, LAN, VPN, port forwards, security edge, Node Edge capability/routes/runtime/access/cache APIs, websocket handlers, and migrations-adjacent behavior.

## Agent: `wirewarp-agent`

Entrypoint and config:

- `cmd/agent/main.go` - flags, config load, WebSocket client startup, handler registration, healers, update command.
- `internal/config/config.go` - YAML config load/save, first-run creation, legacy client-state migration.
- `Makefile` - linux/amd64 build into `dist/wirewarp-agent`.
- `go.mod` - Go module dependencies.

WebSocket and command execution:

- `internal/websocket/client.go` - registration/auth, reconnect loop, heartbeat, public IP detection, peer snapshots.
- `internal/websocket/vpn.go` - VPN peer dump parsing.
- `internal/executor/executor.go` - command dispatch and result reporting.
- `internal/executor/types.go` - command/result message types.

Command handlers:

- `internal/handlers/server.go` - server-side WireGuard init/peer management and port-forward commands.
- `internal/handlers/client.go` - gateway attachment setup, detach, endpoint update, LAN egress rules.
- `internal/handlers/vpn.go` - VPN endpoint and peer lifecycle.
- `internal/handlers/traefik.go` - Traefik install/sync/status, appsec enable, security events.
- `internal/handlers/crowdsec.go` and `crowdsec_install.go` - CrowdSec install, status polling, whitelist sync.
- `internal/handlers/edge_desired.go` - server Security Edge desired-state persistence and reconciliation across Traefik, CrowdSec/AppSec, access logs, and Nginx cache.
- `internal/handlers/edge_lifecycle.go` - reversible install/enable/disable helpers that stop services without deleting generated state.
- `internal/handlers/edge_cache.go` - managed Nginx `proxy_cache` config rendering, status collection, health probes, cache test command, and safe purge helpers.
- `internal/handlers/server_edge_reconciler.go` - server-mode edge reconcile/status polling loop.
- `cmd/agent/main.go` - also contains the current self-update handler.
- `internal/handlers/routing_restore.go` - restore saved routing after reboot.
- `internal/handlers/client_heal.go`, `server_heal.go`, `heal.go` - recurring self-healing and event reporting.

Networking primitives:

- `internal/wireguard/server.go` - server interface config and peer sync.
- `internal/wireguard/client.go` - gateway interface config and key handling.
- `internal/wireguard/gateway.go` - policy routing, fwmarks, CONNMARK, NAT, Docker forwarding, MSS clamp.
- `internal/wireguard/gateway_heal.go` - idempotent repair of gateway routing state.
- `internal/iptables/server.go` - server DNAT/FORWARD/MASQUERADE/MSS/SNAT rules.
- `internal/iptables/server_heal.go` - server-side iptables/sysctl healing.
- `internal/iptables/vpn.go` - VPN endpoint and per-peer ACL rules.
- `internal/lanscan/*` - LAN client discovery from ARP/IP neighbor data.

System helpers:

- `internal/handlers/systemd_unit.go` - service/unit helper for route restore.
- `internal/network/*` - host interface, route, and address inspection.
- `internal/agentmeta/*` - version and host metadata helpers.
- `internal/wscompat/*` - compatibility glue for WebSocket payload behavior.

## Frontend: `wirewarp-web`

Entrypoints:

- `src/main.tsx` - React mount.
- `src/App.tsx` - router, auth fragment handling, protected routes, role guards.
- `src/components/Layout.tsx` - app shell, navigation, theme, command palette, help overlay, mobile nav.
- `vite.config.ts` - build target and dev proxies.
- `package.json` - React 19, Vite, TanStack Query, React Router, Zustand, uPlot, QR code library.

API and state:

- `src/lib/api.ts` - typed REST client and auth token handling.
- `src/lib/types.ts` - shared frontend domain types.
- `src/lib/realtime.ts` - active dashboard WebSocket and query invalidation map.
- `src/lib/websocket.ts` - legacy Zustand WebSocket store; likely not used by current app.

Pages:

- `src/pages/Dashboard.tsx` - operational summary.
- `src/pages/Agents.tsx` and `AgentDetail.tsx` - legacy agent inventory/detail.
- `src/pages/Nodes.tsx` and `NodeDetail.tsx` - unified node console with role-aware tabs, Security Edge capability panel, routes, policies, access feed, cache, import/diff, and advanced config views.
- `src/pages/TunnelServers.tsx`, `TunnelServerDetail.tsx` - server operations, status, peers, edge controls.
- `src/pages/TunnelClients.tsx`, `TunnelClientDetail.tsx` - gateway clients, attachments, LAN context.
- `src/pages/LanClients.tsx` - discovered LAN devices, pinning, egress, service exposure.
- `src/pages/PortForwards.tsx` - raw and HTTP service forwarding.
- `src/pages/VpnEndpoints.tsx` and `MyVpn.tsx` - admin VPN endpoints and user VPN config download.
- `src/pages/Users.tsx`, `Settings.tsx`, `Login.tsx` - admin and auth UI.
- `src/pages/Security*.tsx` - security overview, events, sites, protections, bans, certs. These remain compatible while Node Edge route/profile controls become the preferred surface.

Components:

- `src/components/ui/*` - local UI primitives.
- `src/components/CrowdSecCard.tsx` - CrowdSec install/status surface.
- `src/components/WgPeerTable.tsx` - peer status and traffic display.
- `src/components/VpnPermissionsSheet.tsx` - VPN permission editing.
- `src/components/UPlotChart.tsx` - chart wrapper.
- `src/components/CommandPalette.tsx`, `HelpOverlay.tsx`, `BottomNav.tsx`, `Toasts.tsx` - app chrome and feedback.

Styles:

- `src/styles.css` - global app styling and responsive layout.

## Generated Or Build Artifacts

- `wirewarp-agent/dist/wirewarp-agent` - checked-in static agent binary built by workflow.
- `wirewarp-server/static/*` - built frontend bundle served by FastAPI.
- `wirewarp-web/dist/` and `node_modules/` are ignored and were not part of the source inventory.

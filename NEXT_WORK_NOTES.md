# Next Work Notes

Generated on 2026-05-30 after exploring non-gitignored files, excluding `docs/`.
Updated on 2026-05-31 for the Node Edge / Cloudflare-parity implementation.

## Current Implementation State

The product is already more than a tunnel CRUD app. The current code includes:

- Multi-user auth with local, OIDC, and LDAP paths.
- Hashed one-time registration tokens.
- Agent registration and long-lived agent JWTs.
- Site-to-site tunnel servers, clients, attachments, rebasing, and port forwards.
- LAN client discovery, egress pinning, SNAT, and Cloudflare DNS sync.
- Road-warrior VPN endpoints, profiles, and permissions.
- CrowdSec install/status/whitelist sync.
- Traefik install/status/config sync for HTTP sites.
- Per-node edge capability mode/state: `tcp_udp_only` by default, optional
  reversible `security_edge` enable/disable, component desired state, and
  machine-readable `edge_feature_disabled` responses for unsupported edge APIs.
- Route/profile/path-rule/upstream-pool APIs, effective-policy inheritance,
  rendered config/version snapshots, Traefik import preview/apply/upsert, and
  full desired-state snapshots for automation.
- Live edge access feed: Traefik JSON access logs, agent batching, server
  `edge_access_events`, and dashboard `edge.access` invalidation/filtering.
- Local Nginx proxy-cache support behind Traefik, including desired-state
  rendering, agent reconcile/status, health-gated availability, cache test, and
  safe full-node or exact host/path purge helpers.
- Unified Nodes list/detail UI with mode/state/component health and node-scoped
  Security Edge tabs.
- Security pages and APIs for overview, events, sites, protections, bans, and certs.
- Dashboard realtime invalidation for most domain events.
- Server-side pytest coverage for most control-plane behavior.

The most relevant roadmap source in the non-ignored tree is `tasks.md`. Phase
12 and Phase 13 now split implemented Node Edge parity from remaining rollout
and hardening work:

- Phase 12: legacy Security pages and compatibility APIs remain available.
- Phase 13: Node Edge capability model, route/profile APIs, unified node UI,
  access feed, desired-state reconcile, and Nginx cache are implemented; live
  deployment verification and cache-index purge expansion remain.

## Drift To Resolve

These are current implementation risks or follow-up items found during exploration:

- Current migration head is `0038_edge_upstream_pools`.
- Agent self-update currently downloads a raw binary and installs it without hash verification.
- `wirewarp-agent/go.mod` declares `go 1.25.6`, while CI pins Go 1.22; reconcile this before touching Go build workflows.
- `wirewarp-web/src/lib/websocket.ts` appears legacy; active realtime behavior lives in `src/lib/realtime.ts`.
- Security overview endpoint returns placeholder zeros for several traffic/access metrics.
- Wider cache purge scopes (`host`, `prefix`, `route`) need a cache index before
  being exposed as safe destructive actions. Current safe scopes are full-node
  and exact host/path.
- Live node checks still need to prove the deployed main image on actual
  Security Edge nodes: enable/disable preserves state, external HTTPS route,
  WAF probe, rate-limit events, import reachability, `MISS -> HIT`, `BYPASS`,
  and post-purge `MISS`.
- Go agent system behavior has focused unit coverage for edge helpers but still
  needs real-host verification for package install, systemd, Traefik/CrowdSec,
  Nginx, iptables, and WireGuard interactions.
- Frontend has no tests in the current non-ignored tree.
- FastAPI lifespan calls `Base.metadata.create_all()` while container startup also runs Alembic. This is convenient for tests/dev but worth reviewing if strict migration-only production schema management is desired.

## Good Starting Points

For Node Edge work:

- Backend node API: `wirewarp-server/app/routers/nodes.py`.
- Node-scoped edge API: `wirewarp-server/app/routers/edge_node.py`.
- Global route/profile API: `wirewarp-server/app/routers/edge.py`.
- Edge services: `wirewarp-server/app/services/edge_ops.py`,
  `edge_resources.py`, `edge_runtime.py`, `edge_cache_ops.py`, and
  `traefik_importer.py`.
- Edge models: `wirewarp-server/app/models/edge_*.py` plus
  `edge_route_config.py`.
- Agent handlers: `wirewarp-agent/internal/handlers/edge_desired.go`,
  `edge_lifecycle.go`, `edge_cache.go`, and `server_edge_reconciler.go`.
- Frontend pages: `wirewarp-web/src/pages/Nodes.tsx` and `NodeDetail.tsx`.

For legacy security dashboard compatibility:

- Backend API: `wirewarp-server/app/routers/security.py`.
- Data models: `wirewarp-server/app/models/security_event.py`, `edge_route_config.py`, `crowdsec_snapshot.py`, and `traefik_snapshot.py`.
- Traefik desired config: `wirewarp-server/app/services/traefik_ops.py`.
- CrowdSec desired whitelist/status: `wirewarp-server/app/services/crowdsec_ops.py`.
- Agent Traefik implementation: `wirewarp-agent/internal/handlers/traefik.go`.
- Agent CrowdSec implementation: `wirewarp-agent/internal/handlers/crowdsec.go` and `crowdsec_install.go`.
- Frontend pages: `wirewarp-web/src/pages/Security*.tsx`.

For self-healing edge hardening:

- Existing agent healing loop: `wirewarp-agent/internal/handlers/client_heal.go`, `server_heal.go`, and `heal.go`.
- Existing restore path: `wirewarp-agent/internal/handlers/routing_restore.go`.
- Existing desired-state dispatch helpers: `edge_ops.py`, `traefik_ops.py`,
  `crowdsec_ops.py`, `tunnel_server_ops.py`, and `vpn_ops.py`.
- Realtime/status feedback: `app/websocket/handlers.py`, `app/realtime/events.py`, and `src/lib/realtime.ts`.

For consolidated node UI work:

- Current inventory: `wirewarp-web/src/pages/Nodes.tsx` and `NodeDetail.tsx`.
- Legacy inventory: `wirewarp-web/src/pages/Agents.tsx` and `AgentDetail.tsx`.
- Server views: `TunnelServers.tsx`, `TunnelServerDetail.tsx`.
- Client views: `TunnelClients.tsx`, `TunnelClientDetail.tsx`.
- Navigation and app shell: `src/components/Layout.tsx`.
- Backend summary endpoints: `app/routers/tunnel_servers.py` and `app/routers/tunnel_clients.py`.

For agent update hardening:

- Current updater: `wirewarp-agent/cmd/agent/main.go`.
- Command registration and current implementation: `wirewarp-agent/cmd/agent/main.go`.
- Server trigger: `wirewarp-server/app/routers/agents.py`.
- Release artifact workflow: `.github/workflows/docker-image.yml`.

## Suggested Implementation Rules

Backend:

- Write or update pytest coverage first for behavior changes.
- If a model changes, add an Alembic migration and update SQLite test compatibility if needed.
- Preserve command-result binding by authenticated agent id.
- Emit realtime events whenever visible state changes.

Agent:

- Keep command handlers idempotent where possible.
- Avoid changing saved YAML shape without migration logic in `internal/config/config.go`.
- For iptables/routing changes, add both apply and heal/restore paths.
- Test pure parsing/validation helpers directly; document manual verification for host-level behavior.

Frontend:

- Keep API types in `src/lib/types.ts` in sync with backend schemas.
- Add new API methods in `src/lib/api.ts`.
- Wire any new backend events into `src/lib/realtime.ts`.
- Check responsive states for dense operator pages.

## Verification Checklist

Before finishing backend work:

```bash
cd wirewarp-server
pytest
```

Before finishing agent work:

```bash
cd wirewarp-agent
go test ./...
go vet ./...
```

Before finishing frontend work:

```bash
cd wirewarp-web
npm run build
```

For full CI parity, run all three when a change crosses boundaries.

## What Was Intentionally Not Explored

The `docs/` directory was excluded by request and was not used as source material for these notes. Ignored directories such as `legacy`, `SafeLine-main`, `bunkerweb-master`, `node_modules`, and build outputs were also not explored.

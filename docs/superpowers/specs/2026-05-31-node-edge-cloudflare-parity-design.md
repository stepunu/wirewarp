# Node Edge Console - Cloudflare-like control plane with API parity

**Status**: Designed 2026-05-31. Supersedes and extends the Phase 12/13
security-edge designs by turning the per-server node edge into a full control
surface with policy inheritance, live request visibility, and first-class API
automation for Ansible.

**Goal**: let operators choose whether a WireWarp server node is a simple
WireGuard plus TCP/UDP forwarding host or a full security-edge host. When the
security edge is enabled, the node feels like a self-hosted Cloudflare zone:
routes, WAF, rate limiting, access, TLS, origin behavior, headers, transforms,
cache, import, live access feed, and rendered-config diffs are all managed from
one node-scoped console. Every UI action maps to documented, idempotent REST
APIs so the same state can be managed from Ansible or other automation.

## Design Reference

Cloudflare is the interaction benchmark, not the implementation target. The
features map to these Cloudflare product areas:

- Rules, transforms, redirects, origin routing, and configuration rules:
  <https://developers.cloudflare.com/rules/>
- WAF custom/managed rules and feature ordering:
  <https://developers.cloudflare.com/waf/feature-interoperability/>
- Rate limiting rules:
  <https://developers.cloudflare.com/waf/rate-limiting-rules/>
- Access policies:
  <https://developers.cloudflare.com/cloudflare-one/policies/access/>
- SSL/TLS and edge/origin certificates:
  <https://developers.cloudflare.com/ssl/get-started/>
- Health checks and origin monitoring:
  <https://developers.cloudflare.com/health-checks/>
- Cache rules:
  <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/>
- Nginx proxy cache directives:
  <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- NGINX content caching guide:
  <https://docs.nginx.com/nginx/admin-guide/content-cache/content-caching/>

WireWarp will not match Cloudflare's global Anycast network, global DDoS
capacity, ML bot score, or distributed CDN storage. It can match most
operator-facing edge policy and origin-control workflows on the operator's own
VPS nodes.

## Core Principles

1. **WireWarp remains source of truth**. Operators declare edge intent in the
   control plane; agents converge each server node to the rendered desired state.
2. **Friendly controls first, escape hatch second**. Common settings are modeled
   as forms and typed API resources. Raw Traefik fragments are allowed only in
   Advanced, with validation, preview, and rollback.
3. **Policy inheritance prevents repetition**. Configuration flows from global
   defaults to node defaults to route profiles to route/path overrides.
4. **Every UI action has an API equivalent**. The REST API is stable enough for
   Ansible. Endpoints are idempotent where practical, support read-after-write,
   and return rendered/effective policy for drift detection.
5. **Live visibility is part of the product**. The console has a Pi-hole-style
   access feed showing current HTTP edge traffic, not only blocked requests.
6. **Edge features are optional**. A tunnel server can run as pure WireGuard plus
   TCP/UDP forwarding. Traefik, CrowdSec, AppSec, Nginx cache, and live edge
   logging are installed only when the operator enables the security-edge
   capability for that node.

## Server Provisioning Modes

Adding a tunnel server exposes an explicit mode choice:

1. **TCP/UDP only**
   - Installs and heals WireGuard, iptables forwarding, sysctl, and route
     restore.
   - Supports raw TCP/UDP forwards and tunnel attachments.
   - Does not install Traefik, CrowdSec, AppSec, or Nginx cache.
   - Node detail shows Edge as unavailable with an install/enable action.

2. **Security Edge**
   - Installs the TCP/UDP baseline plus Traefik, CrowdSec, AppSec support, edge
     access logging, and optional Nginx cache capability.
   - Enables HTTP route management, WAF/rate/access/TLS/origin/header policy,
     live access feed, import/diff, and rendered config history.
   - Runs the same self-healing loop, but only for enabled edge components.

The add-server screen should default to the simpler `tcp_udp_only` mode unless
the operator opts into Security Edge. This prevents surprise package installs on
minimal VPS nodes and keeps the blast radius of the larger edge stack explicit.

Existing server nodes derive their mode from observed state:

- No Traefik/CrowdSec desired state: `tcp_udp_only`.
- Existing Traefik or CrowdSec snapshots, HTTP routes, or edge policies:
  `security_edge`.

Operators can enable Security Edge later from Node Settings. They can also
disable it later as a reversible stop-only action: WireWarp stops and disables
the managed systemd services, marks edge components disabled, and leaves
generated configs, secrets, certificates, route definitions, and package files on
disk. Re-enabling starts the same services and reconciles the saved desired
state. Deleting files or uninstalling packages is a separate destructive action
and can remain a later guarded workflow.

## Node Edge Console IA

The accepted layout is a node-scoped console:

- Left column: server node identity and Security Edge tabs.
- Center: current tab workspace.
- Right column: persistent live access feed when Security Edge is enabled.

For `tcp_udp_only` servers, the node page keeps the normal Forwards, Peers,
Activity, and Audit tabs. The Security Edge tab becomes a concise capability
panel showing what is not installed and offering "Enable Security Edge". It must
not show route/cache/WAF controls that cannot work yet.

Tabs for a server node:

1. **Overview**
   - Component health: WireGuard, Traefik, CrowdSec, AppSec, cert resolver.
   - Route count, active certs, block counts, top clients, top routes.
   - Policy stack summary: global defaults -> node defaults -> profiles.
   - Persistent right-side live access feed.

2. **Routes**
   - Host/path routing table.
   - Route enable/disable, route priority, entrypoints, profile assignment.
   - Upstream target or upstream pool.
   - Host rule and path rules shown separately.
   - Diff preview before apply when route changes affect generated config.

3. **Security**
   - WAF mode: off, observe, block.
   - CrowdSec remediation: allow, log, block, captcha.
   - IP allow/deny, country allow/deny, ASN allow/deny.
   - Bot and crawler controls where supported locally.
   - Emergency mode: temporarily challenge/block high-risk traffic for a node.

4. **Rate Limits**
   - Node, route, and path-level limits.
   - Requests, period, burst, mitigation duration.
   - Keying strategy: client IP, forwarded client IP, header, host, path, method.
   - Exemptions: CIDRs, countries, paths, auth users, service tokens.
   - Separate concurrency limit using Traefik `InFlightReq`.

5. **Access**
   - Basic auth.
   - ForwardAuth templates for Authentik, Authelia, generic HTTP auth.
   - Bypass paths and CIDRs.
   - Auth response headers.
   - Later: service/API tokens and mTLS client cert policies.

6. **TLS**
   - Let's Encrypt resolver status and wildcard certificates.
   - DNS-01 provider, resolvers, propagation delay, staging/production.
   - Per-route TLS source: managed, custom cert, no TLS.
   - Upstream TLS verification: insecure skip verify, SNI/serverName, root CA.
   - Certificate expiry and issuance errors.

7. **Origin**
   - Single upstream or upstream pool.
   - Health checks: path, interval, timeout, expected status range.
   - Retry count, response/read timeout, idle timeout.
   - Circuit breaker settings.
   - passHostHeader, upstream Host override, upstream scheme.

8. **Headers & Transforms**
   - Security headers: HSTS, no-sniff, frame options, referrer policy.
   - CSP editor with presets.
   - CORS policy.
   - Request/response header add/set/remove.
   - Redirects, stripPrefix, addPrefix, replacePath, replacePathRegex.
   - Query-string preservation/removal where Traefik supports it.

9. **Cache**
   - Local Nginx `proxy_cache` controls for static assets and selected paths.
   - Capability-gated mode: headers-only until the Nginx cache backend is
     installed, healthy, and verified.
   - Cache mode: off, headers-only, respect-origin, static-assets, custom.
   - Edge TTL, browser TTL, stale-if-error, revalidation, cache key mode.
   - Bypass/no-store rules for auth headers, cookies, API paths, query strings,
     response status codes, and `Set-Cookie`.
   - Purge by route, host, path, prefix, or full node cache where supported by
     the managed cache index.
   - This is local VPS cache, not a Cloudflare CDN.

10. **Import / Diff**
    - Traefik YAML/TOML import.
    - Separate files for `dynamic`, `middlewares`, and `serversTransports`.
    - Warning resolution: map, preserve as advanced fragment, or ignore.
    - Final rendered YAML diff before apply.
    - Idempotent import mode for Ansible.

11. **Advanced**
    - Generated static and dynamic Traefik config.
    - Validated raw fragments.
    - Render preview and syntax validation.
    - Rollback history with restore.
    - Agent desired-state payload viewer.

## Policy Inheritance

Configuration is evaluated in this order:

```text
global edge defaults
  -> node edge defaults
  -> route profile
  -> route override
  -> path rule override
```

Each level stores only the values it owns. Read APIs return both:

- `desired`: values directly stored on that resource.
- `effective`: inherited, fully resolved policy.

This lets UI and Ansible show exactly where a value came from and detect drift
without re-implementing inheritance.

### Profiles

Reusable route profiles are first-class resources:

- `public-app`
- `media-public`
- `internal-only`
- `admin-panel`
- `forwardauth-required`
- `api-strict`
- `static-cache`

Profiles contain edge defaults for WAF, access, rate limits, headers, cache,
TLS, and origin behavior. A route may override any profile field.

## Data Model

Existing tables stay:

- `tunnel_servers`
- `port_forwards`
- `edge_route_configs`
- `crowdsec_snapshots`
- `traefik_snapshots`
- `security_events`

New or expanded resources:

### `tunnel_servers` additions

Server nodes store the operator-selected capability mode.

Fields:

- `edge_mode`: tcp_udp_only, security_edge
- `edge_state`: disabled, enabled
- `edge_enabled_at` nullable
- `edge_enabled_by` nullable
- `edge_disabled_at` nullable
- `edge_disabled_by` nullable
- `edge_install_phase`: disabled, pending, installing, healthy, degraded, failed
- `edge_last_error` nullable

`edge_mode` records whether the node has the Security Edge capability. `edge_state`
records whether that capability is currently active. Snapshot rows remain
observed state. A node can be `security_edge` plus `disabled` when the operator
has paused the edge services without deleting configuration, or `security_edge`
plus `degraded` if one active component is unhealthy.

### `edge_component_states`

Observed and desired state for optional edge components.

Fields:

- `node_id`
- `component`: traefik, crowdsec, appsec, nginx_cache, access_log
- `desired`: disabled, enabled
- `installed`
- `phase`: disabled, pending, installing, healthy, degraded, failed
- `version`
- `last_error`
- `updated_at`

### `edge_profiles`

Reusable policy presets.

Fields:

- `id`
- `name`
- `slug`
- `description`
- `scope`: global, node
- `node_id` nullable
- `policy_json`
- `created_at`, `updated_at`

### `edge_node_policies`

Node defaults.

Fields:

- `node_id`
- `default_profile_id`
- `client_ip_strategy`
- `trusted_proxy_cidrs`
- `cloudflare_mode`: off, trust_headers, cloudflare_only
- `access_log_retention_hours`
- `security_event_retention_days`
- `policy_json`

### `edge_routes`

HTTP edge route identity. This can initially be backed by `port_forwards` and
`edge_route_configs`, but the API should expose a route-shaped resource.

Fields:

- `id`
- `node_id`
- `attachment_id`
- `domain`
- `enabled`
- `priority`
- `profile_id`
- `upstream_pool_id`
- `policy_json`
- `created_at`, `updated_at`

### `edge_path_rules`

Path-level overrides under a route.

Fields:

- `id`
- `route_id`
- `name`
- `match`: path prefix, exact path, regex
- `priority`
- `enabled`
- `policy_json`

### `edge_upstream_pools`

Named origin pools for one or more routes.

Fields:

- `id`
- `node_id`
- `name`
- `pass_host_header`
- `host_header`
- `servers_transport`
- `health_check_json`
- `retry_json`
- `timeout_json`

### `edge_upstream_servers`

Servers inside a pool.

Fields:

- `id`
- `pool_id`
- `url`
- `weight`
- `enabled`
- `health_state`
- `last_error`

### `edge_fragments`

Validated advanced Traefik snippets.

Fields:

- `id`
- `node_id`
- `route_id` nullable
- `name`
- `fragment_type`: middleware, service, router, tls, transport
- `content`
- `enabled`
- `validation_state`
- `last_error`

### `edge_config_versions`

Rendered config history and rollback.

Fields:

- `id`
- `node_id`
- `desired_hash`
- `rendered_static_hash`
- `rendered_dynamic_hash`
- `rendered_dynamic_yaml`
- `rendered_cache_hash`
- `rendered_cache_config`
- `created_by`
- `created_at`
- `applied_at`
- `agent_result`

### `edge_cache_snapshots`

Observed Nginx cache backend state for a server node.

Fields:

- `node_id`
- `backend`: nginx_proxy_cache
- `installed`
- `running`
- `phase`: pending, healthy, degraded, failed
- `version`
- `cache_path`
- `max_size_bytes`
- `current_size_bytes`
- `keys_zone_size`
- `last_config_hash`
- `last_test_status`: hit, miss, bypass, stale, failed
- `last_purge_result`
- `last_error`
- `updated_at`

### `edge_access_events`

Short-retention full access feed.

Fields:

- `id` bigint
- `node_id`
- `route_id` nullable
- `request_id`
- `occurred_at`
- `host`
- `path`
- `method`
- `status_code`
- `client_ip`
- `client_country`
- `client_asn`
- `user_agent`
- `referer`
- `action`: pass, block, captcha, rate_limit, auth_denied, upstream_error
- `source`: traefik, crowdsec, appsec
- `latency_ms`
- `cache_status`: hit, miss, bypass, stale, revalidated, not_configured
- `upstream_url`
- `upstream_status`
- `bytes_in`, `bytes_out`
- `matched_rule`
- `sampled`

Retention:

- Default full access retention: 72 hours.
- Configurable per node.
- Security events and audit/config events are retained long-term.

## Live Access Feed

The live feed behaves like Pi-hole's query stream:

- Always visible on server-node Security Edge pages when Security Edge is
  enabled.
- Shows new requests in near real time.
- Filters by host, path, status, action, IP, country, upstream, method.
- Clicking a row opens details: request headers, matched route, policy action,
  upstream timing, correlated security event, and generated route config.
- Operators can pause, resume, clear visible rows, or pin filters.

Implementation:

1. Agent tails Traefik access logs in JSON mode.
2. Cache-enabled routes add `X-WireWarp-Cache-Status` from Nginx, and Traefik
   access logs include that response header.
3. Agent batches events over WebSocket to the control server.
4. Server stores access events in `edge_access_events`.
5. Server emits realtime `edge.access` events to dashboards.
6. Dashboard keeps a bounded in-memory live list and refetches paginated history
   from REST for searches.

Privacy and safety:

- Request bodies are not logged by default.
- Query strings are captured by default but can be redacted per node or per route.
- Header capture is opt-in and allowlisted.
- Sensitive paths can be excluded or sampled.

## REST API For UI And Ansible

All endpoints use the existing auth/RBAC model. Admin/operator can mutate; viewer
can read. Write APIs are idempotent when addressed by stable resource IDs or slugs.

### Node Edge

```http
GET    /api/nodes/{agent_id}/edge
GET    /api/nodes/{agent_id}/edge/effective
PATCH  /api/nodes/{agent_id}/edge/policy
GET    /api/nodes/{agent_id}/edge/capabilities
PUT    /api/nodes/{agent_id}/edge/capabilities
POST   /api/nodes/{agent_id}/edge/install
POST   /api/nodes/{agent_id}/edge/enable
POST   /api/nodes/{agent_id}/edge/disable
POST   /api/nodes/{agent_id}/edge/reconcile
GET    /api/nodes/{agent_id}/edge/rendered
POST   /api/nodes/{agent_id}/edge/validate
GET    /api/nodes/{agent_id}/edge/versions
POST   /api/nodes/{agent_id}/edge/versions/{version_id}/rollback
```

Capability behavior:

- `GET /edge` works for every server node and returns `mode`, component phases,
  and unavailable reasons.
- `PUT /edge/capabilities` is idempotent and accepts desired components such as
  `traefik`, `crowdsec`, `appsec`, `access_log`, and `nginx_cache`.
- `POST /edge/install` starts or retries installation for enabled components.
- `POST /edge/disable` is reversible and stop-only. It runs service stop/disable
  operations but does not delete files, packages, ACME state, generated configs,
  route rows, or secrets.
- `POST /edge/enable` restarts the previously installed services and reconciles
  saved desired state.
- Route, policy, import, live-feed, and cache mutation endpoints return a
  machine-readable `edge_feature_disabled` error when called on a `tcp_udp_only`
  server or a disabled Security Edge.
- Raw TCP/UDP forwarding APIs remain available in both modes.

### Profiles

```http
GET    /api/edge/profiles
POST   /api/edge/profiles
GET    /api/edge/profiles/{profile_id_or_slug}
PUT    /api/edge/profiles/{profile_id_or_slug}
DELETE /api/edge/profiles/{profile_id_or_slug}
```

`PUT` is idempotent and intended for Ansible.

### Routes

```http
GET    /api/nodes/{agent_id}/edge/routes
POST   /api/nodes/{agent_id}/edge/routes
GET    /api/edge/routes/{route_id}
PUT    /api/edge/routes/{route_id}
PATCH  /api/edge/routes/{route_id}
DELETE /api/edge/routes/{route_id}
GET    /api/edge/routes/{route_id}/effective
POST   /api/edge/routes/{route_id}/validate
```

Route create also supports idempotent upsert by `domain` and `node_id`:

```http
PUT /api/nodes/{agent_id}/edge/routes/by-domain/{domain}
```

### Path Rules

```http
GET    /api/edge/routes/{route_id}/path-rules
POST   /api/edge/routes/{route_id}/path-rules
GET    /api/edge/path-rules/{rule_id}
PUT    /api/edge/path-rules/{rule_id}
PATCH  /api/edge/path-rules/{rule_id}
DELETE /api/edge/path-rules/{rule_id}
```

### Upstreams

```http
GET    /api/nodes/{agent_id}/edge/upstream-pools
POST   /api/nodes/{agent_id}/edge/upstream-pools
GET    /api/edge/upstream-pools/{pool_id}
PUT    /api/edge/upstream-pools/{pool_id}
PATCH  /api/edge/upstream-pools/{pool_id}
DELETE /api/edge/upstream-pools/{pool_id}
GET    /api/edge/upstream-pools/{pool_id}/health
```

### Live Feed And History

```http
GET /api/nodes/{agent_id}/edge/access-events
GET /api/edge/access-events
GET /api/edge/access-events/{event_id}
GET /api/edge/access-events/live-token
WS  /ws/dashboard emits edge.access
```

Query filters:

- `node_id`
- `route_id`
- `host`
- `status`
- `action`
- `client_ip`
- `country`
- `method`
- `path_prefix`
- `since`
- `until`
- `limit`
- `cursor`

### Cache

```http
GET    /api/nodes/{agent_id}/edge/cache
PATCH  /api/nodes/{agent_id}/edge/cache
POST   /api/nodes/{agent_id}/edge/cache/install
POST   /api/nodes/{agent_id}/edge/cache/reconcile
GET    /api/nodes/{agent_id}/edge/cache/stats
POST   /api/nodes/{agent_id}/edge/cache/purge
POST   /api/nodes/{agent_id}/edge/cache/test
POST   /api/edge/routes/{route_id}/cache/purge
POST   /api/edge/routes/{route_id}/cache/preview
```

Cache mutation is capability-gated:

- `headers_only` is always available because it renders response headers.
- `edge_cache` requires a healthy `nginx_proxy_cache` backend snapshot.
- `purge` requires the backend to report purge support for the selected scope.

Routes return `cache.available`, `cache.backend`, and `cache.reason` so UI and
Ansible can distinguish a disabled setting from an unavailable node capability.

### Import

```http
POST /api/nodes/{agent_id}/edge/import/traefik/preview
POST /api/nodes/{agent_id}/edge/import/traefik/apply
POST /api/nodes/{agent_id}/edge/import/traefik/upsert
```

The Ansible-friendly `upsert` accepts all import files and mapping decisions in
one payload, returns created/updated/skipped counts, warnings, and a rendered
diff.

### Advanced Fragments

```http
GET    /api/nodes/{agent_id}/edge/fragments
POST   /api/nodes/{agent_id}/edge/fragments
GET    /api/edge/fragments/{fragment_id}
PUT    /api/edge/fragments/{fragment_id}
PATCH  /api/edge/fragments/{fragment_id}
DELETE /api/edge/fragments/{fragment_id}
POST   /api/edge/fragments/{fragment_id}/validate
```

### Bulk Desired State

For Ansible, a complete node edge desired state endpoint reduces API chatter:

```http
GET /api/nodes/{agent_id}/edge/desired-state
PUT /api/nodes/{agent_id}/edge/desired-state
```

`PUT` replaces all managed edge resources for the node after validation. It
supports:

- `dry_run=true`
- `apply=false`
- `prune=true|false`
- `return_diff=true`

Response includes:

- validation errors
- created/updated/deleted resources
- final effective policy
- rendered config hash
- whether reconcile command was sent

## Ansible Contract

The API should be easy to wrap with `ansible.builtin.uri` before a dedicated
collection exists.

Design constraints:

- Stable slugs for profiles and named resources.
- Idempotent `PUT` for profiles, routes-by-domain, upstream pools, path rules,
  fragments, and full node desired state.
- `check_mode` support through `dry_run=true`.
- Diff support through `return_diff=true`.
- Secrets use write-only fields and read-back `*_set` booleans.
- Error responses include machine-readable `code`, `field`, and `detail`.
- API docs expose OpenAPI schemas with examples.

Example desired-state shape:

```yaml
node: vps-at-1
mode: security_edge
state: enabled
components:
  traefik: enabled
  crowdsec: enabled
  appsec: enabled
  access_log: enabled
  nginx_cache: disabled
policy:
  cloudflare_mode: cloudflare_only
  access_log_retention_hours: 72
profiles:
  - slug: media-public
    policy:
      waf_mode: block
      rate_limit:
        requests: 600
        period_seconds: 60
        burst: 120
routes:
  - domain: media.ww.step1.ro
    profile: media-public
    upstream:
      servers:
        - url: http://192.168.20.151:8096
    tls:
      mode: managed
    path_rules:
      - name: api-login
        match:
          type: prefix
          value: /Users/AuthenticateByName
        rate_limit:
          requests: 20
          period_seconds: 60
          mitigation_seconds: 300
```

## Rendering Rules

The server renderer owns all Traefik/CrowdSec/AppSec/Nginx cache config. Agents
should not invent config; they apply desired state and report observed state.
For `tcp_udp_only` nodes or disabled Security Edge, the renderer sends no active
edge desired-state command. Saved route/config state remains in the database for
later reactivation.

Renderer responsibilities:

- Refuse edge route rendering when the node's `edge_mode` is `tcp_udp_only`.
- Skip active edge dispatch when `edge_state` is `disabled`.
- Compute inheritance.
- Render Traefik routers, services, middlewares, TLS, transports.
- Render CrowdSec bouncer/AppSec middleware.
- Render rate limits, in-flight limits, redirects, headers, auth, and
  transforms.
- Render Nginx `proxy_cache` config when a route uses real edge cache.
- Validate generated config before dispatch.
- Store rendered config version and hash.

Generated config should be deterministic so diffs are stable for UI and Ansible.

## Cache Backend

WireWarp cache uses a managed local Nginx `proxy_cache` backend on each server
node. Traefik remains the public edge for TLS, routing, WAF, CrowdSec, auth, and
rate limits. Cache-enabled routes point from Traefik to a loopback Nginx listener;
Nginx then proxies to the origin over the normal WireWarp path.

```text
client or Cloudflare
  -> Traefik security edge
  -> local Nginx cache backend on 127.0.0.1
  -> origin over WireGuard
```

This keeps security decisions in one place and makes cache behavior concrete and
testable. A cached response is never served before Traefik has applied the route
middleware chain.

Supported cache policy:

- `off`: no cache headers and no Nginx cache path.
- `headers_only`: set browser/cache-control headers without storing responses.
- `respect_origin`: use Nginx cache but honor origin `Cache-Control`, `Expires`,
  `Set-Cookie`, and authorization safety rules.
- `static_assets`: cache safe static extensions and bypass API/auth/session
  paths.
- `custom`: explicit TTL, status-code TTLs, cache key, bypass, no-cache, stale,
  and revalidation settings.

Required safety defaults:

- Cache only `GET` and `HEAD` unless explicitly overridden.
- Bypass and do not store when `Authorization` is present.
- Bypass and do not store session/auth cookies by default.
- Do not store responses with `Set-Cookie`.
- Do not store `Cache-Control: private` or `no-store`.
- Do not cache API/login/admin paths in generated presets.
- Add a cache-status response header only when enabled by policy.

Purge behavior:

- Nginx open source supports cache storage and cache-control directives, but
  `proxy_cache_purge` is commercial. WireWarp must not depend on that directive
  for the open-source path.
- For open-source Nginx, WireWarp stores deterministic cache keys and performs
  purge through a controlled local agent helper that deletes matching cache
  entries by route, host, path, prefix, or full node cache.
- Purge APIs return `unsupported` if the node cannot safely identify matching
  cache files.

Health verification:

- After applying cache config, the agent performs a synthetic request sequence
  against a test route or configured route sample.
- The node is marked cache-healthy only when it can observe real `MISS` followed
  by `HIT`, or a policy-valid `BYPASS`.
- The live feed reports the real Nginx cache status as `hit`, `miss`, `bypass`,
  `stale`, `revalidated`, or `not_configured`.

## Import Behavior

The importer becomes a migration assistant:

1. Parse dynamic config, middleware files, transports, and TOML/YAML.
2. Resolve chains.
3. Map known middlewares to modeled WireWarp fields.
4. Preserve unknown but safe middlewares as advanced fragments.
5. Flag unsafe or unsupported constructs with actionable warnings.
6. Preview final route table, effective policies, and generated config diff.
7. Apply idempotently.

Warnings are categorized:

- `mapped`: imported into modeled fields.
- `preserved`: retained as advanced fragment.
- `ignored`: explicitly dropped by the user.
- `blocked`: cannot safely import.

## Feature Coverage

### Security

- WAF off/observe/block.
- AppSec failure behavior.
- CrowdSec IP reputation and manual decisions.
- IP allow/deny.
- Country allow/deny.
- ASN allow/deny.
- CAPTCHA/challenge with provider settings.
- Emergency route/node mode.

### Rate limiting

- Requests per period.
- Burst.
- Mitigation duration.
- Key strategy.
- Path-specific rules.
- In-flight concurrency.
- Exemptions.

### Access

- BasicAuth.
- ForwardAuth templates.
- Bypass paths/CIDRs.
- Auth response headers.
- Future mTLS and service tokens.

### TLS

- Managed wildcard certs.
- Per-route TLS mode.
- Custom cert support later.
- DNS-01 propagation delay.
- Upstream SNI and verification.

### Origin

- Multiple upstream servers.
- Health checks.
- Retries.
- Timeouts.
- Circuit breakers.
- Host header controls.

### Rules and transforms

- Redirects.
- Path strip/add/replace.
- Header add/set/remove.
- CORS.
- HSTS/CSP/security headers.

### Cache

- Headers-only mode without installing a cache backend.
- Nginx `proxy_cache` backend mode for real edge cache.
- Capability gating so unavailable cache backends cannot be enabled by accident.
- Edge TTL and browser TTL.
- Status-code TTLs.
- Cache key controls.
- Bypass and no-store rules.
- Stale-if-error and revalidation.
- Route, host, path, prefix, and node purge where supported by the managed cache
  index.
- Live feed cache status from observed Nginx behavior.

### Observability

- Live access feed.
- Historical access search.
- Security event grouping.
- Config version history.
- Rendered config diff.

## UX Details

### Live Feed Side Panel

Default columns:

- time
- host
- method/path
- status
- action
- client IP
- latency

Row colors:

- green: pass
- yellow: auth denied, policy denied, upstream warning
- red: WAF block, rate-limit, IP deny
- gray: sampled/ignored

Operators can:

- pause feed
- filter feed
- open event details
- copy curl/replay metadata
- jump to route
- create a rule from an event

### Full Event Explorer

The full explorer is a tab or drill-down from the side panel. It supports:

- saved filters
- grouping by host/IP/status/action
- time range
- CSV/JSON export
- security-only toggle

## Phasing

### Phase 1 - Foundation And API Shape

- Add server `edge_mode`, component state, edge profile, node policy,
  access-event, and config-version models.
- Update add-server UI/API with `tcp_udp_only` versus `security_edge` mode.
- Add Node Settings capability panel for enabling Security Edge after server
  creation and reversibly disabling/reactivating it later.
- Add REST endpoints for profiles, node policy, rendered config, desired-state
  dry-run, access-event query, and edge capabilities.
- Preserve existing site APIs while adding route-shaped aliases.
- Acceptance: OpenAPI shows all new resources; Ansible can create or update a
  server's edge capability mode idempotently; TCP/UDP-only nodes do not install
  Traefik/CrowdSec/Nginx and still support raw forwarding.

### Phase 2 - Live Access Feed

- Configure Traefik JSON access logs only for nodes with Security Edge enabled.
- Agent tails and batches access events.
- Server stores short-retention events and emits `edge.access`.
- Frontend adds right-side live feed and full event explorer.
- Acceptance: external requests appear live with status/action/latency; `/.env`
  WAF block correlates with security event.

### Phase 3 - Policy Profiles And Inheritance

- Implement effective policy resolver.
- Add profile assignment and route/path overrides.
- Add UI for policy stack and effective values.
- Acceptance: changing a node default affects routes without overrides; UI/API
  show value origin.

### Phase 4 - Cloudflare-Aware Client Identity

- Add trusted proxy and Cloudflare-only modes.
- Render forwarded-header trust safely.
- Use resolved client identity for logs, IP rules, and rate limits.
- Acceptance: Cloudflare/mobile traffic records true client IP where possible
  and policies key on the intended identity.

### Phase 5 - Rich Rate, Security, Access

- Add path rules, richer rate limits, in-flight limits, ASN rules, auth
  templates, bypass rules.
- Acceptance: login path can have stricter rate limits than the rest of a site;
  forward auth and bypass paths render correctly.

### Phase 6 - Origin, TLS, Headers, Transforms

- Add upstream pools, health checks, retries, timeouts, host/SNI controls.
- Add headers, CORS, redirects, prefix/path transforms.
- Add TLS propagation delay and upstream TLS controls.
- Acceptance: imported routes with redirects/headers/path transforms can be
  represented without raw fragments in common cases.

### Phase 7 - Cache And Advanced Fragments

- Add headers-only cache controls first.
- Add managed Nginx `proxy_cache` install/reconcile/status.
- Add capability-gated route cache policy and cache-status feed fields.
- Add purge by route/host/path/prefix/full-node through the agent-managed cache
  helper.
- Add validated advanced fragments and rollback.
- Acceptance: cache-enabled route proves `MISS` then `HIT`; unsafe auth/API
  requests prove `BYPASS`; purge removes matching cached entries; safe
  unsupported middleware can be preserved; bad fragments fail validation before
  reaching an agent.

### Phase 8 - Import V2 And Bulk Desired State

- Upgrade importer to map/preserve/ignore/block warnings.
- Add full-node desired-state `PUT`.
- Add complete examples for Ansible.
- Acceptance: a homelab Traefik config can be imported idempotently and rerun
  from Ansible without duplicate routes.

## Testing Strategy

Backend:

- Server provisioning mode tests.
- Edge capability idempotency and disabled-feature error tests.
- Reversible disable/enable tests proving files and rows are preserved.
- Inheritance resolver tests.
- Renderer snapshot tests.
- API idempotency tests.
- Desired-state dry-run/diff tests.
- Import warning category tests.
- Access-event ingestion/query/retention tests.

Agent:

- Component capability install/skip tests.
- TCP/UDP-only server reconciler tests proving no edge package install is
  attempted.
- Security Edge disable tests proving services are stopped/disabled but config,
  ACME state, and route files are preserved.
- Access-log tail parser tests.
- Nginx cache-status parser tests.
- Nginx cache config render/apply tests.
- Cache purge helper tests using deterministic keys.
- Batch send/retry tests.
- Reconnect behavior.
- Rendered config apply and rollback tests.

Frontend:

- Build.
- Route/profile editor smoke coverage where available.
- Manual browser checks for responsive node console and live feed.

Integration/manual:

- Fresh TCP/UDP-only node converges healthy without Traefik, CrowdSec, AppSec,
  or Nginx installed.
- Enabling Security Edge later installs components and converges healthy without
  breaking existing raw forwards.
- Disabling Security Edge stops HTTP edge services, preserves config files, and
  re-enabling restores the same routes.
- Imported routes stay reachable.
- Cloudflare/mobile request shows correct TLS and access-feed identity.
- WAF probe produces both live feed row and security event.
- Cache test route shows `MISS` then `HIT`, auth/API route shows `BYPASS`, and
  purge causes the next request to return `MISS`.
- Ansible-style `PUT desired-state` dry-run then apply is idempotent.

## Out Of Scope

- True global CDN/Anycast behavior.
- Cloudflare ML bot score.
- Global L3/L4 DDoS absorption.
- Replacing the user's LAN Traefik.
- Logging request bodies by default.
- Building a full Ansible collection in the first implementation pass.

## Open Extension Points

These are intentionally not in the first pass but should remain possible:

- Dedicated Ansible collection modules.
- mTLS client certificate policies.
- Per-route custom cert upload.
- Geo/IP database provider configuration.
- Notification hooks for access/security thresholds.
- Multi-node active/active edge steering.

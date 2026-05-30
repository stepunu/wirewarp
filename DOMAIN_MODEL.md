# Domain Model

Generated on 2026-05-30 from non-gitignored files, excluding `docs/`.

## Core Concepts

Agent:
Linux daemon connected to the control plane over `/ws/agent`. An agent has mode `server` or `client`, stores a long-lived agent JWT after registration, sends heartbeats, receives commands, and reports command results.

Tunnel server:
A server-mode agent with a public-facing WireGuard interface, one allocated tunnel network, and one or more public IPs. It accepts peers for gateway attachments and exposes public port forwards.

Tunnel client:
A client-mode agent usually installed as a gateway inside a private LAN. It can attach to one or more tunnel servers using separate WireGuard interfaces.

Attachment:
The connection between one tunnel client and one tunnel server. It owns:

- A per-client WireGuard interface such as `wg0`, `wg1`, etc.
- A tunnel IP inside the server network.
- A route table and fwmark.
- Optional gateway LAN routing and SNAT behavior.
- Any port forwards that target services through that attachment.

LAN client:
A discovered or pinned device behind a gateway. LAN clients can be used as forward targets or pinned to a specific egress route through a tunnel server.

Port forward:
A public service exposure on a tunnel server IP. Raw TCP/UDP forwards are handled by iptables. HTTP edge forwards use Traefik route config plus an `EdgeRouteConfig` row.

VPN endpoint:
A road-warrior WireGuard endpoint hosted on a gateway tunnel client. It has its own network and interface, separate from site-to-site attachments.

VPN profile:
A user profile on a VPN endpoint. It has one tunnel IP, generated key material, optional full-tunnel mode, optional DNS, and permissions that become gateway firewall rules.

Security edge:
The Traefik/CrowdSec integration for HTTP sites, WAF/appsec behavior, decisions, certificates, and security events.

## Relationship Sketch

```text
User
  -> REST API / dashboard

Agent
  -> TunnelServer, if mode=server
  -> TunnelClient, if mode=client

TunnelServer
  -> TunnelServerIP*
  -> TunnelClientAttachment*
  -> PortForward*
  -> CrowdSecSnapshot
  -> TraefikSnapshot

TunnelClient
  -> TunnelClientAttachment*
  -> GatewayLanClient*
  -> VpnEndpoint, at most one when it is a gateway

TunnelClientAttachment
  -> PortForward*
  -> GatewayLanClient egress pins

VpnEndpoint
  -> VpnProfile*
  -> VpnPermission*

PortForward
  -> EdgeRouteConfig, when service_kind=http
```

## Registration And Authentication

Registration tokens are created by admins and stored as hashes. The plaintext token is returned once.

First connection:

1. Agent sends a `register` message with token, mode, hostname, version, and optional public IP data.
2. Server validates the token hash.
3. Server creates an `Agent`.
4. For `server` mode, it creates a `TunnelServer` and allocates a tunnel network.
5. For `client` mode, it creates a `TunnelClient`.
6. Server issues an agent JWT and marks the token consumed.

Reconnect:

1. Agent sends an `auth` message with its stored JWT.
2. Server validates `typ=agent`, marks it connected, and replays desired state commands:
   - Server agents get active port forwards and peers.
   - Client agents get attachment commands and VPN-related state.

User auth uses local credentials, OIDC, or LDAP depending on settings. Roles include admin/operator/viewer-style operations plus `vpn_user` for self-service VPN access.

## WireGuard Site-To-Site Flow

Server initialization:

1. A server-mode agent registers.
2. The control plane waits for a usable primary public IP from heartbeat if needed.
3. Server dispatches `wg_init`.
4. Agent creates or syncs the server WireGuard interface, enables forwarding/NAT/MSS clamp, saves config, and returns the public key.
5. Server stores the public key and can add peers.

Client attachment:

1. Operator creates an attachment between a tunnel client and tunnel server.
2. Server allocates the lowest free client-side WireGuard ordinal for that client.
3. Server allocates a tunnel IP in the server network.
4. Server dispatches `wg_attach` to the client agent with endpoint, keys, tunnel IP, route table, fwmark, and LAN settings.
5. Client configures the WireGuard interface with `Table = off`, policy routing, CONNMARK restore/set rules, LAN NAT, Docker forwarding, and MSS clamp.
6. Client returns its public key.
7. Server dispatches `wg_add_peer` to the server agent.
8. Server agent adds the client peer and any LAN routes needed for allowed IPs beyond the tunnel IP.

Detach:

1. Server removes or migrates dependent port forwards and LAN egress pins.
2. Server dispatches `wg_remove_peer` to the server and `wg_detach` to the client.
3. Client tears down routing, iptables state, and saved attachment config.

## Network Allocation

Site-to-site server networks are allocated from `10.21.0.0/24` through `10.255.0.0/24`.

Within a server network:

- The server tunnel IP is `.1`.
- Attachment IPs start after `.1`.
- Attachment interface ordinal chooses the lowest unused ordinal for a given client agent.
- Attachment route tables are `100 + ordinal`.
- Attachment fwmarks are `0x101 + ordinal`.

VPN endpoint networks use the same global conflict-avoidance helpers, so VPN networks and tunnel server networks cannot overlap.

Rebase preserves host octets where possible and redispatches `wg_init`, `wg_attach`, and port forward commands.

## Port Forwards And HTTP Sites

Raw forwards:

- `service_kind` is raw/default.
- Agent command is `iptables_add_forward` or `iptables_remove_forward`.
- Server agent applies DNAT, FORWARD accept, and MASQUERADE rules.
- Rules can be scoped to a specific public IP.

HTTP sites:

- `service_kind=http`.
- A `PortForward` stores the public port and target.
- `EdgeRouteConfig` stores domains, TLS/ACME settings, middleware, auth, WAF, rate limits, IP allowlists, and other edge policy.
- Server builds Traefik dynamic config and dispatches `traefik_sync_config`.
- Traefik status and security events flow back through WebSocket messages.

## LAN Egress Pinning

Gateway heartbeats report LAN clients discovered from local neighbor/ARP sources. Operators can pin a LAN client to use a specific tunnel attachment for egress.

Pinning dispatches client-side routing commands:

- `set_lan_egress` installs or clears source-based routing for the LAN IP.
- `set_lan_snat` can add server-side SNAT for stable return paths.
- DNS sync may update Cloudflare records when configured.
- Existing port forwards can be migrated to the pinned attachment.

## Road-Warrior VPN Flow

Endpoint:

1. Admin creates a VPN endpoint on a gateway tunnel client.
2. Server allocates a network and dispatches `vpn_endpoint_up`.
3. Gateway agent configures the WireGuard endpoint interface and returns public key/status.

Profile:

1. Admin or enabled user creates a VPN profile.
2. Server generates private key, public key, and preshared key.
3. Only the public key and encrypted/derived operational state persist; the private key is returned once in the rendered config.
4. Server dispatches `vpn_peer_add` or `vpn_peer_update_rules`.
5. Gateway agent applies peer ACLs through iptables based on permissions and full-tunnel mode.

Permissions determine allowed destinations unless full-tunnel mode is enabled.

## Commands

The control plane logs commands in `command_log` before sending them. Results are accepted only from the agent that owns the command.

Important command types:

- WireGuard mesh: `wg_init`, `wg_attach`, `wg_detach`, `wg_add_peer`, `wg_remove_peer`, `wg_update_endpoint`.
- Port forwards: `iptables_add_forward`, `iptables_remove_forward`.
- LAN routing: `set_lan_egress`, `set_lan_snat`, `gateway_up`, `gateway_down`.
- Agent lifecycle: `agent_update`.
- VPN: `vpn_endpoint_up`, `vpn_endpoint_down`, `vpn_peer_add`, `vpn_peer_remove`, `vpn_peer_update_rules`.
- Security edge: `crowdsec_install`, `crowdsec_sync_whitelist`, `traefik_install`, `traefik_sync_config`, `crowdsec_appsec_enable`.

## Realtime Events

Dashboard clients connect to `/ws/dashboard?token=...`.

The server emits typed events through `app/realtime/events.py`. The frontend maps those event types to TanStack Query invalidations in `wirewarp-web/src/lib/realtime.ts`.

Common event families:

- `agent.changed`
- `tunnel_server.changed`
- `tunnel_client.changed`
- `port_forward.changed`
- `lan_client.changed`
- `audit.changed`
- `heal_event.changed`
- `wg_peer.changed`
- `crowdsec.changed`
- `traefik.changed`
- `security.changed`

The realtime bus is bounded. If a dashboard subscriber falls behind, it gets a `desync` event and the frontend invalidates all main query groups.

## Telemetry And Healing

Heartbeats update:

- Agent version, public IP, public interface, and connectivity.
- Server IP inventory.
- LAN client discovery for gateway agents.
- VPN profile handshake state.
- WireGuard peer snapshots from `wg show dump`.

Agents also emit:

- Heal events for repaired routing/iptables/sysctl state.
- CrowdSec status snapshots.
- Traefik status snapshots.
- Security events from decisions and edge signals.

The server stores peer snapshots and periodically samples traffic counters for charts.

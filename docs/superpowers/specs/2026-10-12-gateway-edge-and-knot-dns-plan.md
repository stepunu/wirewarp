# Gateway Security Edge and Knot DNS implementation plan

Date: 2026-10-12
Status: local implementation started under the active goal. Commit, push, deployment, and live configuration require separate authorization.

## Goal and scope

Allow WireWarp to manage Traefik and the complete HTTP security stack on local gateways as well as VPS nodes. Gateway hosting must support LAN-only services without a VPS attachment. Public services can reach a gateway edge through a VPS relay over WireGuard.

Add Knot DNS support for ACME DNS-01 through RFC2136 signed updates. Preserve Cloudflare support for existing installations.

This plan covers edge placement, HTTP route ownership, exposure controls, agent lifecycle, WAF, TLS, cache, access events, UI, migration, gateway site links, and verification. It does not include the unrelated monitoring, uninstall, updater, or general polish backlog.

## Confirmed requirements and evidence

- WireWarp must install, configure, reconcile, and monitor Traefik on gateways, as it currently does on VPS nodes.
- LAN-only routes must work locally without depending on a VPS or control-server connection.
- Both gateway and VPS edge hosting should remain available. The UI must explain their different traffic paths and protection locations.
- Knot DNS serves `step1.ro` with a primary/secondary topology.
- Proxmox already uses Knot RFC2136 updates with an HMAC-SHA256 TSIG key and a 30-second validation delay.
- Read-only queries on 2026-10-12 resolved `ns1.step1.ro` to `89.39.64.51` and `ns2.step1.ro` to `45.8.47.198`.
- The primary answered authoritative SOA queries over UDP and TCP port 53. Both servers reported serial `2026101203`.
- Public DNS query reachability is confirmed from the coding VM. Signed update permission and reachability from actual edge nodes remain unverified.

Current source constraints:

- `wirewarp-agent/cmd/agent/main.go` starts the edge reconciler only in server mode.
- `wirewarp-server/app/services/edge_ops.py` and node capabilities depend on `TunnelServer` edge state.
- `EdgeRouteConfig` is tied to an HTTP `PortForward`. A port forward requires a tunnel attachment.
- Traefik rendering, effective configuration, and compatibility routes select HTTP services through server attachments.
- ACME readiness, settings, credential delivery, and agent secret files currently assume Cloudflare.

## Proposed architecture

These decisions are recommendations for implementation. Validate the transport details in Phase 1 before committing to a relay mechanism.

### Edge placement

Make Security Edge a node capability independent of its WireGuard role. Support server nodes and gateway clients. Ordinary clients must not become edge hosts implicitly.

Default new gateway HTTP setups to gateway hosting. Preserve existing VPS hosting during upgrade. Enabling a gateway must not silently move routes or disable a VPS edge.

| Placement | Traffic path | Operator notice |
| --- | --- | --- |
| Gateway edge | LAN -> gateway -> origin; public -> VPS relay -> WireGuard -> gateway -> origin | Supports local routes. Public HTTP inspection and cache run on the gateway after traffic crosses the tunnel. |
| VPS edge | Public -> VPS edge -> WireGuard -> origin | Inspects public HTTP before tunnel transit. Does not provide an independent local LAN listener. |

One edge node owns each HTTP route and its TLS, WAF, cache, and event state. Both placements can coexist for different routes. Running one logical route on two edge nodes is outside the initial scope.

### Route ownership and exposure

Introduce a first-class HTTP route independent of raw TCP/UDP port forwards. Store its edge node, domains, upstream targets, enabled state, visibility, and existing policy relationships.

Use the existing policy inheritance order: global defaults -> node defaults -> profile -> route -> path rule. Preserve upstream pools, fragments, import provenance, and config versions.

Gateway routes support `lan_only`, `public_only`, and `both`. VPS routes support public ingress in the initial release. Reject unsupported placement and visibility combinations explicitly.

Public publishing is a separate relationship between a route or gateway listener and a VPS ingress. It requires a valid WireGuard attachment, but a LAN-only route does not.

Use separate LAN and public entry points on the gateway. Bind listeners to explicit addresses and ports. Public relays must target only the public entry point. Compile LAN-only routes only into LAN entry points.

DNS records do not enforce visibility. Public requests with a LAN-only Host header or TLS SNI must fail. Include IPv6, alternate listener addresses, and custom configuration fragments in that protection.

Public DNS points to the selected VPS ingress. Local DNS points LAN-visible hostnames to the gateway. WireWarp must explain this requirement and expose the needed records. Configuring the local resolver is outside this scope.

### Public relay and client identity

For gateway hosting, terminate public TLS on the gateway. The VPS uses Traefik TCP TLS passthrough over WireGuard with PROXY protocol v2. A relay-only VPS runs Traefik without CrowdSec, AppSec, cache, or ACME credentials. A VPS that also hosts Security Edge keeps its existing HTTP processing.

The isolated relay proof passed 14 checks with Traefik 3.6.25. Gateway certificate ownership, client address forwarding, spoofed header removal, LAN/public hostname isolation, and coexistence with VPS HTTP routes passed. The managed Traefik 3.3.4 source and documentation support this transport. Verify the managed version on the actual target before cutover.

The first relay release supports IPv4 and HTTPS TCP port 443. Each gateway uses one selected relay attachment for its public HTTP routes. Reject conflicting raw TCP forwards on ports 80 and 443 and duplicate public hostnames on that VPS. Public HTTP port 80 redirects to HTTPS on the VPS. HTTP-01 and HTTP/3 need separate transport support.

PROXY protocol trust does not deny other connections. Protect the gateway public listener with an owned INPUT chain. Admit only the selected WireGuard interface and VPS tunnel source, and deny other access to the listener ports. Remove untrusted Forwarded headers on every gateway HTTP listener.

If PROXY protocol is used, accept it only from designated relay peers on a protected listener. Do not trust client-supplied forwarding headers or PROXY data. If DNAT is used, prove the return path and source preservation through the existing gateway rules.

Public client identity must survive into WAF decisions, rate limits, bans, and access logs. LAN client identity must remain accurate too. A CrowdSec firewall ban on a gateway must not ban the relay peer and disconnect every public visitor. Define whether each decision is enforced by the HTTP bouncer or the firewall bouncer.

### Gateway runtime

Extract the existing edge lifecycle into one shared agent module used by server and gateway handlers. Preserve install, enable, reconcile, disable, and saved-state restore behavior.

Persist complete accepted desired state. Validate and render configuration before replacing the running configuration. Report desired and applied versions, component health, and bounded errors.

Disabling edge stops managed services and preserves routes, credentials, packages, cache policy, and ACME state. Gateway edge shutdown must not tear down unrelated VPN endpoints or attachment routing.

Detect existing listeners and unmanaged Traefik configuration before installation. Return an actionable conflict instead of overwriting it. Offline startup must restore the last accepted edge configuration.

### Knot DNS and ACME

Offer Knot / RFC2136 settings. Render Traefik's supported `exec` DNS provider with a fixed WireWarp hook that performs signed RFC2136 updates. The saved provider and UI remain Knot / RFC2136. Offer a settings form with:

- Update endpoint, defaulting for this installation to `ns1.step1.ro:53`.
- TSIG algorithm and key name.
- Masked, write-only TSIG secret.
- Propagation delay, initially 30 seconds.
- DNS resolver configuration and ACME staging selection.

Optionally accept the Proxmox `algorithm:key-name:secret` format as an input convenience. Parse it into the same validated fields without displaying the secret afterward.

Map credentials to `RFC2136_NAMESERVER`, `RFC2136_TSIG_ALGORITHM`, `RFC2136_TSIG_KEY`, and `RFC2136_TSIG_SECRET`. Verify the environment-file or secret-file mechanism supported by the deployed Traefik/Lego version before implementation. Keep node secret files root-readable only.

Store the TSIG secret encrypted using the current server secret mechanism. Keep credentials out of API readback, audit parameters, config previews, diffs, events, and logs. Deliver them only to authorized edge nodes that use that DNS configuration.

Update the writable primary. Confirm the challenge TXT value is visible on both authoritative servers before treating propagation as complete. Do not disable normal ACME propagation checks to hide failures.

Use a dedicated TSIG identity restricted by Knot ACLs to the required TXT owner names. Do not reuse an unrestricted zone-management key. Existing DNS server ACL changes require a separate authorized infrastructure action.

The currently managed Traefik 3.3.4 uses Lego 4.22.2. Its RFC2136 challenge creation replaces the TXT record set. Use the fixed WireWarp hook to add an exact TXT value and remove only that value. Verify concurrent distinct values against a real primary/secondary fixture. The explicit challenge-test action must also preserve existing TXT values.

The hook runs as an agent binary subcommand before normal startup. It works without an active control connection. Bound its queries, signed TCP updates, and retries. Require a valid signed response. Keep credential generation files immutable during rotation and include the hook and environment in rollback. Record failed exact-value cleanup for a bounded retry.

DNS challenge tests must follow authoritative challenge CNAMEs, as the certificate provider does. Bound the chain and reject cycles or invalid responses before updates. Report the effective TXT owner and remove only the test value there. For this installation, `_acme-challenge.step1.ro` points to `lan.step1.ro`.

Keep separate ACME accounts on each node. Do not copy ACME account storage between nodes. External ACME clients must also preserve sibling TXT values. The current acme.sh Knot plugin deletes the whole TXT set during cleanup. If Proxmox uses it, avoid overlapping challenge owners or fix that external plugin before claiming cross-client protection. Changing Proxmox or DNS infrastructure requires separate authorization.

Provide an explicit DNS challenge test on the selected edge node. Create a unique temporary TXT value within the allowed challenge scope, verify both servers, and remove only that value. Preserve concurrent challenges and pre-existing TXT values. Report update denial, timeout, propagation failure, and cleanup failure separately.

Bound the test to 100 seconds plus a separate 15-second cleanup deadline. Accept test propagation delays up to 90 seconds. Certificate issuance settings can retain delays up to 600 seconds. Reject longer test delays before dispatch. If no agent result arrives within 150 seconds, report failure with unconfirmed cleanup. Accept a late result when it arrives. Confirm cleanup on the primary and state that secondary deletion was not checked.

LAN-only services under `step1.ro` can use DNS-01 without public HTTP listeners. Public certificate issuance still requires publicly visible challenge records and exposes certificate names through certificate transparency.

Automatic A/AAAA record management through Knot is outside this release. Existing Cloudflare DNS sync must not run for Knot configurations. Show manual DNS instructions until a separate RFC2136 record-management feature is implemented.

## Implementation phases

### Phase 1: Inventory and prove the transport

Read the current orientation files and relevant edge designs. Inventory route ownership, node capability checks, migrations, command contracts, settings, import/export, and event invalidation paths.

Obtain a read-only inventory of the target gateway, selected VPS, listener conflicts, WireGuard paths, current HTTP routes, and certificate storage when infrastructure access is available. Do not read secret values.

Test relay alternatives in an isolated environment. Record the selected mechanism, actual client identity, return path, and listener isolation evidence.

Acceptance:

- LAN and public flows have explicit listener addresses and ports.
- The selected relay preserves client identity and rejects spoofed identity.
- A LAN-only hostname is inaccessible through the relay.
- The migration inventory identifies routes, policies, certificates, and dependencies to preserve.
- No production routing changes occur during discovery.

### Phase 2: Knot DNS-01 as a complete vertical slice

Update settings storage, schemas, validation, encryption, ACME readiness, desired-state credentials, agent secret handling, and the Settings UI together. Preserve existing Cloudflare credentials and behavior.

Implement the explicit challenge test with bounded execution and cleanup reporting. Add staging issuance and renewal verification.

Primary paths: `app/models/system_settings.py`, `app/schemas/system_settings.py`, `app/routers/settings.py`, `app/services/secrets.py`, `app/services/traefik_ops.py`, `app/services/edge_ops.py`, agent Traefik handlers, and frontend Settings/API types.

Acceptance:

- Cloudflare and RFC2136 each have complete settings and validation paths.
- Missing credentials produce a clear unavailable state.
- A permitted challenge reaches both authoritative servers and is cleaned up.
- A denied update reports failure without exposing credentials.
- DNS challenge tests identify DNS and TSIG rejection codes, timeout, and transport failures without returning credential contents or library error text.
- Staging issuance and renewal succeed from the actual edge host.

### Phase 3: Node capability and independent HTTP routes

Add migrations for node-owned edge state, first-class HTTP routes, and public ingress relationships. Backfill existing HTTP routes to their current VPS owner and public visibility.

Preserve route identifiers where feasible. If an identifier must change, use an explicit mapping and test every dependent relationship. Keep compatibility endpoints through adapters to the new route model.

Update capability APIs, policy rendering, command dispatch, event ownership, config snapshots, and frontend types together. Keep raw forwards on their existing model.

Acceptance:

- A LAN-only route can be created without a VPS attachment.
- Existing VPS routes render equivalent policy and upstream configuration after migration.
- Raw forwarding remains unchanged.
- Ownership, role permissions, duplicate hostname/listener checks, and invalid placement combinations are enforced.
- Legacy HTTP APIs and new route APIs agree on the same stored state.

### Phase 4: Managed gateway edge

Enable the shared edge runtime on gateway agents. Add gateway capability controls and route editing in the node UI. Wire Traefik, CrowdSec/AppSec, TLS, cache, access events, and health into the same gateway desired state.

Implement explicit LAN and public listeners, last-known-state restoration, safe reload, and reversible disable.

Preserve an active UFW firewall on existing nodes. Firewall persistence must work without installing packages that remove UFW. Restore only WireWarp-owned rules after startup or reload. Preserve unrelated firewall rules. Apply and teardown must report persistence failures.

When UFW is enabled with `MANAGE_BUILTINS=no`, persist WireWarp-owned rules in an atomic, root-only journal. Keep the existing persistence adapter on other nodes. Reject unsafe UFW modes and ownership collisions before changing rules. Restore the journal after UFW starts. Preserve UFW files, hooks, global policies, and foreign chains.

Tag managed rules and adopt legacy rules only when a runtime command identifies their exact tuple. Persist deletions before releasing teardown ownership. Defer scoped Docker pass-through allowances while `DOCKER-USER` is absent, then restore them when Docker creates it. Keep deferred rules in the journal and remove them on teardown. Never defer security guards or create a foreign chain.

Use separate local AppSec listeners for block and observe policies. Block uses port 7422. Observe uses port 7423, an allow remediation override, and AppSec-only bouncer mode. Observe must not inherit block remediation or IP bans from another route. Anti-bot decisions remain a separate policy.

Acceptance:

- A real LAN route reaches its origin through managed Traefik.
- WAF off, observe, and block modes produce the expected request and event behavior.
- LAN routes survive agent restart and controller outage.
- Invalid configuration preserves the last working configuration and reports failure.
- Enable/disable leaves existing gateway routing and VPN behavior intact.
- UFW remains active while WireWarp persists, restores, and removes its owned rules.
- Listener conflicts are reported before services are replaced.

### Phase 5: Public relay and exposure controls

Implement the Phase 1 relay choice and its persisted lifecycle. Add ingress selection, conflict checks, public publishing state, reconnect replay, and applied-state reporting.

Render only public-visible routes on the public listener. Protect it from arbitrary LAN access and untrusted relay identities.

Acceptance:

- Public HTTPS reaches a gateway route through the selected VPS.
- The gateway owns TLS and HTTP inspection for that route.
- A LAN-only route fails public probes using both Host and SNI.
- Public-only routes are absent from the LAN listener.
- A route marked both works through both intended paths.
- Rate limits and bans identify the visitor, not the relay.
- Relay restart and tunnel disruption recover without duplicate rules or stale publishing state.
- Multiple hostnames can share an ingress without conflicting with raw forwards or VPS-hosted edge listeners.

### Phase 6: UI parity and migration

Finish gateway parity for profiles, path rules, upstream pools, access feed, cache, import/diff, TLS, rendered configuration, and advanced fragments.

Show edge host, route visibility, public ingress, DNS requirements, protection location, and desired versus applied state. Show placement notices before enabling an edge or publishing a route.

Provide a migration preview from VPS hosting to gateway hosting. Preserve domains, upstreams, effective policy, profiles, secrets, and import metadata. Provision the gateway and verify it before switching public ingress.

Prefer issuing gateway certificates through ACME staging then production. Do not copy or delete ACME private state automatically. Account for issuance limits and retain the old working endpoint until cutover checks pass.

Persist each migration with a revision, original route and resource snapshot, source fingerprint, staged configuration hash, and command IDs. Stage an unpublished clone without changing the VPS route. Provision its gateway listener while keeping VPS relay publication inactive. Require an authenticated success for that exact configuration and a gateway probe of the real HTTPS listener before cutover. The probe must verify the hostname and certificate chain, test saved upstreams directly, and bypass cached responses. A connected agent or an old successful version is insufficient.

Stage requires the source fingerprint returned by the reviewed preview. Reject a changed source before writing staged resources. Restore the persisted ingress guard before WireGuard startup. Require the same guard before the managed Traefik service starts. Reject replacement of a published attachment identity until publication is removed.

Move the original route UUID at cutover. Preserve its policy and resource relationships. Freeze the source effective policy during migration so target node defaults cannot add restrictions or change behavior. Require both gateway and VPS acknowledgements before reporting completion. Keep original ownership and bindings for rollback. Cancel removes staged resources and waits for the gateway removal acknowledgement when provisioning occurred. Retain migration history until explicit discard.

Store source configuration with each rendered version. A version rollback restores routes, path rules, pools, fragments, listener settings, and profile policy before reconciliation. Restore a changed shared profile as a node-owned copy. Never change another node through rollback. Reject snapshots whose routes moved to another node and use migration rollback for those routes.

Gateway Traefik imports default to LAN-only visibility and need no attachment. Public imports require the gateway's initialized relay attachment. Replace imported entrypoints with managed listeners. Preview through the route editor's ownership and exposure checks without saving changes or sending commands. Report each create, update, skip, visibility, listener change, and warning. Block imports that would discard a Host restriction or unsupported middleware behavior.

Bulk imports apply routes and their referenced resources in one transaction before validating the complete configuration. Dry runs roll back all writes and send no commands. Report offline reconciliation as pending. Redact credentials from command logs and displayed diffs. Mask desired-state readback by default. Allow an administrator to request a sensitive export explicitly. Reject masked exports on import rather than overwrite credentials with mask text. Keep private historical snapshots for exact rollback.

The existing cache backend supports one origin per hostname. Reject a path-specific cache origin or an upstream pool with backend cache until path-aware cache support is implemented. Native Traefik pools and path rules remain available without backend cache. Surface this restriction before saving or migrating a route.

Acceptance:

- Desktop and mobile UI cover loading, empty, error, disabled, pending, and healthy states.
- Import and bulk desired state respect node ownership and exposure restrictions.
- Fragments cannot bypass listener isolation without explicit validation failure.
- Migration preview reports conflicts and every planned change.
- Failed cutover can restore the old VPS path without reconstructing route policy.
- Removing unused VPS edge services is a separate explicit action. Preserve their state for rollback.

### Phase 7: Rollout and live verification

Start with one LAN-only route, then one public gateway route, then one migrated VPS route. Expand only after the acceptance checks pass.

When commit, push, and deployment are authorized, follow the repository contract: rebase on `origin/main`, run relevant checks, push, wait for CI and generated commits, rebuild the control server, update changed agents, and verify actual nodes.

Use `.agents/skills/wirewarp-rebuild/SKILL.md` for the control server rebuild. Do not include unrelated workspace files in commits.

Acceptance:

- CI publishes the intended image and artifact versions.
- Target agents report the intended version and applied configuration.
- LAN and public HTTPS, WAF modes, rate limits, client identity, DNS-01, and renewal work on real nodes.
- Cache proves `MISS -> HIT`, authenticated/API `BYPASS`, and post-purge `MISS` on the correct edge host.
- LAN service continues during a VPS outage and controller outage.
- Restart and reboot recovery work for the gateway edge and public relay.
- Existing raw forwards, VPN endpoints, attachments, and retained VPS routes still work.
- Evidence includes commit/image versions, target nodes, checks, observed outcomes, and unresolved limits.

### Phase 8: Gateway site links through Alwyzon

Decision agreed on 2026-10-12: use the current Alwyzon VPS as the shared WireGuard hub. Direct gateway tunnels are outside the initial scope. Confirm its live attachments, configuration, and capacity before rollout.

The initial sites are Home (`192.168.20.0/24`) and Vienna (`192.168.0.0/24`). Both gateways connect to Alwyzon. The hub routes traffic between the selected attachments and enforces link permissions. Ordinary WireGuard hub routing decrypts and re-encrypts packets on Alwyzon, so the hub is trusted with site traffic.

Model a site link with named gateway endpoints, shared subnets, selected hub attachments, enabled state, access direction, and destination-side SNAT settings. Offer Home -> Vienna, Vienna -> Home, and bidirectional access. One-way access restricts new connections and permits established reply traffic.

Keep destination-specific site routes separate from per-host internet egress pins. Site routes must take precedence for selected remote subnets even when a host uses another attachment for internet egress. Validate overlapping subnet advertisements and conflicting peer `AllowedIPs` before applying changes. Do not permit transit between unrelated sites implicitly.

Support source-preserving routing when the destination LAN has a return route. Offer destination-side SNAT when it does not. SNAT hides the original source IP and solves replies only. It does not route new connections from destination LAN devices into the tunnel.

Vienna's Technicolor router cannot currently configure static routes. Home -> Vienna can use SNAT on the Vienna gateway without changing that router. Vienna -> Home requires selected hosts to use the Vienna gateway or have a persistent remote-subnet route. Do not show bidirectional connectivity as ready merely because the policy allows it.

Home hosts using `192.168.20.110` already send traffic to the WireWarp gateway. Hosts using `192.168.20.254` need a route for `192.168.0.0/24` through `.110` on their router or on the hosts. The hub does not remove this prerequisite.

Implement link storage, API validation and RBAC, persisted agent desired state, hub peer routes, forwarding rules, gateway routes, SNAT, applied-state acknowledgements, and UI as a complete vertical slice. Restore accepted state on restart and reconcile drift. Link removal must remove only its managed rules and preserve attachments, internet egress, VPN endpoints, and public forwarding.

The UI must show policy direction, SNAT tradeoffs, required LAN routes, tunnel health, and applied routing state separately. Link creation must not modify the Technicolor or other LAN routers automatically.

#### Site Links UI

Add a Site Links page under Networking and a Links tab on each gateway detail page. Reuse the existing dashboard components and responsive design.

The list shows the link name, named access direction, selected hub, enabled state, and routing readiness. For example: Home / Vienna, Home -> Vienna, Alwyzon, Enabled, Needs Home route. Keep tunnel connectivity separate from end-device reachability.

The creation form selects both gateways, each shared subnet, and a common hub with valid attachments. Offer Both directions, Home -> Vienna, and Vienna -> Home using the selected gateway names. Explain that directions control new connections and always allow valid replies.

Show return-traffic settings for each destination allowed by the direction. Offer Use gateway IP (SNAT) and Preserve source IP. Explain the source-IP loss for SNAT and the return-route requirement for source preservation. Bidirectional mode needs independent settings for both destinations.

Include an optional Restrict access section for destination hosts, protocols, and ports. Show restrictions per direction. Unrestricted access means the selected advertised subnets only, not other hub-connected networks.

The detail page shows the network path, current policy, and separate indicators for tunnel connections, desired/applied configuration, return-traffic handling, and LAN routing prerequisites. For Home, explain that hosts using `.110` can enter the link and hosts using `.254` need a remote-subnet route through `.110`.

Provide Create, Edit, Disable/Enable, and Test connectivity actions. Test results must identify the source node, destination, protocol, time, and outcome. A gateway-to-service probe cannot prove that an arbitrary LAN host has the required route. Report that distinction explicitly. Use Unverified for unknown end-device routing, not Ready.

After deleting all links, show retained guard ownership for each node. Provide an explicit Restore normal forwarding action. Explain that teardown ends Site Links isolation and leaves ordinary WireWarp forwarding in place. Require confirmation and the exact reviewed node revisions and hashes. Reject teardown while any link, including a disabled link, remains.

Persist teardown intent before dispatch. Remove only owned Site Links rules after each agent validates its empty applied state. Keep topology changes blocked until every retained node acknowledges the same teardown generation. Show disconnected, partial, and failed cleanup separately. Retry pending cleanup on reconnect. Preserve an agent receipt across restart so a lost acknowledgement cannot trap ownership permanently. Reject stale teardown against a newer desired state.

Keep a durable revision counter after releasing guard ownership. A later link must use a higher revision than the released generation. Reject database downgrades that would discard this counter. Save firewall cleanup before clearing agent ownership so reboot cannot restore released rules. If persistence fails, restore the deny guard and report the failure.

During teardown, freeze network changes for the retained gateways and hub. Allow unrelated nodes to keep operating. Reconnected retained nodes must receive cleanup before normal network replay. Keep their control connection open for acknowledgements. Resume normal replay only after every retained node confirms cleanup.

Validate unreachable selections and subnet or port conflicts before submission. Preserve unsaved form values after errors. Show pending application, per-node failures, stale status, and recovery without masking failures.

Verify desktop and mobile list, form, and detail layouts in a real browser. Exercise loading, empty, error, disconnected, pending, applied, disabled, and missing-route states. Verify keyboard access and labels for direction and SNAT choices.

Acceptance:

- Both gateways attach to Alwyzon and advertise only authorized site subnets.
- Home reaches a selected Vienna service through the hub without a per-device VPN profile.
- Each one-way mode blocks reverse initiation while allowing reply traffic.
- Bidirectional access works when both sites have the required host or LAN routes.
- Destination-side SNAT works with the unchanged Vienna router and reports the source-IP tradeoff.
- Site traffic follows its destination route while internet traffic retains existing egress selection.
- Hosts using `.254` receive an explicit routing prerequisite instead of a false ready state.
- Unrelated attachments and sites cannot access either LAN through implicit hub forwarding.
- Link disable, deletion, restart, and drift recovery preserve unrelated networking.
- Final link deletion retains the hub deny guard. Keep node role and topology changes blocked while retained guard ownership exists. Provide a separate explicit teardown before releasing that ownership.
- Live checks cover route decisions, real service requests, policy denial, observed source IPs, restart recovery, and existing egress behavior.

## Validation and migration rules

For each vertical slice, run all checks relevant to changed code:

```bash
cd wirewarp-server && pytest -q
cd wirewarp-agent && go test ./...
cd wirewarp-web && npm run build
```

Test migrations against a populated PostgreSQL fixture as well as the existing SQLite harness. Verify row counts, ownership, policy relationships, and equivalent rendered configurations.

Add meaningful integration coverage for listener isolation, relay identity, agent/controller restart, DNS update cleanup, and compatibility behavior. Inspect test counts and skipped cases.

Give remote diagnostics and challenge tests explicit timeouts. After interruption, verify process exit and cleanup status. Stop only exact process IDs when needed.

Do not claim live completion from a build or mocked test. If the actual target is unavailable, list the exact remaining checks.

## Remaining implementation decisions

- Confirm the writable primary endpoint and ACME key ACL without exposing the secret.
- Confirm the target gateway, available listener addresses, and existing unmanaged proxy services.
- Confirm how the local resolver receives LAN hostname records. This plan supplies instructions, not resolver automation.

These inputs do not block preparing the local implementation. They do block dependent live configuration and cutover.

## Sources

- [Current Node Edge design](2026-05-31-node-edge-cloudflare-parity-design.md).
- [Existing implementation runbook](2026-05-31-node-edge-cloudflare-parity-implementation.md). This plan supersedes its VPS-only assumptions for the changes described here.
- [Traefik ACME documentation](https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/).
- [Lego RFC2136 provider](https://go-acme.github.io/lego/dns/rfc2136/index.html).
- [Knot DNS configuration and dynamic update restrictions](https://www.knot-dns.cz/docs/latest/html/configuration.html#restricting-dynamic-updates).

## Completion condition

The work is complete when WireWarp manages either supported edge placement, LAN-only routes are isolated from public ingress, gateway public routes preserve client identity, Knot certificates issue and renew, and migrated services pass the live checks with a verified rollback path. Gateway site links through Alwyzon must also pass the direction, SNAT, route-readiness, recovery, and egress checks in Phase 8.

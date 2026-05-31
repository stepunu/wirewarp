# Node Edge Cloudflare-Parity Implementation Runbook

This runbook is the execution contract for implementing:

- `docs/superpowers/specs/2026-05-31-node-edge-cloudflare-parity-design.md`

It exists to make future sessions repeat the same disciplined loop: rebase,
implement, test, push, wait for CI/generated commits, rebuild, update agents, and
verify live behavior.

## Current Implementation Status

The Node Edge parity slices are implemented on the
`node-edge-cloudflare-parity` branch through:

- Capability model, mode/state migrations, component desired state, and
  install/enable/disable/reconcile APIs.
- Route/profile/path/upstream resources, effective policy, rendered config
  versions, fragments, Traefik import/diff, cache/access APIs, and full
  desired-state snapshots.
- Agent desired-state reconcile for Traefik, CrowdSec/AppSec, access logs, and
  Nginx cache.
- Live access event ingestion and dashboard invalidation.
- Nginx `proxy_cache` rendering/status/test plus safe full-node or exact
  host/path purge.
- Unified Nodes UI with TCP/UDP-only and Security Edge states.

The remaining work is operational: merge to `main`, wait for the main GitHub
Actions image workflow, rebuild `192.168.20.116`, update connected agents, and
capture live verification evidence. Broader cache purge scopes still need a
cache index before they can be made destructive.

## Definition Of Done

A slice is not done until all relevant items are true:

- The code is rebased on the latest `origin/main`.
- The slice has focused local tests or build checks.
- The slice is committed and pushed.
- GitHub Actions has finished for the pushed commit.
- If CI creates generated artifact/image commits, the local branch has rebased
  on those commits before further work.
- If deployed behavior changed, the control server on `192.168.20.116` has been
  rebuilt with `.claude/commands/rebuild.md`.
- If agent code changed, connected agents have been updated from the Nodes
  UI/API and checked after reconnect.
- Live node behavior has been verified for the affected surface.

Do not report a slice as complete from local tests alone when it affects the
deployed control server, agent, edge routing, TLS, DNS, firewall, CrowdSec,
Traefik, or Nginx cache behavior.

## Standard Loop

Use this loop for every implementation slice:

```bash
git fetch origin
git rebase origin/main
```

Implement the smallest vertical slice that can be tested and deployed. Prefer
schema/API/backend/agent/frontend changes that prove one user-facing capability
end to end instead of broad partial scaffolding.

Run checks based on touched areas:

```bash
cd wirewarp-server && pytest -q
cd wirewarp-agent && go test ./...
cd wirewarp-web && npm run build
```

Commit and push:

```bash
git status -sb
git add <intentional files>
git commit -m "<concise slice summary>"
git push origin main
```

After pushing:

1. Wait for GitHub Actions to finish.
2. Watch for generated commits such as rebuilt agent binaries or server images.
3. Rebase on the generated commit before continuing:

```bash
git fetch origin
git rebase origin/main
```

4. Rebuild the control server on `192.168.20.116` using
   `.claude/commands/rebuild.md`.
5. Update agents if agent code changed.
6. Verify live behavior and include evidence in the final response.

## Suggested Implementation Slices

1. **Capability model**
   - Add server `edge_mode` and `edge_state`.
   - Add component state read/write APIs.
   - Add disabled-feature errors for edge-only APIs on TCP/UDP-only or disabled
     Security Edge nodes.
   - Verify raw TCP/UDP forwards still work when edge is disabled.

2. **Node Settings toggles**
   - Add create-server mode selection.
   - Add per-node Security Edge enable/disable controls.
   - Disable is stop-only and must preserve files, route rows, secrets, and ACME
     state.

3. **Edge capability install/reconcile**
   - Dispatch desired components only when enabled.
   - Respect disabled components in the agent reconciler.
   - Re-enable restarts services and reconciles saved desired state.

4. **Route/profile/API parity**
   - Add route-shaped APIs, profiles, path rules, effective policy, dry-run, and
     rendered config endpoints.
   - Preserve existing site APIs as compatibility aliases.

5. **Live access feed**
   - Configure Traefik JSON logs only on enabled Security Edge nodes.
   - Agent batches events.
   - Server persists short-retention access events and emits realtime
     `edge.access`.

6. **Rich policy controls**
   - Rate limits, access/auth, WAF modes, IP/geo/ASN rules, headers, transforms,
     origin health, TLS controls.

7. **Nginx proxy cache**
   - Headers/cache policy, managed Nginx `proxy_cache`
     install/status/reconcile, and health-gated availability are implemented.
   - Full-node and exact host/path purge are implemented without NGINX Plus.
   - Remaining live gate: prove `MISS -> HIT`, `BYPASS`, and post-purge `MISS`
     on a deployed node.

8. **Traefik import and bulk desired state**
   - Add preview/apply/upsert import.
   - Add full-node desired-state `PUT` for Ansible with `dry_run` and
     `return_diff`.

## Live Verification Checklist

Use affected checks, not all checks every time:

- Control server UI loads after rebuild.
- Nodes list shows connected server and gateway agents.
- TCP/UDP-only server does not install or restart Traefik/CrowdSec/Nginx.
- Security Edge enable installs services and reports healthy components.
- Security Edge disable stops/disables services without deleting config files.
- Existing raw forwards continue after edge toggles.
- HTTP routes return expected status externally.
- TLS certificate is valid for route hosts.
- WAF probe such as `/.env` returns the expected block status.
- Rate limits produce expected throttling and dashboard/live-feed events.
- Imported routes are reachable and idempotent on re-import.
- Cache route proves `MISS -> HIT`; auth/API path proves `BYPASS`; purge
  causes a subsequent `MISS`.

## Final Response Requirements

Each implementation final response should include:

- Commits pushed.
- Local checks run and exact pass/fail status.
- GitHub Actions status and generated commit/image status.
- Control-server rebuild result when applicable.
- Agent update result when applicable.
- Live verification evidence for affected behavior.
- Any known gaps or deferred parts.

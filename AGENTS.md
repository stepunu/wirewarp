<claude-mem-context>
# Memory Context

# [wirewarp] recent context, 2026-05-31 1:41am GMT+2

No previous sessions found.
</claude-mem-context>

# Agent Context

Start with these generated orientation files before changing code:

1. `CODEBASE_GUIDE.md` - current high-level architecture, runtime topology, development commands, and known drift.
2. `MODULE_MAP.md` - where the backend, agent, frontend, migrations, tests, and build workflows live.
3. `DOMAIN_MODEL.md` - product vocabulary, data relationships, lifecycle flows, commands, and realtime events.
4. `NEXT_WORK_NOTES.md` - active roadmap areas, risks, and likely starting points.

These notes were created from files that are not gitignored, excluding `docs/` as requested.

# WireWarp Implementation Contract

For implementation work, especially the Node Edge / Cloudflare-parity plan:

1. Rebase onto `origin/main` before starting and before each push. CI often adds generated agent/image commits after pushes.
2. Work in small vertical slices with intentional commits. Do not bundle unrelated refactors.
3. Run the relevant local checks before each implementation claim:
   - Backend: `cd wirewarp-server && pytest -q`
   - Agent: `cd wirewarp-agent && go test ./...`
   - Frontend: `cd wirewarp-web && npm run build`
4. Push commits to git. Then wait for GitHub Actions and any generated artifact/image commits before deploying.
5. Rebuild the control server on `192.168.20.116` using `.claude/commands/rebuild.md` after CI publishes the new image.
6. If agent code changed, update connected agents from the Nodes UI/API after the control server rebuild.
7. For routing, edge, DNS, TLS, security, or cache changes, verify live behavior on the actual nodes before declaring completion.
8. Report commit hashes, local checks, CI status, rebuild result, agent update result, and live verification evidence in the final response.
9. Keep workspace artifacts such as `.superpowers/` out of commits unless the user explicitly asks to preserve them.

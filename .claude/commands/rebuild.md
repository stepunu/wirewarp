---
description: Pull latest wirewarp image on the control host, recreate the container, and prune old images
allowed-tools: Bash
---

Deploy the latest `ghcr.io/<gh-org>/wirewarp:latest` image to the control host. Assumes CI has already built and pushed the image to GHCR.

> Configure `CONTROL_HOST` (set as a shell variable or hardcode for your deployment) before invoking. Example: `CONTROL_HOST=root@wirewarp-host`.

Steps (run sequentially, single SSH session):

1. Pull, recreate, prune, and health-check in one shot:
   ```
   ssh "$CONTROL_HOST" 'set -e
     cd /opt/wirewarp
     echo "==> pulling latest image..."
     docker compose pull wirewarp
     echo "==> recreating container..."
     docker compose up -d wirewarp
     echo "==> pruning dangling images..."
     docker image prune -f
     echo "==> waiting for health..."
     for i in 1 2 3 4 5 6 7 8 9 10; do
       if curl -fs http://localhost:8100/api/health >/dev/null 2>&1; then
         echo "ok"
         break
       fi
       sleep 2
     done
     docker compose ps
     echo "---"
     echo "running image digest:"
     docker inspect --format "{{.Image}}" wirewarp
   '
   ```

2. If `/api/health` did not return ok within 20s, tail the container logs:
   ```
   ssh "$CONTROL_HOST" 'docker logs --tail 40 wirewarp'
   ```
   and report what's broken.

3. After success, summarize in one line: image digest pulled + that prune freed N (count from the prune output), or skip if nothing was pruned.

Notes:
- Do NOT prune volumes (`-v`) or networks (`-a`) — only dangling images.
- The `wirewarp-db` container should remain `Up` from before; only `wirewarp` is recreated.

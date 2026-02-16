#!/usr/bin/env bash
# Quick end-to-end test: register a user, get a token, generate an agent token, run the agent.
# Usage: bash scripts/test-connect.sh [server|client]
# Requires: curl, python3, the built binary at dist/wirewarp-agent

set -e
MODE=${1:-server}
API=http://localhost:8100

curl -sf -X POST $API/api/auth/register -H "Content-Type: application/json" -d '{"username":"admin","email":"admin@local","password":"admin123"}' > /dev/null 2>&1 || true

TOKEN=$(curl -sf -X POST $API/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

REG_TOKEN=$(curl -sf -X POST $API/api/agents/tokens -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"agent_type\":\"$MODE\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "Registration token: $REG_TOKEN"
echo "Running agent (Ctrl+C to stop)..."

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
$SCRIPT_DIR/../dist/wirewarp-agent --mode $MODE --url $API --token $REG_TOKEN --config /tmp/wirewarp-test-agent.yaml

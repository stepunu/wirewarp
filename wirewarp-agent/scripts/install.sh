#!/usr/bin/env bash
set -euo pipefail

# WireWarp Agent installer
# Usage: curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash -s -- --mode client --url http://x.x.x.x:8100 --token TOKEN

MODE=""
URL=""
TOKEN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)  MODE="$2";  shift 2 ;;
    --url)   URL="$2";   shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ -z "$MODE" || -z "$URL" || -z "$TOKEN" ]]; then
  echo "Usage: install.sh --mode <server|client> --url <control-server-url> --token <token>"
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
fi

BINARY_URL="https://github.com/stepunu/wirewarp/raw/main/wirewarp-agent/dist/wirewarp-agent"
SERVICE_URL="https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/wirewarp-agent.service"

echo "==> Installing dependencies..."
if command -v apt-get &>/dev/null; then
  apt-get update -qq
  apt-get install -y -qq curl wireguard-tools iptables iproute2 >/dev/null
elif command -v dnf &>/dev/null; then
  dnf install -y -q curl wireguard-tools iptables iproute >/dev/null
elif command -v yum &>/dev/null; then
  yum install -y -q curl wireguard-tools iptables iproute >/dev/null
elif command -v apk &>/dev/null; then
  apk add --quiet curl wireguard-tools iptables iproute2
else
  echo "Unsupported package manager — install curl, wireguard-tools, iptables, iproute2 manually"
  exit 1
fi

# netfilter-persistent for iptables save (Debian/Ubuntu only, optional)
if command -v apt-get &>/dev/null; then
  apt-get install -y -qq netfilter-persistent iptables-persistent >/dev/null 2>&1 || true
fi

echo "==> Downloading wirewarp-agent binary..."
curl -fsSL -o /usr/local/bin/wirewarp-agent "$BINARY_URL"
chmod +x /usr/local/bin/wirewarp-agent

echo "==> Installing systemd service..."
curl -fsSL -o /etc/systemd/system/wirewarp-agent.service "$SERVICE_URL"
systemctl daemon-reload

echo "==> Registering agent (mode=$MODE)..."
/usr/local/bin/wirewarp-agent --mode "$MODE" --url "$URL" --token "$TOKEN" &
AGENT_PID=$!

# Wait for the agent to register (creates the config with a JWT)
for i in $(seq 1 15); do
  if grep -q "agent_jwt" /etc/wirewarp/agent.yaml 2>/dev/null; then
    break
  fi
  sleep 1
done
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

if ! grep -q "agent_jwt" /etc/wirewarp/agent.yaml 2>/dev/null; then
  echo "WARNING: Agent may not have registered yet. Check connectivity to $URL"
fi

echo "==> Starting wirewarp-agent service..."
systemctl enable --now wirewarp-agent

echo "==> Done! Agent is running. Check status with: systemctl status wirewarp-agent"

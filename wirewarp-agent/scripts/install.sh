#!/usr/bin/env bash
set -euo pipefail

# WireWarp Agent installer
# Usage: curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash -s -- --mode client --url http://x.x.x.x:8100 --token TOKEN

export DEBIAN_FRONTEND=noninteractive

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
  echo "This script must be run as root (use sudo or run as root directly)"
  exit 1
fi

BINARY_URL="https://github.com/stepunu/wirewarp/raw/main/wirewarp-agent/dist/wirewarp-agent"
SERVICE_URL="https://raw.githubusercontent.com/stepunu/wirewarp/main/wirewarp-agent/scripts/wirewarp-agent.service"

# If a previous install is present, stop it cleanly so we can overwrite the
# binary without ETXTBSY ("text file busy") and so the new agent comes up with
# fresh state. The WireGuard private key at /etc/wireguard/wg0.key is preserved.
echo "==> Cleaning up any existing installation..."
if command -v systemctl &>/dev/null; then
  systemctl stop wirewarp-agent.service 2>/dev/null || true
  systemctl disable wirewarp-agent.service 2>/dev/null || true
fi
pkill -x wirewarp-agent 2>/dev/null || true
# brief grace so the kernel releases the binary
for _ in 1 2 3 4 5; do
  pgrep -x wirewarp-agent >/dev/null 2>&1 || break
  sleep 1
done
rm -f /usr/local/bin/wirewarp-agent
rm -f /etc/systemd/system/wirewarp-agent.service
if command -v systemctl &>/dev/null; then
  systemctl daemon-reload 2>/dev/null || true
fi

echo "==> Installing dependencies..."
# conntrack is needed to flush stale flow marks during fwmark/route-table
# reconfigs (e.g. multi-server gateway upgrades). Reply-path routing also
# depends on conntrack already being loaded by iptables MARK rules.
if command -v apt-get &>/dev/null; then
  apt-get update -qq
  apt-get install -y -qq curl wireguard-tools iptables iproute2 conntrack >/dev/null
  # netfilter-persistent for iptables save (optional, noninteractive)
  apt-get install -y -qq netfilter-persistent iptables-persistent >/dev/null 2>&1 || true
elif command -v dnf &>/dev/null; then
  dnf install -y -q curl wireguard-tools iptables iproute conntrack-tools >/dev/null
elif command -v yum &>/dev/null; then
  yum install -y -q curl wireguard-tools iptables iproute conntrack-tools >/dev/null
elif command -v apk &>/dev/null; then
  apk add --quiet curl wireguard-tools iptables iproute2 conntrack-tools
else
  echo "Unsupported package manager — install curl, wireguard-tools, iptables, iproute2, conntrack manually"
  exit 1
fi

echo "==> Downloading wirewarp-agent binary..."
curl -fsSL -o /usr/local/bin/wirewarp-agent "$BINARY_URL"
chmod +x /usr/local/bin/wirewarp-agent

echo "==> Installing systemd service..."
curl -fsSL -o /etc/systemd/system/wirewarp-agent.service "$SERVICE_URL"
systemctl daemon-reload

echo "==> Registering agent (mode=$MODE)..."
# Remove any existing config so --url and --token are picked up as a fresh install.
# The WireGuard private key at /etc/wireguard/wg0.key is preserved; the agent
# will regenerate /etc/wireguard/wg0.conf on its next wg_init / wg_configure.
rm -f /etc/wirewarp/agent.yaml
rm -f /etc/wireguard/wg0.conf
# Tear down a stale wg0 interface (if any) so wg-quick up doesn't conflict.
if ip link show wg0 &>/dev/null; then
  if command -v wg-quick &>/dev/null; then
    wg-quick down wg0 2>/dev/null || true
  fi
  ip link delete wg0 2>/dev/null || true
fi

/usr/local/bin/wirewarp-agent --mode "$MODE" --url "$URL" --token "$TOKEN" &
AGENT_PID=$!

# Wait for the agent to register (config will have a non-empty agent_jwt after success)
for i in $(seq 1 15); do
  if grep -qE 'agent_jwt: [^"]' /etc/wirewarp/agent.yaml 2>/dev/null; then
    break
  fi
  sleep 1
done
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

if ! grep -qE 'agent_jwt: [^"]' /etc/wirewarp/agent.yaml 2>/dev/null; then
  echo "WARNING: Agent may not have registered yet. Check connectivity to $URL"
fi

echo "==> Starting wirewarp-agent service..."
systemctl enable --now wirewarp-agent

echo "==> Done! Agent is running. Check status with: systemctl status wirewarp-agent"

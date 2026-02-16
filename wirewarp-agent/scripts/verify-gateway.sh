#!/bin/bash
# verify-gateway.sh — Check that all gateway routing rules from gateway-up.sh are applied.
# Run on the gateway LXC as root.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}OK${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}WARN${NC}  $1"; ((WARN++)); }

# Auto-detect from wg0.conf and agent config
WG_IFACE="wg0"
LAN_IFACE="eth0"

if [ ! -f /etc/wireguard/wg0.conf ]; then
  echo -e "${RED}ERROR: /etc/wireguard/wg0.conf not found. WireGuard not configured.${NC}"
  exit 1
fi

if [ ! -f /etc/wirewarp/agent.yaml ]; then
  echo -e "${RED}ERROR: /etc/wirewarp/agent.yaml not found. Agent not configured.${NC}"
  exit 1
fi

echo "========================================="
echo " WireWarp Gateway Verification"
echo "========================================="
echo ""

# --- 1. WireGuard Interface ---
echo "[ WireGuard Interface ]"
if ip link show "$WG_IFACE" &>/dev/null; then
  pass "$WG_IFACE interface exists"
else
  fail "$WG_IFACE interface does not exist"
fi

WG_OUTPUT=$(wg show "$WG_IFACE" 2>/dev/null)
if echo "$WG_OUTPUT" | grep -q "public key:"; then
  pass "$WG_IFACE has a public key"
else
  fail "$WG_IFACE has no public key"
fi

if echo "$WG_OUTPUT" | grep -q "endpoint:"; then
  ENDPOINT=$(echo "$WG_OUTPUT" | grep "endpoint:" | awk '{print $2}')
  pass "Peer endpoint: $ENDPOINT"
else
  fail "No peer endpoint configured"
fi

HANDSHAKE=$(echo "$WG_OUTPUT" | grep "latest handshake:")
if [ -n "$HANDSHAKE" ]; then
  pass "Handshake established: $(echo "$HANDSHAKE" | sed 's/.*latest handshake: //')"
else
  fail "No handshake — tunnel not working"
fi

TX=$(echo "$WG_OUTPUT" | grep "transfer:" | awk '{print $2, $3}')
RX=$(echo "$WG_OUTPUT" | grep "transfer:" | awk '{print $5, $6}')
if echo "$WG_OUTPUT" | grep -q "transfer:"; then
  if echo "$WG_OUTPUT" | grep "transfer:" | grep -q "0 B received"; then
    fail "Transfer: $TX sent, 0 B received — one-way traffic"
  else
    pass "Transfer: $TX sent, $RX received"
  fi
fi
echo ""

# --- 2. Kernel Settings ---
echo "[ Kernel Settings ]"
check_sysctl() {
  local key=$1
  local expected=$2
  local val=$(sysctl -n "$key" 2>/dev/null)
  if [ "$val" = "$expected" ]; then
    pass "$key = $val"
  else
    fail "$key = $val (expected $expected)"
  fi
}

check_sysctl net.ipv4.ip_forward 1
check_sysctl net.ipv4.conf.all.rp_filter 0
check_sysctl net.ipv4.conf.default.rp_filter 0
check_sysctl "net.ipv4.conf.$LAN_IFACE.rp_filter" 0
check_sysctl "net.ipv4.conf.$WG_IFACE.rp_filter" 0
echo ""

# --- 3. Routing Tables ---
echo "[ Routing Tables ]"
if grep -q "100 tunnel" /etc/iproute2/rt_tables 2>/dev/null; then
  pass "rt_tables has '100 tunnel' entry"
else
  fail "rt_tables missing '100 tunnel' entry"
fi

if ip route show table 51820 2>/dev/null | grep -q "default dev $WG_IFACE"; then
  pass "Table 51820: default dev $WG_IFACE"
else
  fail "Table 51820: missing default route via $WG_IFACE"
fi

if ip route show table tunnel 2>/dev/null | grep -q "default"; then
  TUNNEL_ROUTE=$(ip route show table tunnel 2>/dev/null | head -1)
  pass "Table tunnel: $TUNNEL_ROUTE"
else
  fail "Table tunnel: missing default route"
fi
echo ""

# --- 4. IP Rules ---
echo "[ IP Rules ]"
RULES=$(ip rule list)

check_rule() {
  local prio=$1
  local desc=$2
  local pattern=$3
  if echo "$RULES" | grep -q "^${prio}:"; then
    local line=$(echo "$RULES" | grep "^${prio}:")
    if echo "$line" | grep -qE "$pattern"; then
      pass "Priority $prio: $desc"
    else
      warn "Priority $prio exists but unexpected: $line"
    fi
  else
    fail "Priority $prio: $desc — missing"
  fi
}

# Control server exception (priority 99)
if echo "$RULES" | grep -q "^99:"; then
  CTRL_IP=$(echo "$RULES" | grep "^99:" | grep -oP 'to \K[^ ]+')
  pass "Priority 99: control server bypass ($CTRL_IP)"
else
  warn "Priority 99: no control server bypass (may be same IP as VPS)"
fi

check_rule 100 "VPS endpoint bypass" "lookup main"
check_rule 200 "LAN exception" "lookup main"
check_rule 5000 "Forward LAN through tunnel" "lookup 51820"
check_rule 5100 "Forward self through tunnel" "lookup 51820"
check_rule 30000 "Reply mark routing" "lookup tunnel"
echo ""

# --- 5. IPTables Mangle ---
echo "[ IPTables Mangle ]"
if iptables -t mangle -C PREROUTING -i "$WG_IFACE" -j MARK --set-mark 0x1 2>/dev/null; then
  pass "PREROUTING: mark incoming tunnel packets (0x1)"
else
  fail "PREROUTING: mark rule missing"
fi

if iptables -t mangle -C PREROUTING -i "$WG_IFACE" -j CONNMARK --save-mark 2>/dev/null; then
  pass "PREROUTING: CONNMARK save-mark"
else
  fail "PREROUTING: CONNMARK save-mark missing"
fi

if iptables -t mangle -C OUTPUT -j CONNMARK --restore-mark 2>/dev/null; then
  pass "OUTPUT: CONNMARK restore-mark"
else
  fail "OUTPUT: CONNMARK restore-mark missing"
fi

if iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o "$WG_IFACE" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
  pass "POSTROUTING: MSS clamping on $WG_IFACE"
else
  fail "POSTROUTING: MSS clamping missing"
fi
echo ""

# --- 6. NAT & Forwarding ---
echo "[ NAT & Forwarding ]"
FWD_POLICY=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+')
if [ "$FWD_POLICY" = "ACCEPT" ]; then
  pass "FORWARD policy: ACCEPT"
else
  fail "FORWARD policy: $FWD_POLICY (expected ACCEPT)"
fi

if iptables -t nat -C POSTROUTING -o "$WG_IFACE" -j MASQUERADE 2>/dev/null; then
  pass "MASQUERADE on $WG_IFACE"
else
  fail "MASQUERADE on $WG_IFACE missing"
fi

# Docker DOCKER-USER chain (optional)
if iptables -L DOCKER-USER -n &>/dev/null; then
  if iptables -C DOCKER-USER -i "$WG_IFACE" -o "$LAN_IFACE" -j ACCEPT 2>/dev/null; then
    pass "DOCKER-USER: $WG_IFACE -> $LAN_IFACE ACCEPT"
  else
    warn "DOCKER-USER: $WG_IFACE -> $LAN_IFACE rule missing (Docker present)"
  fi
  if iptables -C DOCKER-USER -i "$LAN_IFACE" -o "$WG_IFACE" -j ACCEPT 2>/dev/null; then
    pass "DOCKER-USER: $LAN_IFACE -> $WG_IFACE ACCEPT"
  else
    warn "DOCKER-USER: $LAN_IFACE -> $WG_IFACE rule missing (Docker present)"
  fi
else
  pass "No Docker — DOCKER-USER rules not needed"
fi
echo ""

# --- 7. Service Status ---
echo "[ Service ]"
if systemctl is-active wirewarp-agent &>/dev/null; then
  pass "wirewarp-agent service is running"
else
  fail "wirewarp-agent service is not running"
fi

if systemctl is-enabled wirewarp-agent &>/dev/null; then
  pass "wirewarp-agent service is enabled"
else
  warn "wirewarp-agent service is not enabled (won't start on boot)"
fi
echo ""

# --- Summary ---
echo "========================================="
echo -e " Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$WARN warnings${NC}"
echo "========================================="

[ "$FAIL" -eq 0 ] && exit 0 || exit 1

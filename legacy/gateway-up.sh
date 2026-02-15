#!/bin/bash
# gateway-up.sh
# Comprehensive setup script for Gateway LXC routing, firewall, and NAT.
# Consolidated & Parameterized Version

# --- CONFIGURATION ---
VPS_ENDPOINT_IP="205.147.200.16"
VPS_TUNNEL_IP="10.0.0.1"
GATEWAY_TUNNEL_IP="10.0.0.3"
GATEWAY_LAN_IP="192.168.20.110"
LAN_NETWORK="192.168.20.0/24"

TUNNEL_IF="wg0"
LAN_IF="eth0"

# Routing Tables
WG_TABLE_ID="51820"
REPLY_TABLE_ID="100"
REPLY_TABLE_NAME="tunnel"

# Priorities (Lower = Higher Precedence)
PRIO_VPS_EXCEPTION=100
PRIO_LAN_EXCEPTION=200
PRIO_FORWARD_LAN=5000
PRIO_FORWARD_SELF=5100
PRIO_REPLY_MARK=30000

# --- 1. Kernel Settings ---
echo "--- Configuring Kernel Settings ---"
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.${LAN_IF}.rp_filter=0
sysctl -w net.ipv4.conf.${TUNNEL_IF}.rp_filter=0

# --- 2. Cleanup ---
echo "--- Cleaning up existing rules ---"
# Flush Tables
ip route flush table ${WG_TABLE_ID} 2>/dev/null || true
ip route flush table ${REPLY_TABLE_NAME} 2>/dev/null || true

# Delete Rules by Priority
for prio in ${PRIO_VPS_EXCEPTION} ${PRIO_LAN_EXCEPTION} ${PRIO_FORWARD_LAN} ${PRIO_FORWARD_SELF} ${PRIO_REPLY_MARK} 99 1000 2000; do
    ip rule del priority ${prio} 2>/dev/null || true
done

# Cleanup Mangle Rules
iptables -t mangle -D PREROUTING -i ${TUNNEL_IF} -j MARK --set-mark 0x1 2>/dev/null || true
iptables -t mangle -D PREROUTING -i ${TUNNEL_IF} -j CONNMARK --save-mark 2>/dev/null || true
iptables -t mangle -D OUTPUT -j CONNMARK --restore-mark 2>/dev/null || true

# --- 3. Routing Tables Setup ---
echo "--- Setting up Routing Tables ---"
# Table for outbound tunnel traffic
ip route add default dev ${TUNNEL_IF} table ${WG_TABLE_ID} 2>/dev/null || true

# Table for inbound reply traffic
grep -q "${REPLY_TABLE_ID} ${REPLY_TABLE_NAME}" /etc/iproute2/rt_tables || echo "${REPLY_TABLE_ID} ${REPLY_TABLE_NAME}" >> /etc/iproute2/rt_tables
ip route add default via ${VPS_TUNNEL_IP} dev ${TUNNEL_IF} table ${REPLY_TABLE_NAME} 2>/dev/null || true

# --- 4. IP Rules (The Magic Order) ---
echo "--- Applying IP Rules ---"
# A. Exceptions (Bypass tunnel for local/VPS control traffic)
ip rule add to ${VPS_ENDPOINT_IP} table main priority ${PRIO_VPS_EXCEPTION}
ip rule add to ${LAN_NETWORK} table main priority ${PRIO_LAN_EXCEPTION}

# B. Forwarding (Send LAN traffic to Tunnel)
ip rule add from ${LAN_NETWORK} table ${WG_TABLE_ID} priority ${PRIO_FORWARD_LAN}

# C. Self (Send Gateway traffic to Tunnel)
ip rule add from ${GATEWAY_TUNNEL_IP} table ${WG_TABLE_ID} priority ${PRIO_FORWARD_SELF}
ip rule add from ${GATEWAY_LAN_IP} table ${WG_TABLE_ID} priority ${PRIO_FORWARD_SELF}

# D. Replies (Policy Routing for Port Forwarding)
ip rule add fwmark 0x1 table ${REPLY_TABLE_NAME} priority ${PRIO_REPLY_MARK}

# --- 5. IPTables (Firewall & NAT) ---
echo "--- Configuring IPTables ---"
# Mark incoming tunnel packets for reply routing
iptables -t mangle -A PREROUTING -i ${TUNNEL_IF} -j MARK --set-mark 0x1
iptables -t mangle -A PREROUTING -i ${TUNNEL_IF} -j CONNMARK --save-mark
iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark

# Allow Forwarding & Docker Bypass
iptables -P FORWARD ACCEPT
iptables -C DOCKER-USER -i ${TUNNEL_IF} -o ${LAN_IF} -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -i ${TUNNEL_IF} -o ${LAN_IF} -j ACCEPT
iptables -C DOCKER-USER -i ${LAN_IF} -o ${TUNNEL_IF} -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -i ${LAN_IF} -o ${TUNNEL_IF} -j ACCEPT

# NAT (Masquerade)
iptables -t nat -C POSTROUTING -o ${TUNNEL_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${TUNNEL_IF} -j MASQUERADE

# MSS Clamping (MTU Fix)
iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o ${TUNNEL_IF} -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o ${TUNNEL_IF} -j TCPMSS --clamp-mss-to-pmtu

echo "✅ Gateway configuration applied successfully."

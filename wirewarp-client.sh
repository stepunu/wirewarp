#!/bin/bash
# WireWarp Client Setup Script

set -euo pipefail

# This script configures a client (e.g., a Proxmox host) to connect to a WireWarp server.
# It is designed to be run after a new peer has been added on the server.

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [ "$#" -ne 7 ]; then
    echo "Usage: $0 <PEER_PRIVATE_KEY> <PEER_TUNNEL_IP> <SERVER_PUBLIC_KEY> <SERVER_ENDPOINT> <VM_GATEWAY_IP> <DNS_SERVER> <TUNNEL_BRIDGE_NAME>"
    echo "Example: $0 '...' 10.0.0.2 '...' 'vps.example.com:51820' 10.99.2.1 1.1.1.1 vmbr1"
    exit 1
fi

PEER_PRIVATE_KEY=$1
PEER_TUNNEL_IP=$2
SERVER_PUBLIC_KEY=$3
SERVER_ENDPOINT=$4
VM_GATEWAY_IP=$5
DNS_SERVER=$6
TUNNEL_BRIDGE=$7

VM_NETWORK=$(echo "${VM_GATEWAY_IP}" | awk -F. '{print $1"."$2"."$3".0/24"}')

echo "--- Installing Prerequisites ---"
apt-get update >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard iptables-persistent >/dev/null

echo "--- Configuring WireGuard Interface (wg0) ---"
cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = ${PEER_TUNNEL_IP}/24
PrivateKey = ${PEER_PRIVATE_KEY}
DNS = ${DNS_SERVER}
PostUp = iptables -t nat -A POSTROUTING -s ${VM_NETWORK} -o %i -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${VM_NETWORK} -o %i -j MASQUERADE
[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOL

echo "--- Configuring Network Bridge (${TUNNEL_BRIDGE}) ---"
if ! grep -q "# WireWarp Bridge for ${TUNNEL_BRIDGE}" /etc/network/interfaces; then
    cat >> /etc/network/interfaces << EOL

# WireWarp Bridge for ${TUNNEL_BRIDGE}
auto ${TUNNEL_BRIDGE}
iface ${TUNNEL_BRIDGE} inet static
    address ${VM_GATEWAY_IP}
    netmask 255.255.255.0
    bridge-ports none
    bridge-stp off
    bridge-fd 0
EOL
fi

echo "--- Enabling IP Forwarding ---"
sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "--- Starting Services ---"
systemctl enable wg-quick@wg0 >/dev/null
systemctl restart wg-quick@wg0
ifup ${TUNNEL_BRIDGE} >/dev/null 2>&1 || echo "Bridge '${TUNNEL_BRIDGE}' is already up or requires a reboot."
netfilter-persistent save >/dev/null

echo "✅ Client setup complete." 
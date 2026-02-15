#!/bin/bash
# WireWarp Client Uninstall Script

set -euo pipefail

# This script uninstalls the WireWarp client configuration.
# It reverses the changes made by wirewarp-client.sh.

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <TUNNEL_BRIDGE_NAME>"
    echo "Example: $0 vmbr1"
    exit 1
fi

TUNNEL_BRIDGE=$1

echo "--- Stopping WireGuard Service (wg0) ---"
if systemctl is-active --quiet wg-quick@wg0; then
    systemctl stop wg-quick@wg0
    echo "Service wg-quick@wg0 stopped."
else
    echo "Service wg-quick@wg0 is not running."
fi

if systemctl is-enabled --quiet wg-quick@wg0; then
    systemctl disable wg-quick@wg0
    echo "Service wg-quick@wg0 disabled."
fi

echo "--- Removing WireGuard Configuration ---"
if [ -f /etc/wireguard/wg0.conf ]; then
    rm /etc/wireguard/wg0.conf
    echo "Removed /etc/wireguard/wg0.conf"
else
    echo "/etc/wireguard/wg0.conf does not exist."
fi

echo "--- Removing Network Bridge Configuration (${TUNNEL_BRIDGE}) ---"
if grep -q "# WireWarp Bridge for ${TUNNEL_BRIDGE}" /etc/network/interfaces; then
    # Bring down the interface first
    if ip link show "${TUNNEL_BRIDGE}" >/dev/null 2>&1; then
        echo "Bringing down interface ${TUNNEL_BRIDGE}..."
        ifdown "${TUNNEL_BRIDGE}" || ip link set "${TUNNEL_BRIDGE}" down || true
    fi

    # Create a backup
    cp /etc/network/interfaces /etc/network/interfaces.bak.$(date +%s)
    echo "Backed up /etc/network/interfaces"

    # Remove the block
    # Matches from the comment line down to "bridge-fd 0" which is the last line of the block in the install script
    sed -i "/# WireWarp Bridge for ${TUNNEL_BRIDGE}/,/bridge-fd 0/d" /etc/network/interfaces
    
    # Remove any empty lines left behind (optional, but clean)
    # sed -i '/^$/N;/^\n$/D' /etc/network/interfaces 

    echo "Removed configuration for ${TUNNEL_BRIDGE} from /etc/network/interfaces"
else
    echo "Configuration for ${TUNNEL_BRIDGE} not found in /etc/network/interfaces"
fi

echo "--- Cleaning up Firewall Rules ---"
# WireGuard's PostDown should have removed the runtime rules when we stopped the service.
# We save the current state to make it persistent.
netfilter-persistent save >/dev/null
echo "Persistent firewall rules updated."

echo "--- Uninstallation Complete ---"
echo "Note: The following system-wide settings were NOT reverted to avoid breaking other services:"
echo "1. IP Forwarding (net.ipv4.ip_forward) remains enabled."
echo "2. Installed packages (wireguard, iptables-persistent, resolvconf) were not removed."
echo "   To remove them, run: apt-get remove wireguard iptables-persistent resolvconf"

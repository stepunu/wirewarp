#!/bin/bash

# WireWarp: A unified script to set up a WireGuard transparent tunnel.

set -e

# --- Helper Functions ---

# Check if the script is run as root
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo." >&2
    exit 1
  fi
}

# --- Main Logic Functions ---

# Function for Step 1: Initialize VPS
vps_init() {
  check_root
  echo "--- Running Step 1: VPS Initialization ---"
  
  read -p "Enter the public network interface of your VPS [eth0]: " VPS_PUBLIC_INTERFACE < /dev/tty
  VPS_PUBLIC_INTERFACE=${VPS_PUBLIC_INTERFACE:-eth0}
  WIREGUARD_PORT="51820"
  WIREGUARD_VPS_TUNNEL_IP="10.0.0.1"

  echo "Installing WireGuard..."
  apt-get update >/dev/null && apt-get install -y wireguard >/dev/null

  echo "Generating WireGuard keys..."
  wg genkey | tee /etc/wireguard/vps_private.key | wg pubkey > /etc/wireguard/vps_public.key
  VPS_PUBLIC_KEY=$(cat /etc/wireguard/vps_public.key)
  chmod 600 /etc/wireguard/vps_private.key

  echo "Enabling IP forwarding..."
  sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  sysctl -p >/dev/null

  echo "--- VPS Initialization Complete ---"
  echo "✅ Success!"
  echo
  echo "------------------------- Action Required -------------------------"
  echo "Copy the following values. You'll need them for Step 2 on your Proxmox host."
  echo
  echo "VPS Public Key: ${VPS_PUBLIC_KEY}"
  echo "VPS WireGuard Port: ${WIREGUARD_PORT}"
  echo "-------------------------------------------------------------------"
}

# Function for Step 2: Initialize Proxmox Host
proxmox_init() {
  check_root
  echo "--- Running Step 2: Proxmox Initialization ---"

  read -p "Enter the public IP or DDNS hostname of your VPS: " VPS_ENDPOINT < /dev/tty
  read -p "Paste the VPS Public Key you just generated: " WIREGUARD_VPS_PUBLIC_KEY < /dev/tty
  read -p "Enter the public IP of your VPS (this will be the VM's IP): " VM_PUBLIC_IP < /dev/tty
  read -p "Enter the WireGuard port from Step 1 [51820]: " WIREGUARD_PORT < /dev/tty
  WIREGUARD_PORT=${WIREGUARD_PORT:-51820}
  read -p "Enter DNS server for the tunnel interface [1.1.1.1]: " DNS_SERVER < /dev/tty
  DNS_SERVER=${DNS_SERVER:-1.1.1.1}

  WIREGUARD_PROXMOX_TUNNEL_IP="10.0.0.2"
  TUNNEL_BRIDGE="vmbr1"

  if [ -z "$VPS_ENDPOINT" ] || [ -z "$WIREGUARD_VPS_PUBLIC_KEY" ] || [ -z "$VM_PUBLIC_IP" ]; then
    echo "Error: Missing required information." >&2
    exit 1
  fi

  echo "Installing WireGuard and iptables-persistent..."
  apt-get update >/dev/null && apt-get install -y wireguard iptables-persistent >/dev/null

  echo "Generating WireGuard keys for Proxmox..."
  wg genkey | tee /etc/wireguard/proxmox_private.key | wg pubkey > /etc/wireguard/proxmox_public.key
  chmod 600 /etc/wireguard/proxmox_private.key

  echo "Configuring WireGuard interface (wg0)..."
  cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = ${WIREGUARD_PROXMOX_TUNNEL_IP}/24
PrivateKey = $(cat /etc/wireguard/proxmox_private.key)
DNS = ${DNS_SERVER}
PostUp = iptables -A FORWARD -i ${TUNNEL_BRIDGE} -o wg0 -j ACCEPT
PostUp = iptables -A FORWARD -i wg0 -o ${TUNNEL_BRIDGE} -m state --state RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s ${VM_PUBLIC_IP} -o wg0 -j MASQUERADE
PostDown = iptables -D FORWARD -i ${TUNNEL_BRIDGE} -o wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -o ${TUNNEL_BRIDGE} -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s ${VM_PUBLIC_IP} -o wg0 -j MASQUERADE
[Peer]
PublicKey = ${WIREGUARD_VPS_PUBLIC_KEY}
Endpoint = ${VPS_ENDPOINT}:${WIREGUARD_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOL

  echo "Configuring network bridge '${TUNNEL_BRIDGE}'..."
  # Add a unique identifier for safe removal
  if ! grep -q "# WireWarp Tunnel Bridge" /etc/network/interfaces; then
    cat >> /etc/network/interfaces << EOL

# WireWarp Tunnel Bridge - Start
auto ${TUNNEL_BRIDGE}
iface ${TUNNEL_BRIDGE} inet manual
    bridge_ports none
    bridge_stp off
    bridge_fd 0
# WireWarp Tunnel Bridge - End
EOL
  fi

  echo "Enabling and starting services..."
  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  ifup ${TUNNEL_BRIDGE} || echo "Bridge '${TUNNEL_BRIDGE}' is already up or requires a reboot."
  netfilter-persistent save >/dev/null

  PROXMOX_PUBLIC_KEY=$(cat /etc/wireguard/proxmox_public.key)
  echo "--- Proxmox Initialization Complete ---"
  echo "✅ Success!"
  echo
  echo "------------------------- Action Required -------------------------"
  echo "Copy the following value. You'll need it for Step 3 back on your VPS."
  echo
  echo "Proxmox Public Key: ${PROXMOX_PUBLIC_KEY}"
  echo "-------------------------------------------------------------------"
  echo "A reboot of Proxmox is recommended to ensure the new bridge is recognized by the UI."
}

# Function for Step 3: Complete VPS Setup
vps_complete() {
  check_root
  echo "--- Running Step 3: VPS Completion ---"

  read -p "Paste the Proxmox Public Key from Step 2: " WIREGUARD_PROXMOX_PUBLIC_KEY < /dev/tty
  read -p "Enter your Proxmox server's public IP or DDNS hostname: " PROXMOX_ENDPOINT < /dev/tty
  read -p "Enter the public IP of this VPS: " VPS_PUBLIC_IP < /dev/tty
  read -p "Enter the public network interface of this VPS [eth0]: " VPS_PUBLIC_INTERFACE < /dev/tty
  VPS_PUBLIC_INTERFACE=${VPS_PUBLIC_INTERFACE:-eth0}

  WIREGUARD_PORT="51820"
  WIREGUARD_VPS_TUNNEL_IP="10.0.0.1"
  WIREGUARD_PROXMOX_TUNNEL_IP="10.0.0.2"

  if [ -z "$WIREGUARD_PROXMOX_PUBLIC_KEY" ] || [ -z "$PROXMOX_ENDPOINT" ] || [ -z "$VPS_PUBLIC_IP" ]; then
    echo "Error: Missing required information." >&2
    exit 1
  fi

  echo "Installing prerequisite packages..."
  apt-get update >/dev/null && apt-get install -y iptables-persistent curl >/dev/null

  echo "Creating final WireGuard configuration..."
  cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = ${WIREGUARD_VPS_TUNNEL_IP}/24
ListenPort = ${WIREGUARD_PORT}
PrivateKey = $(cat /etc/wireguard/vps_private.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE
[Peer]
PublicKey = ${WIREGUARD_PROXMOX_PUBLIC_KEY}
Endpoint = ${PROXMOX_ENDPOINT}:${WIREGUARD_PORT}
AllowedIPs = ${WIREGUARD_PROXMOX_TUNNEL_IP}/32, ${VPS_PUBLIC_IP}/32
EOL
  # Persist the config values needed by the port manager
  echo "VPS_PUBLIC_INTERFACE=${VPS_PUBLIC_INTERFACE}" > /etc/wireguard/wirewarp.conf
  echo "WIREGUARD_PROXMOX_TUNNEL_IP=${WIREGUARD_PROXMOX_TUNNEL_IP}" >> /etc/wireguard/wirewarp.conf

  echo "Enabling and starting WireGuard service..."
  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  netfilter-persistent save >/dev/null

  echo "--- VPS Completion Finished ---"
  echo "✅ Success! Your WireGuard tunnel is now fully configured and active."
  echo "You can now use this script to manage forwarded ports."
  echo "To check tunnel status, run 'sudo wg show'"
}

# Function to manage ports on the VPS
manage_ports_vps() {
    check_root
    if [ ! -f /etc/wireguard/wirewarp.conf ]; then
        echo "Error: Could not find the WireWarp config file. Please run Step 3 on the VPS first." >&2
        exit 1
    fi
    source /etc/wireguard/wirewarp.conf

    read -p "Action <add|remove>: " ACTION < /dev/tty
    read -p "Protocol <tcp|udp|both>: " PROTO < /dev/tty
    read -p "Port number: " PORT < /dev/tty

    # Function to add or remove a single iptables rule
    manage_rule() {
        local l_action=$1
        local l_proto=$2
        local l_port=$3
        local grep_rule="-A PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} -m ${l_proto} --dport ${l_port} -j DNAT --to-destination ${WIREGUARD_PROXMOX_TUNNEL_IP}"
        local rule_exists=false
        if iptables-save | grep -- "$grep_rule" > /dev/null 2>&1; then
            rule_exists=true
        fi

        if [ "$l_action" == "add" ]; then
            if [ "$rule_exists" = true ]; then
                echo "Rule for ${l_proto}/${l_port} already exists."
            else
                iptables -t nat -A PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} --dport ${l_port} -j DNAT --to-destination ${WIREGUARD_PROXMOX_TUNNEL_IP}
                echo "Port ${l_proto}/${l_port} forwarded to ${WIREGUARD_PROXMOX_TUNNEL_IP}."
            fi
        elif [ "$l_action" == "remove" ]; then
            if [ "$rule_exists" = true ]; then
                iptables -t nat -D PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} --dport ${l_port} -j DNAT --to-destination ${WIREGUARD_PROXMOX_TUNNEL_IP}
                echo "Port forwarding for ${l_proto}/${l_port} removed."
            else
                echo "Rule for ${l_proto}/${l_port} does not exist."
            fi
        fi
    }

    case "$PROTO" in
        tcp|udp)
            manage_rule "$ACTION" "$PROTO" "$PORT"
            ;;
        both)
            echo "Managing rules for both TCP and UDP on port ${PORT}..."
            manage_rule "$ACTION" "tcp" "$PORT"
            manage_rule "$ACTION" "udp" "$PORT"
            ;;
        *)
            echo "Invalid protocol. Use 'tcp', 'udp', or 'both'." >&2
            exit 1
            ;;
    esac

    echo "Saving persistent firewall rules..."
    netfilter-persistent save >/dev/null
    echo "Done."
}

# Function to check WireGuard status
check_status() {
    check_root
    if ! command -v wg &> /dev/null; then
        echo "WireGuard tools are not installed. Please run one of the setup steps first." >&2
        exit 1
    fi
    echo "--- WireGuard Status ---"
    wg show
    echo "------------------------"
}

# Function to uninstall WireWarp
uninstall() {
    check_root
    read -p "Are you sure you want to completely uninstall WireWarp? This is irreversible. [y/N]: " CONFIRM < /dev/tty
    if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
        echo "Uninstall cancelled."
        exit 0
    fi

    echo "Stopping and disabling WireGuard service..."
    systemctl stop wg-quick@wg0 >/dev/null 2>&1 || true
    systemctl disable wg-quick@wg0 >/dev/null 2>&1 || true

    if [ -f /etc/wireguard/vps_private.key ]; then
        echo "Detected VPS installation. Cleaning up..."
        # Port forwarding rules will be removed when iptables-persistent is purged.
        rm -rf /etc/wireguard
        echo "Purging WireGuard and iptables-persistent packages..."
        apt-get purge -y wireguard iptables-persistent >/dev/null
        echo "VPS cleanup complete. A reboot is recommended."
    elif [ -f /etc/wireguard/proxmox_private.key ]; then
        echo "Detected Proxmox installation. Cleaning up..."
        ifdown vmbr1 >/dev/null 2>&1 || true
        # This is safer than a blind sed command. It removes the block between the unique comments.
        sed -i '/# WireWarp Tunnel Bridge - Start/,/# WireWarp Tunnel Bridge - End/d' /etc/network/interfaces
        rm -rf /etc/wireguard
        echo "Purging WireGuard and iptables-persistent packages..."
        apt-get purge -y wireguard iptables-persistent >/dev/null
        echo "Proxmox cleanup complete. A reboot is recommended."
    else
        echo "No WireWarp installation detected."
    fi
    echo "✅ Uninstall complete."
}

# --- Main Menu ---

echo "================================================="
echo " WireWarp - WireGuard Transparent Tunnel Script"
echo "================================================="
echo "What do you want to do?"
echo
echo "   --- SETUP ---"
echo "   1) [VPS]       Step 1: Initialize VPS"
echo "   2) [Proxmox]   Step 2: Initialize Proxmox Host"
echo "   3) [VPS]       Step 3: Complete VPS Setup"
echo
echo "   --- OPERATIONS ---"
echo "   4) [VPS]       Manage Forwarded Ports"
echo "   5) [All]       Check Tunnel Status"
echo
echo "   --- DANGER ---"
echo "   6) [All]       Uninstall WireWarp"
echo "   7) Exit"
echo

read -p "Enter your choice [1-7]: " choice < /dev/tty

case $choice in
  1) vps_init ;;
  2) proxmox_init ;;
  3) vps_complete ;;
  4) manage_ports_vps ;;
  5) check_status ;;
  6) uninstall ;;
  7) echo "Exiting."; exit 0 ;;
  *) echo "Invalid option. Please try again."; exit 1 ;;
esac 
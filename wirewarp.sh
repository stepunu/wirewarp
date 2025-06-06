#!/bin/bash

# A unified script to set up a WireGuard transparent tunnel.

set -e

# --- Helper Functions ---

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
  
  read -p "Enter the public network interface of your VPS [eth0]: " VPS_PUBLIC_INTERFACE
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

  read -p "Enter the public IP or DDNS hostname of your VPS: " VPS_ENDPOINT
  read -p "Paste the VPS Public Key you just generated: " WIREGUARD_VPS_PUBLIC_KEY
  read -p "Enter the public IP of your VPS (this will be the VM's IP): " VM_PUBLIC_IP
  read -p "Enter the WireGuard port from Step 1 [51820]: " WIREGUARD_PORT
  WIREGUARD_PORT=${WIREGUARD_PORT:-51820}

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
  PROXMOX_PUBLIC_KEY=$(cat /etc/wireguard/proxmox_public.key)
  chmod 600 /etc/wireguard/proxmox_private.key

  echo "Configuring WireGuard interface (wg0)..."
  cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = ${WIREGUARD_PROXMOX_TUNNEL_IP}/24
PrivateKey = $(cat /etc/wireguard/proxmox_private.key)
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
  if ! grep -q "iface ${TUNNEL_BRIDGE}" /etc/network/interfaces; then
    cat >> /etc/network/interfaces << EOL

# Bridge for WireGuard-tunneled VMs
auto ${TUNNEL_BRIDGE}
iface ${TUNNEL_BRIDGE} inet manual
    bridge_ports none
    bridge_stp off
    bridge_fd 0
EOL
  fi

  echo "Enabling and starting services..."
  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  ifup ${TUNNEL_BRIDGE} || echo "Bridge '${TUNNEL_BRIDGE}' is already up or requires a reboot."
  netfilter-persistent save >/dev/null

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

  read -p "Paste the Proxmox Public Key from Step 2: " WIREGUARD_PROXMOX_PUBLIC_KEY
  read -p "Enter your Proxmox server's public IP or DDNS hostname: " PROXMOX_ENDPOINT
  read -p "Enter the public IP of this VPS: " VPS_PUBLIC_IP
  read -p "Enter the public network interface of this VPS [eth0]: " VPS_PUBLIC_INTERFACE
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

  echo "Installing port management script to /usr/local/bin/manage-ports.sh..."
  cat > /usr/local/bin/manage-ports.sh << EOL_MANAGE
#!/bin/bash
set -e

# --- Configuration (injected by WireWarp script) ---
VPS_PUBLIC_INTERFACE="${VPS_PUBLIC_INTERFACE}"
PROXMOX_TUNNEL_IP="${WIREGUARD_PROXMOX_TUNNEL_IP}"
# --- End Configuration ---

ACTION=\$1
PROTO=\$2
PORT=\$3

# Function to add or remove a single iptables rule
manage_rule() {
  local l_action=\$1
  local l_proto=\$2
  local l_port=\$3

  # Use grep-friendly rule for checking to avoid issues with iptables-save format
  local grep_rule="-A PREROUTING -i \${VPS_PUBLIC_INTERFACE} -p \${l_proto} -m \${l_proto} --dport \${l_port} -j DNAT --to-destination \${PROXMOX_TUNNEL_IP}"
  local rule_exists=false
  if iptables-save | grep -- "\$grep_rule" > /dev/null 2>&1; then
    rule_exists=true
  fi

  if [ "\$l_action" == "add" ]; then
    if [ "\$rule_exists" = true ]; then
      echo "Rule for \${l_proto}/\${l_port} already exists."
    else
      iptables -t nat -A PREROUTING -i \${VPS_PUBLIC_INTERFACE} -p \${l_proto} --dport \${l_port} -j DNAT --to-destination \${PROXMOX_TUNNEL_IP}
      echo "Port \${l_proto}/\${l_port} forwarded to \${PROXMOX_TUNNEL_IP}."
    fi
  elif [ "\$l_action" == "remove" ]; then
    if [ "\$rule_exists" = true ]; then
      iptables -t nat -D PREROUTING -i \${VPS_PUBLIC_INTERFACE} -p \${l_proto} --dport \${l_port} -j DNAT --to-destination \${PROXMOX_TUNNEL_IP}
      echo "Port forwarding for \${l_proto}/\${l_port} removed."
    else
      echo "Rule for \${l_proto}/\${l_port} does not exist."
    fi
  fi
}

if [ "\$(id -u)" -ne 0 ]; then
  echo "This script must be run as root." >&2
  exit 1
fi

if [ -z "\$ACTION" ] || [ -z "\$PROTO" ] || [ -z "\$PORT" ]; then
  echo "Usage: \$0 <add|remove> <tcp|udp|both> <port>"
  echo "Example: \$0 add both 27016"
  exit 1
fi

case "\$PROTO" in
  tcp|udp)
    manage_rule "\$ACTION" "\$PROTO" "\$PORT"
    ;;
  both)
    echo "Managing rules for both TCP and UDP on port \${PORT}..."
    manage_rule "\$ACTION" "tcp" "\$PORT"
    manage_rule "\$ACTION" "udp" "\$PORT"
    ;;
  *)
    echo "Invalid protocol. Use 'tcp', 'udp', or 'both'." >&2
    exit 1
    ;;
esac

# Save the rules once after all operations have been attempted
echo "Saving persistent firewall rules..."
netfilter-persistent save >/dev/null
echo "Done."

EOL_MANAGE
  chmod +x /usr/local/bin/manage-ports.sh

  echo "Enabling and starting WireGuard service..."
  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  netfilter-persistent save >/dev/null

  echo "--- VPS Completion Finished ---"
  echo "✅ Success! Your WireGuard tunnel is now fully configured and active."
  echo "To manage ports, use '/usr/local/bin/manage-ports.sh add tcp 27016'"
  echo "To check tunnel status, run 'sudo wg show'"
}

# --- Main Menu ---

echo "================================================="
echo " WireGuard Transparent Tunnel Setup Script"
echo "================================================="
echo "Which part of the setup are you running?"
echo
echo "   1) [VPS]       Step 1: Initialize VPS"
echo "   2) [Proxmox]   Step 2: Initialize Proxmox Host"
echo "   3) [VPS]       Step 3: Complete VPS Setup"
echo
echo "   4) Exit"
echo

read -p "Enter your choice [1-4]: " choice

case $choice in
  1)
    vps_init
    ;;
  2)
    proxmox_init
    ;;
  3)
    vps_complete
    ;;
  4)
    echo "Exiting."
    exit 0
    ;;
  *)
    echo "Invalid option. Please try again."
    exit 1
    ;;
esac 
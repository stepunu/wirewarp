#!/bin/bash

# WireWarp v2: Advanced WireGuard Tunnel Manager
# Features: Multi-peer, Port Forwarding (DNAT), Gateway Mode support.

set -euo pipefail
shopt -s inherit_errexit nullglob

# --- Static Network Configuration ---
WIREGUARD_TUNNEL_NET="10.0.0.0/24"
WIREGUARD_VPS_IP="10.0.0.1"

# --- Helper Functions ---

check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo." >&2
    exit 1
  fi
}

install_packages() {
  local packages_to_install=()
  for pkg in "$@"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      packages_to_install+=("$pkg")
    fi
  done

  if [ ${#packages_to_install[@]} -gt 0 ]; then
    echo "Installing missing packages: ${packages_to_install[*]}..."
    apt-get update >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages_to_install[@]}" >/dev/null
  fi
}

cleanup_corrupted_files() {
    if [ -d /etc/wireguard/peers ]; then
        find /etc/wireguard/peers -type f ! -name "*.conf" ! -name "*.info" -delete 2>/dev/null || true
        for f in /etc/wireguard/peers/*.info; do
            if [ -f "$f" ] && ! grep -q '^PEER_NAME=' "$f" 2>/dev/null; then
                rm -f "$f" 2>/dev/null || true
            fi
        done
        for f in /etc/wireguard/peers/*.conf; do
            if [ -f "$f" ] && ! grep -q '^PublicKey =' "$f" 2>/dev/null; then
                rm -f "$f" 2>/dev/null || true
            fi
        done
    fi
}

check_existing_config() {
    cleanup_corrupted_files
    if [ "$1" == "init" ]; then
        if [ -f /etc/wireguard/wg0.conf ]; then
            if (whiptail --title "Existing Installation Found" --yesno "WARNING: A WireWarp installation already exists.\n\nRe-running init will overwrite the main server keys. This breaks all existing peers.\n\nContinue?" 15 78 3>&2 2>&1 1>&3); then
                whiptail --title "Overwrite Confirmed" --infobox "Stopping WireGuard and cleaning up..." 8 78
                systemctl stop wg-quick@wg0 >/dev/null 2>&1 || true
                rm -rf /etc/wireguard
            else
                return 1
            fi
        fi
    fi
    mkdir -p /etc/wireguard/peers
}

# --- Main Logic Functions ---

# Step 1: Initialize VPS (Server-side)
vps_init() {
  check_root
  install_packages wireguard curl whiptail netfilter-persistent
  check_existing_config "init" || return

  VPS_PUBLIC_INTERFACE=$(whiptail --title "VPS Setup" --inputbox "Enter Public Interface (e.g. eth0):" 10 60 "eth0" 3>&1 1>&2 2>&3)
  WIREGUARD_PORT="51820"

  whiptail --title "VPS Setup" --infobox "Generating keys..." 8 78
  wg genkey | tee /etc/wireguard/vps_private.key | wg pubkey > /etc/wireguard/vps_public.key
  chmod 600 /etc/wireguard/vps_private.key

  # Enable IP forwarding
  sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  whiptail --title "VPS Setup" --infobox "Creating config..." 8 78
  cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = ${WIREGUARD_VPS_IP}/24
ListenPort = ${WIREGUARD_PORT}
PrivateKey = $(cat /etc/wireguard/vps_private.key)
# Core Routing & NAT
PostUp = iptables -A FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT; iptables -A FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT; iptables -D FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE
# Routing for Legacy VM Networks (10.99.x.x)
PostUp = ip route add 10.99.0.0/16 dev %i
PostDown = ip route del 10.99.0.0/16 dev %i || true
# Routing for Home LANs (Generic 192.168.0.0/16 via tunnel)
PostUp = ip route add 192.168.0.0/16 dev %i
PostDown = ip route del 192.168.0.0/16 dev %i || true
EOL

  echo "VPS_PUBLIC_INTERFACE=${VPS_PUBLIC_INTERFACE}" > /etc/wireguard/wirewarp.conf
  echo "WIREGUARD_PORT=${WIREGUARD_PORT}" >> /etc/wireguard/wirewarp.conf

  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  
  whiptail --title "✅ Initialization Complete" --msgbox "Server is running.\nPublic Key: $(cat /etc/wireguard/vps_public.key)" 10 78
}

# Step 2: Add Peer
add_peer_vps() {
  check_root
  if [ ! -f /etc/wireguard/wg0.conf ]; then
    whiptail --title "Error" --msgbox "Server not initialized." 8 78; return
  fi
  
  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/vps_public.key)
  PEER_NAME=$(whiptail --title "Add Peer" --inputbox "Peer Name (e.g. gateway, laptop):" 10 60 "" 3>&1 1>&2 2>&3)
  if [ -z "$PEER_NAME" ]; then return; fi
  
  # Calculate next IP
  LAST_PEER_NUM=1
  if [ -d /etc/wireguard/peers ]; then
    for f in /etc/wireguard/peers/*.info; do
        if [ -f "$f" ]; then
            local num=$(basename "$f" | grep -o '^[0-9]\+' 2>/dev/null || echo "0")
            if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -gt "$LAST_PEER_NUM" ]; then LAST_PEER_NUM=$num; fi
        fi
    done
  fi
  NEXT_PEER_NUM=$((LAST_PEER_NUM + 1))

  # IP Allocation
  PEER_TUNNEL_IP="10.0.0.${NEXT_PEER_NUM}"
  # Legacy VM Network (Optional use)
  VM_NETWORK="10.99.${NEXT_PEER_NUM}.0/24"
  # Standard Home LAN (Can be added to AllowedIPs manually if needed, or we allow whole 192.168/16 globally)
  
  # Files
  local conf_file="/etc/wireguard/peers/${NEXT_PEER_NUM}_${PEER_NAME}.conf"
  local info_file="/etc/wireguard/peers/${NEXT_PEER_NUM}_${PEER_NAME}.info"

  # Keys
  CLIENT_PRIVATE_KEY=$(wg genkey)
  CLIENT_PUBLIC_KEY=$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)

  # Update Server Config
  echo "[Peer]" > "${conf_file}"
  echo "PublicKey = ${CLIENT_PUBLIC_KEY}" >> "${conf_file}"
  # Allow Peer IP + Legacy VM Net + Common Home LANs
  echo "AllowedIPs = ${PEER_TUNNEL_IP}/32, ${VM_NETWORK}, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8" >> "${conf_file}"
  
  echo "PEER_NAME=${PEER_NAME}" > "${info_file}"
  echo "PEER_TUNNEL_IP=${PEER_TUNNEL_IP}" >> "${info_file}"
  
  wg addconf wg0 <(cat "${conf_file}")
  wg-quick save wg0

  # Get VPS Public IP
  VPS_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

  # Generate Client Script Command
  CLIENT_SCRIPT_URL="https://gitea.step1.ro/step1nu/wirewarp/raw/branch/main/wirewarp-client.sh"
  
  CMD="bash -c \"\$(curl -fsSL ${CLIENT_SCRIPT_URL})\" -- \\
'${CLIENT_PRIVATE_KEY}' \\
'${PEER_TUNNEL_IP}' \\
'${SERVER_PUBLIC_KEY}' \\
'${VPS_IP}:${WIREGUARD_PORT}'"

  whiptail --title "✅ Peer Added" --msgbox "Peer '${PEER_NAME}' added.\nTunnel IP: ${PEER_TUNNEL_IP}\n\nRun this on the client:\n\n${CMD}" 20 78
}

# Step 3: Remove Peer
remove_peer_vps() {
    check_root
    if [ -z "$(ls -A /etc/wireguard/peers/*.info 2>/dev/null)" ]; then
        whiptail --title "Info" --msgbox "No peers found." 8 78; return
    fi

    local options=()
    for f in /etc/wireguard/peers/*.info; do
        local name=$(grep '^PEER_NAME=' "$f" | cut -d'=' -f2)
        local id=$(basename "$f" | cut -d'_' -f1)
        options+=("$id" "$name")
    done

    PEER_ID=$(whiptail --title "Remove Peer" --menu "Select Peer:" 15 60 5 "${options[@]}" 3>&2 2>&1 1>&3) || return
    
    # Find files
    local conf=$(ls /etc/wireguard/peers/${PEER_ID}_*.conf)
    local info=$(ls /etc/wireguard/peers/${PEER_ID}_*.info)
    
    if [ -f "$conf" ]; then
        local pubkey=$(grep 'PublicKey' "$conf" | awk '{print $3}')
        wg set wg0 peer "$pubkey" remove
        rm "$conf" "$info"
        wg-quick save wg0
        whiptail --title "Success" --msgbox "Peer removed." 8 78
    fi
}

# Step 4: Port Management
manage_ports_vps() {
    check_root
    if [ ! -f /etc/wireguard/wirewarp.conf ]; then return; fi
    source /etc/wireguard/wirewarp.conf

    # Select Peer
    if [ -z "$(ls -A /etc/wireguard/peers/*.info 2>/dev/null)" ]; then return; fi
    local options=()
    for f in /etc/wireguard/peers/*.info; do
        local name=$(grep '^PEER_NAME=' "$f" | cut -d'=' -f2)
        local id=$(basename "$f" | cut -d'_' -f1)
        options+=("$id" "$name")
    done
    PEER_ID=$(whiptail --title "Select Peer" --menu "Forward ports to which peer?" 15 60 5 "${options[@]}" 3>&2 2>&1 1>&3) || return
    
    # Load Peer Info
    local info=$(ls /etc/wireguard/peers/${PEER_ID}_*.info)
    source "$info" # Loads PEER_TUNNEL_IP
    
    # Ask for Target IP
    # Default is Peer Tunnel IP, but user can specify internal LAN IP (e.g. 192.168.20.221)
    TARGET_IP=$(whiptail --title "Target IP" --inputbox "Enter Destination IP.\n\nDefault: ${PEER_TUNNEL_IP} (The Peer itself)\nCustom:  e.g. 192.168.20.221 (A device BEHIND the peer)" 12 78 "${PEER_TUNNEL_IP}" 3>&1 1>&2 2>&3) || return

    ACTION=$(whiptail --title "Action" --menu "Choose:" 12 60 2 "add" "Add Rule" "remove" "Remove Rule" 3>&2 2>&1 1>&3) || return
    PROTO=$(whiptail --title "Protocol" --menu "Choose:" 12 60 3 "tcp" "TCP" "udp" "UDP" "both" "Both" 3>&2 2>&1 1>&3) || return
    PORTS=$(whiptail --title "Ports" --inputbox "Enter Port(s) (e.g. 80, 443, 8000-8010):" 10 60 "" 3>&1 1>&2 2>&3) || return

    if [ -z "$PORTS" ]; then return; fi

    # Helper to apply iptables
    apply_rule() {
        local act=$1; local prot=$2; local port=$3; local dest=$4
        # DNAT Rule
        local rule="-t nat ${act} PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${prot} --dport ${port} -j DNAT --to-destination ${dest}"
        # Execute
        if [ "$act" == "-A" ]; then
            if ! iptables -C ${rule/-A/-C} 2>/dev/null; then
                iptables $rule
                echo "Added: $prot/$port -> $dest"
            fi
        else
            # For removal, we try to delete. If it fails, ignore.
            iptables $rule 2>/dev/null || true
            echo "Removed: $prot/$port -> $dest"
        fi
    }

    # Expand ports (comma separated)
    IFS=',' read -ra PORT_LIST <<< "$PORTS"
    
    # Translate Action to Flag
    ACT_FLAG="-A"
    if [ "$ACTION" == "remove" ]; then ACT_FLAG="-D"; fi

    # Execute
    for p in "${PORT_LIST[@]}"; do
        # Clean whitespace
        p=$(echo "$p" | tr -d ' ')
        if [ "$PROTO" == "both" ]; then
            apply_rule "$ACT_FLAG" "tcp" "$p" "$TARGET_IP"
            apply_rule "$ACT_FLAG" "udp" "$p" "$TARGET_IP"
        else
            apply_rule "$ACT_FLAG" "$PROTO" "$p" "$TARGET_IP"
        fi
    done

    # Save
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save >/dev/null
    fi
    
    whiptail --title "Success" --msgbox "Port forwarding rules updated." 8 78
}

# Function to view ports (Simple grep)
view_ports_vps() {
    check_root
    if [ ! -f /etc/wireguard/wirewarp.conf ]; then return; fi
    source /etc/wireguard/wirewarp.conf
    
    local rules=$(iptables -t nat -S PREROUTING | grep "DNAT" | grep "${VPS_PUBLIC_INTERFACE}")
    if [ -z "$rules" ]; then
        whiptail --title "Active Rules" --msgbox "No active port forwarding rules." 8 78
    else
        # Pretty print
        local output=$(echo "$rules" | awk '{for(i=1;i<=NF;i++) if($i=="--dport") port=$(i+1); else if($i=="-p") proto=$(i+1); else if($i=="--to-destination") dest=$(i+1); print proto " " port " -> " dest}')
        whiptail --title "Active Forwarding Rules" --msgbox "$output" 20 78
    fi
}

# Function to fix routing issues in existing installations
fix_routing() {
    whiptail --title "Fix Routing" --msgbox "This function is deprecated in v2. Routing is handled automatically." 8 78
}

# Function to check WireGuard status
check_status() {
    check_root
    if ! command -v wg &> /dev/null; then return; fi
    wg show > /tmp/wg_status
    whiptail --title "WireGuard Status" --textbox /tmp/wg_status 20 78
}

# Function to uninstall WireWarp
uninstall() {
    check_root
    if (whiptail --title "Uninstall" --yesno "Remove WireWarp Server?" 10 60); then
        systemctl stop wg-quick@wg0
        systemctl disable wg-quick@wg0
        rm -rf /etc/wireguard
        # Flush iptables NAT (Safe? Maybe not if other services use it. Better to leave or flush specific chains)
        # For safety, we just remove config. User should reboot or flush manually.
        whiptail --title "Done" --msgbox "WireWarp config removed. Reboot recommended to clear iptables." 8 78
    fi
}

# --- Main Menu ---
check_root
install_packages whiptail

while true; do
  CHOICE=$(whiptail --title "WireWarp v2 - Server Manager" --menu "Select Option:" 20 78 8 \
    "1" "Initialize Server" \
    "2" "Add Peer" \
    "3" "Remove Peer" \
    "4" "Manage Ports (Forwarding)" \
    "5" "View Ports" \
    "6" "Check Status" \
    "7" "Uninstall" 3>&2 2>&1 1>&3)
  
  case $CHOICE in
    1) vps_init ;;
    2) add_peer_vps ;;
    3) remove_peer_vps ;;
    4) manage_ports_vps ;;
    5) view_ports_vps ;;
    6) check_status ;;
    7) uninstall ;;
    *) break ;;
  esac
done

#!/bin/bash

# WireWarp: A unified script to set up a WireGuard transparent tunnel using a TUI.

set -euo pipefail
shopt -s inherit_errexit nullglob

# --- Static Network Configuration ---
# This defines the private network between the Proxmox host and the Windows VM.
VM_NETWORK_BASE="10.99"
WIREGUARD_TUNNEL_NET="10.0.0.0/24"
WIREGUARD_VPS_IP="10.0.0.1"

# --- Helper Functions ---

# Check if the script is run as root
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo." >&2
    exit 1
  fi
}

# Function to check for and install missing packages
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

# Function to check for existing WireWarp/WireGuard configs before setup
check_existing_config() {
    # This function is now only relevant for a full uninstall/reinstall.
    # Peer management will handle its own files.
    if [ "$1" == "init" ]; then
        if [ -f /etc/wireguard/wg0.conf ]; then
            if (whiptail --title "Existing Installation Found" --yesno "WARNING: A WireWarp installation already exists.\n\nRe-running the initialization will overwrite the main server keys and configuration. This is a destructive action.\n\nAre you sure you want to re-initialize?" 15 78 3>&2 2>&1 1>&3); then
                whiptail --title "Overwrite Confirmed" --infobox "Stopping WireGuard service and removing old configuration..." 8 78
                systemctl stop wg-quick@wg0 >/dev/null 2>&1 || true
                rm -rf /etc/wireguard
            else
                echo "Operation cancelled by user."
                exit 1
            fi
        fi
    fi
    mkdir -p /etc/wireguard/peers
}

# --- Main Logic Functions ---

# Step 1: Initialize VPS (Server-side)
vps_init() {
  check_root
  check_existing_config "init"
  install_packages wireguard curl whiptail

  VPS_PUBLIC_INTERFACE=$(whiptail --title "VPS Setup (Step 1)" --inputbox "Enter the public network interface of your VPS:" 10 60 "eth0" 3>&1 1>&2 2>&3)
  WIREGUARD_PORT="51820"

  whiptail --title "VPS Setup" --infobox "Generating WireGuard keys..." 8 78
  wg genkey | tee /etc/wireguard/vps_private.key | wg pubkey > /etc/wireguard/vps_public.key
  chmod 600 /etc/wireguard/vps_private.key

  whiptail --title "VPS Setup" --infobox "Enabling IP forwarding..." 8 78
  sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  whiptail --title "VPS Setup" --infobox "Creating main WireGuard configuration..." 8 78
  cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = ${WIREGUARD_VPS_IP}/24
ListenPort = ${WIREGUARD_PORT}
PrivateKey = $(cat /etc/wireguard/vps_private.key)
PostUp = iptables -A FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT; iptables -A FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT; iptables -D FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE
EOL

  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  
  VPS_PUBLIC_KEY=$(cat /etc/wireguard/vps_public.key)
  whiptail --title "✅ VPS Initialization Complete" --msgbox "Step 1 is complete. The WireWarp server is running.\n\nYour VPS Public Key is: ${VPS_PUBLIC_KEY}\n\nYou will need this key for every peer you add." 14 78
}

# Step 2 is now "Add Peer"
add_peer_vps() {
  check_root
  if [ ! -f /etc/wireguard/wg0.conf ]; then
    whiptail --title "Error" --msgbox "WireWarp server is not initialized. Please run Step 1 on this VPS first." 8 78
    exit 1
  fi
  
  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/vps_public.key)

  PEER_NAME=$(whiptail --title "Add New Peer" --inputbox "Enter a unique name for this peer (e.g., proxmox_home, office_pc):" 10 60 "" 3>&1 1>&2 2>&3)
  if [ -z "$PEER_NAME" ]; then whiptail --title "Error" --msgbox "Peer name cannot be empty." 8 78; exit 1; fi
  
  LAST_PEER_NUM=$(ls /etc/wireguard/peers/ 2>/dev/null | grep -o '^[0-9]\+' | sort -n | tail -1)
  [ -z "$LAST_PEER_NUM" ] && LAST_PEER_NUM=1
  NEXT_PEER_NUM=$((LAST_PEER_NUM + 1))

  WIREGUARD_PROXMOX_IP="10.0.0.${NEXT_PEER_NUM}"
  VM_NETWORK="10.99.${NEXT_PEER_NUM}.0/24"
  PROXMOX_GW_IP="10.99.${NEXT_PEER_NUM}.1"
  VM_PRIVATE_IP="10.99.${NEXT_PEER_NUM}.2"

  local peer_conf_file="/etc/wireguard/peers/${NEXT_PEER_NUM}_${PEER_NAME}.conf"
  local peer_info_file="/etc/wireguard/peers/${NEXT_PEER_NUM}_${PEER_NAME}.info"

  CLIENT_PRIVATE_KEY=$(wg genkey)
  CLIENT_PUBLIC_KEY=$(echo "${CLIENT_PRIVATE_KEY}" | wg pubkey)

  whiptail --title "Add New Peer" --infobox "Creating peer configuration on server..." 8 78
  echo "[Peer]" > "${peer_conf_file}"
  echo "PublicKey = ${CLIENT_PUBLIC_KEY}" >> "${peer_conf_file}"
  echo "AllowedIPs = ${WIREGUARD_PROXMOX_IP}/32, ${VM_NETWORK}" >> "${peer_conf_file}"
  
  echo "PEER_NAME=${PEER_NAME}" > "${peer_info_file}"
  echo "VM_PRIVATE_IP=${VM_PRIVATE_IP}" >> "${peer_info_file}"
  
  wg addconf wg0 <(cat "${peer_conf_file}")
  wg-quick save wg0

  CLIENT_SCRIPT_URL="https://gitea.step1.ro/step1nu/wirewarp/raw/branch/main/wirewarp-client.sh"
  
  whiptail --title "✅ Peer Added - Action Required on Client" --msgbox "The new peer '${PEER_NAME}' has been configured on the server.\n\nNow, run the following command on your Proxmox/Client machine to set it up. This command contains the new private key.\n\n---------------------------------\nbash -c \"\$(curl -fsSL ${CLIENT_SCRIPT_URL})\" -- \\
'${CLIENT_PRIVATE_KEY}' \\
'${WIREGUARD_PROXMOX_IP}' \\
'${SERVER_PUBLIC_KEY}' \\
'YOUR_VPS_IP_OR_HOSTNAME:51820' \\
'${PROXMOX_GW_IP}' \\
'1.1.1.1' \\
'vmbr1'
\n---------------------------------\n\nAfter running this on the client, configure your Windows VM with IP: ${VM_PRIVATE_IP}, Gateway: ${PROXMOX_GW_IP}" 28 82
}

# Function to remove a peer
remove_peer_vps() {
    check_root
    PEER_TO_REMOVE=$(ls /etc/wireguard/peers/*.conf | xargs -n 1 basename | whiptail --title "Remove Peer" --menu "Select a peer to remove:" 20 78 12 3>&1 1>&2 2>&3)
    
    if [ -n "$PEER_TO_REMOVE" ]; then
        PEER_PUBLIC_KEY=$(grep 'PublicKey' "/etc/wireguard/peers/${PEER_TO_REMOVE}" | awk '{print $3}')
        wg set wg0 peer "${PEER_PUBLIC_KEY}" remove
        rm "/etc/wireguard/peers/${PEER_TO_REMOVE}"
        rm "/etc/wireguard/peers/${PEER_TO_REMOVE%.conf}.info"
        wg-quick save wg0
        whiptail --title "Success" --msgbox "Peer ${PEER_TO_REMOVE} and its configurations have been removed." 8 78
    fi
}

# Function to manage ports for a specific peer
manage_ports_vps() {
    check_root
    PEER_INFO_FILE=$(ls /etc/wireguard/peers/*.info | xargs -n 1 basename | whiptail --title "Manage Ports" --menu "Select a peer to manage ports for:" 20 78 12 3>&1 1>&2 2>&3)
    
    if [ -n "$PEER_INFO_FILE" ]; then
        source "/etc/wireguard/peers/${PEER_INFO_FILE}"
        source /etc/wireguard/wirewarp.conf # Get VPS_PUBLIC_INTERFACE

        ACTION=$(whiptail --title "Port Management for ${PEER_NAME}" --menu "Choose an action:" 15 60 2 "add" "Add a new port forward" "remove" "Remove an existing port forward" 3>&2 2>&1 1>&3)
        PROTO=$(whiptail --title "Port Management for ${PEER_NAME}" --menu "Choose a protocol:" 15 60 3 "tcp" "" "udp" "" "both" "Forward both TCP and UDP" 3>&2 2>&1 1>&3)
        PORT=$(whiptail --title "Port Management for ${PEER_NAME}" --inputbox "Enter the port number:" 10 60 "" 3>&1 1>&2 2>&3)

        manage_rule() {
            local l_action=$1; local l_proto=$2; local l_port=$3
            local grep_rule="-A PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} -m ${l_proto} --dport ${l_port} -j DNAT --to-destination ${VM_PRIVATE_IP}"
            if [ "$l_action" == "add" ]; then
                if ! iptables-save | grep -- "$grep_rule" > /dev/null 2>&1; then
                    iptables -t nat -A PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} --dport ${l_port} -j DNAT --to-destination ${VM_PRIVATE_IP}
                    whiptail --title "Success" --msgbox "Port ${l_proto}/${l_port} forwarded to ${VM_PRIVATE_IP}." 8 78
                fi
            elif [ "$l_action" == "remove" ]; then
                if iptables-save | grep -- "$grep_rule" > /dev/null 2>&1; then
                    iptables -t nat -D PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} --dport ${l_port} -j DNAT --to-destination ${VM_PRIVATE_IP}
                    whiptail --title "Success" --msgbox "Port forwarding for ${l_proto}/${l_port} removed." 8 78
                fi
            fi
        }

        case "$PROTO" in
            tcp|udp) manage_rule "$ACTION" "$PROTO" "$PORT" ;;
            both)
                whiptail --title "Info" --msgbox "Managing rules for both TCP and UDP on port ${PORT}..." 8 78
                manage_rule "$ACTION" "tcp" "$PORT"; manage_rule "$ACTION" "udp" "$PORT"
                ;;
        esac

        whiptail --title "Port Management" --infobox "Saving persistent firewall rules..." 8 78
        netfilter-persistent save >/dev/null
        whiptail --title "Success" --msgbox "Port rules updated successfully." 8 78
    fi
}

# Function to view ports for a specific peer
view_ports_vps() {
    check_root
    PEER_INFO_FILE=$(ls /etc/wireguard/peers/*.info | xargs -n 1 basename | whiptail --title "View Ports" --menu "Select a peer to view ports for:" 20 78 12 3>&1 1>&2 2>&3)

    if [ -n "$PEER_INFO_FILE" ]; then
        source "/etc/wireguard/peers/${PEER_INFO_FILE}"
        source /etc/wireguard/wirewarp.conf
        local rules=$(iptables-save | grep -- "-A PREROUTING -i ${VPS_PUBLIC_INTERFACE}" | grep -- "-j DNAT --to-destination ${VM_PRIVATE_IP}")
        
        if [ -z "$rules" ]; then
            whiptail --title "Forwarded Ports" --msgbox "No active WireWarp port forwarding rules found." 10 78
        else
            local formatted_rules=$(echo "$rules" | awk '{print "Protocol: " $6 ", Port: " $10}')
            whiptail --title "Active Forwarded Ports" --msgbox "The following ports are being forwarded to ${VM_PRIVATE_IP}:\n\n${formatted_rules}" 20 78
        fi
    fi
}

# Function to check WireGuard status
check_status() {
    check_root
    if ! command -v wg &> /dev/null; then
        whiptail --title "Error" --msgbox "WireGuard tools are not installed. Please run one of the setup steps first." 8 78
        exit 1
    fi
    wg_status=$(wg show)
    whiptail --title "WireGuard Status" --msgbox "$wg_status" 20 78
}

# Function to uninstall WireWarp
uninstall() {
    check_root
    if (whiptail --title "Uninstall WireWarp" --yesno "Are you sure you want to completely uninstall WireWarp? This is irreversible." 10 78); then
        whiptail --title "Uninstalling..." --infobox "Stopping and disabling WireGuard service..." 8 78
        systemctl stop wg-quick@wg0 >/dev/null 2>&1 || true
        systemctl disable wg-quick@wg0 >/dev/null 2>&1 || true

        if [ -f /etc/wireguard/vps_private.key ]; then
            apt-get purge -y wireguard >/dev/null
            rm -rf /etc/wireguard
            whiptail --title "Info" --msgbox "VPS cleanup complete." 8 78
        elif [ -f /etc/wireguard/proxmox_private.key ]; then
            ifdown vmbr1 >/dev/null 2>&1 || true
            sed -i '/# WireWarp Tunnel Bridge - Start/,/# WireWarp Tunnel Bridge - End/d' /etc/network/interfaces
            apt-get purge -y wireguard iptables-persistent >/dev/null
            rm -rf /etc/wireguard
            whiptail --title "Info" --msgbox "Proxmox cleanup complete. A reboot is recommended." 8 78
        fi
    fi
}

# --- Main Menu ---
check_root
install_packages whiptail

while true; do
  CHOICE=$(whiptail --title "WireWarp - Multi-Tunnel Manager" --menu "What do you want to do?" 20 78 7 \
    "1" "[VPS] Initialize Server" \
    "2" "[VPS] Add New Peer" \
    "3" "[VPS] Remove Peer" \
    "4" "[VPS] Manage Ports for a Peer" \
    "5" "[VPS] View Ports for a Peer" \
    "6" "[All] Check Tunnel Status" \
    "7" "[All] Uninstall WireWarp" 3>&2 2>&1 1>&3)
  
  case $CHOICE in
    1) vps_init ;;
    2) add_peer_vps ;;
    3) remove_peer_vps ;;
    4) manage_ports_vps ;;
    5) view_ports_vps ;;
    6) check_status ;;
    7) uninstall ;;
    *) break ;; # Exit on Esc/Cancel
  esac
done 
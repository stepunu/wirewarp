#!/bin/bash

# WireWarp: A unified script to set up a WireGuard transparent tunnel using a TUI.

set -euo pipefail
shopt -s inherit_errexit nullglob

# --- Static Network Configuration ---
# This defines the private network between the Proxmox host and the Windows VM.
VM_NETWORK="10.99.0.0/24"
PROXMOX_GW_IP="10.99.0.1"
VM_PRIVATE_IP="10.99.0.2"
WIREGUARD_TUNNEL_NET="10.0.0.0/24"
WIREGUARD_VPS_IP="10.0.0.1"
WIREGUARD_PROXMOX_IP="10.0.0.2"

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
    if [ -f /etc/wireguard/wg0.conf ] || [ -f /etc/wireguard/vps_private.key ] || [ -f /etc/wireguard/proxmox_private.key ]; then
        if (whiptail --title "Existing Configuration Found" --yesno "WARNING: An existing WireGuard configuration was found.\n\nContinuing will overwrite the existing wg0.conf and any related keys.\n\nDo you want to continue and overwrite?" 12 78 3>&2 2>&1 1>&3); then
            whiptail --title "Overwrite Confirmed" --infobox "Stopping WireGuard service and removing old configuration..." 8 78
            systemctl stop wg-quick@wg0 >/dev/null 2>&1 || true
            rm -f /etc/wireguard/*.key /etc/wireguard/wg0.conf /etc/wireguard/wirewarp.conf
        else
            echo "Operation cancelled by user."
            exit 1
        fi
    fi
    mkdir -p /etc/wireguard
}

# --- Main Logic Functions ---

# Step 1: Initialize VPS
vps_init() {
  check_root
  check_existing_config
  install_packages wireguard curl whiptail

  VPS_PUBLIC_INTERFACE=$(whiptail --title "VPS Setup (Step 1)" --inputbox "Enter the public network interface of your VPS:" 10 60 "eth0" 3>&1 1>&2 2>&3)
  WIREGUARD_PORT="51820"

  whiptail --title "VPS Setup" --infobox "Generating WireGuard keys..." 8 78
  wg genkey | tee /etc/wireguard/vps_private.key | wg pubkey > /etc/wireguard/vps_public.key
  chmod 600 /etc/wireguard/vps_private.key

  whiptail --title "VPS Setup" --infobox "Enabling IP forwarding..." 8 78
  sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  
  VPS_PUBLIC_KEY=$(cat /etc/wireguard/vps_public.key)
  whiptail --title "✅ VPS Initialization Complete" --msgbox "Step 1 is complete. Copy the following values for Step 2 on your Proxmox host.\n\nVPS Public Key: ${VPS_PUBLIC_KEY}\nVPS WireGuard Port: ${WIREGUARD_PORT}" 14 78
}

# Step 2: Initialize Proxmox Host
proxmox_init() {
  check_root
  check_existing_config
  install_packages wireguard iptables-persistent curl whiptail

  VPS_ENDPOINT=$(whiptail --title "Proxmox Setup (Step 2)" --inputbox "Enter the public IP or DDNS hostname of your VPS:" 10 60 "" 3>&1 1>&2 2>&3)
  WIREGUARD_VPS_PUBLIC_KEY=$(whiptail --title "Proxmox Setup (Step 2)" --inputbox "Paste the VPS Public Key from Step 1:" 10 60 "" 3>&1 1>&2 2>&3)
  WIREGUARD_PORT=$(whiptail --title "Proxmox Setup (Step 2)" --inputbox "Enter the WireGuard port from Step 1:" 10 60 "51820" 3>&1 1>&2 2>&3)
  DNS_SERVER=$(whiptail --title "Proxmox Setup (Step 2)" --inputbox "Enter DNS server for the tunnel interface:" 10 60 "1.1.1.1" 3>&1 1>&2 2>&3)
  TUNNEL_BRIDGE="vmbr1"

  whiptail --title "Proxmox Setup" --infobox "Generating WireGuard keys for Proxmox..." 8 78
  wg genkey | tee /etc/wireguard/proxmox_private.key | wg pubkey > /etc/wireguard/proxmox_public.key
  chmod 600 /etc/wireguard/proxmox_private.key

  whiptail --title "Proxmox Setup" --infobox "Configuring WireGuard interface (wg0)..." 8 78
  cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = ${WIREGUARD_PROXMOX_IP}/24
PrivateKey = $(cat /etc/wireguard/proxmox_private.key)
DNS = ${DNS_SERVER}
PostUp = iptables -A FORWARD -i %i -o ${TUNNEL_BRIDGE} -j ACCEPT
PostUp = iptables -A FORWARD -i ${TUNNEL_BRIDGE} -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s ${VM_NETWORK} -o %i -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o ${TUNNEL_BRIDGE} -j ACCEPT
PostDown = iptables -D FORWARD -i ${TUNNEL_BRIDGE} -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s ${VM_NETWORK} -o %i -j MASQUERADE
[Peer]
PublicKey = ${WIREGUARD_VPS_PUBLIC_KEY}
Endpoint = ${VPS_ENDPOINT}:${WIREGUARD_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOL

  whiptail --title "Proxmox Setup" --infobox "Configuring network bridge '${TUNNEL_BRIDGE}'..." 8 78
  if ! grep -q "# WireWarp Tunnel Bridge" /etc/network/interfaces; then
    cat >> /etc/network/interfaces << EOL

# WireWarp Tunnel Bridge - Start
auto ${TUNNEL_BRIDGE}
iface ${TUNNEL_BRIDGE} inet static
    address ${PROXMOX_GW_IP}
    netmask 255.255.255.0
    bridge-ports none
    bridge-stp off
    bridge-fd 0
# WireWarp Tunnel Bridge - End
EOL
  fi
  
  whiptail --title "Proxmox Setup" --infobox "Enabling IP forwarding..." 8 78
  sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  whiptail --title "Proxmox Setup" --infobox "Enabling and starting services..." 8 78
  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  ifup ${TUNNEL_BRIDGE} >/dev/null 2>&1 || whiptail --title "Info" --msgbox "Bridge '${TUNNEL_BRIDGE}' is already up or requires a reboot to become active in the UI." 8 78
  netfilter-persistent save >/dev/null

  PROXMOX_PUBLIC_KEY=$(cat /etc/wireguard/proxmox_public.key)
  whiptail --title "✅ Proxmox Initialization Complete" --msgbox "Step 2 is complete. Copy this public key for Step 3 on your VPS.\n\nProxmox Public Key: ${PROXMOX_PUBLIC_KEY}" 12 78
}

# Step 3: Complete VPS Setup
vps_complete() {
  check_root
  if [ ! -f /etc/wireguard/vps_private.key ]; then
    whiptail --title "Error" --msgbox "VPS private key not found. Please run Step 1 on this VPS first." 8 78
    exit 1
  fi
  install_packages iptables-persistent curl whiptail

  WIREGUARD_PROXMOX_PUBLIC_KEY=$(whiptail --title "VPS Completion (Step 3)" --inputbox "Paste the Proxmox Public Key from Step 2:" 10 60 "" 3>&1 1>&2 2>&3)
  PROXMOX_ENDPOINT=$(whiptail --title "VPS Completion (Step 3)" --inputbox "Enter your Proxmox server's public IP or DDNS hostname:" 10 60 "" 3>&1 1>&2 2>&3)
  VPS_PUBLIC_INTERFACE=$(whiptail --title "VPS Completion (Step 3)" --inputbox "Enter the public network interface of this VPS:" 10 60 "eth0" 3>&1 1>&2 2>&3)
  WIREGUARD_PORT="51820"

  whiptail --title "VPS Completion" --infobox "Creating final WireGuard configuration..." 8 78
  cat > /etc/wireguard/wg0.conf << EOL
[Interface]
Address = ${WIREGUARD_VPS_IP}/24
ListenPort = ${WIREGUARD_PORT}
PrivateKey = $(cat /etc/wireguard/vps_private.key)
PostUp = iptables -A FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT
PostUp = iptables -A FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT
PostDown = iptables -D FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE
[Peer]
PublicKey = ${WIREGUARD_PROXMOX_PUBLIC_KEY}
Endpoint = ${PROXMOX_ENDPOINT}:${WIREGUARD_PORT}
AllowedIPs = ${WIREGUARD_PROXMOX_IP}/32, ${VM_NETWORK}
EOL
  
  echo "VPS_PUBLIC_INTERFACE=${VPS_PUBLIC_INTERFACE}" > /etc/wireguard/wirewarp.conf
  echo "VM_PRIVATE_IP=${VM_PRIVATE_IP}" >> /etc/wireguard/wirewarp.conf

  whiptail --title "VPS Completion" --infobox "Enabling and starting WireGuard service..." 8 78
  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  netfilter-persistent save >/dev/null
  
  whiptail --title "✅ Success! Final Configuration for Windows VM" --msgbox "The tunnel is active. Configure your Windows VM's primary network card (the one connected to vmbr1) with these settings:\n\nIP address: ${VM_PRIVATE_IP}\nSubnet mask: 255.255.255.0\nDefault gateway: ${PROXMOX_GW_IP}\n\nPreferred DNS: ${DNS_SERVER:-1.1.1.1} (or any other)\n\nEnsure your second VM network card (for RDP) has no gateway set." 20 78
}

# Function to manage ports on the VPS
manage_ports_vps() {
    check_root
    if [ ! -f /etc/wireguard/wirewarp.conf ]; then
        whiptail --title "Error" --msgbox "Could not find the WireWarp config file. Please run Step 3 on the VPS first." 8 78
        exit 1
    fi
    source /etc/wireguard/wirewarp.conf

    ACTION=$(whiptail --title "Port Management" --menu "Choose an action:" 15 60 2 "add" "Add a new port forward" "remove" "Remove an existing port forward" 3>&2 2>&1 1>&3)
    PROTO=$(whiptail --title "Port Management" --menu "Choose a protocol:" 15 60 3 "tcp" "" "udp" "" "both" "Forward both TCP and UDP" 3>&2 2>&1 1>&3)
    PORT=$(whiptail --title "Port Management" --inputbox "Enter the port number:" 10 60 "" 3>&1 1>&2 2>&3)

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
  CHOICE=$(whiptail --title "WireWarp - WireGuard Tunnel Script" --menu "What do you want to do?" 20 78 7 \
    "1" "[VPS] Step 1: Initialize VPS" \
    "2" "[Proxmox] Step 2: Initialize Proxmox Host" \
    "3" "[VPS] Step 3: Complete VPS Setup" \
    "4" "[VPS] Manage Forwarded Ports" \
    "5" "[All] Check Tunnel Status" \
    "6" "[All] Uninstall WireWarp" \
    "7" "Exit" 3>&2 2>&1 1>&3)
  
  case $CHOICE in
    1) vps_init ;;
    2) proxmox_init ;;
    3) vps_complete ;;
    4) manage_ports_vps ;;
    5) check_status ;;
    6) uninstall ;;
    7) break ;;
    *) break ;; # Exit on Esc/Cancel
  esac
done 
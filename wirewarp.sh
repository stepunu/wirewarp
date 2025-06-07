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

# Function to clean up any corrupted or invalid files
cleanup_corrupted_files() {
    if [ -d /etc/wireguard/peers ]; then
        # Remove any files that don't match our expected patterns or contain invalid data
        find /etc/wireguard/peers -type f ! -name "*.conf" ! -name "*.info" -delete 2>/dev/null || true
        
        # Remove any .info files that don't contain PEER_NAME
        for f in /etc/wireguard/peers/*.info; do
            if [ -f "$f" ] && ! grep -q '^PEER_NAME=' "$f" 2>/dev/null; then
                rm -f "$f" 2>/dev/null || true
            fi
        done
        
        # Remove any .conf files that don't contain PublicKey
        for f in /etc/wireguard/peers/*.conf; do
            if [ -f "$f" ] && ! grep -q '^PublicKey =' "$f" 2>/dev/null; then
                rm -f "$f" 2>/dev/null || true
            fi
        done
    fi
}

# Function to check for existing WireWarp/WireGuard configs before setup
check_existing_config() {
    # Clean up any corrupted files first
    cleanup_corrupted_files
    
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
  install_packages wireguard curl whiptail netfilter-persistent
  check_existing_config "init"

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
PostUp = iptables -A FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT; iptables -A FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE; ip route add 10.99.0.0/16 dev %i
PostDown = iptables -D FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT; iptables -D FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE; ip route del 10.99.0.0/16 dev %i || true
EOL

  # Save VPS configuration for later use
  echo "VPS_PUBLIC_INTERFACE=${VPS_PUBLIC_INTERFACE}" > /etc/wireguard/wirewarp.conf
  echo "WIREGUARD_PORT=${WIREGUARD_PORT}" >> /etc/wireguard/wirewarp.conf

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
  
  # Find the highest peer number from existing .info files
  LAST_PEER_NUM=1
  if [ -d /etc/wireguard/peers ]; then
    for f in /etc/wireguard/peers/*.info; do
      if [ -f "$f" ]; then
        local peer_num=$(basename "$f" | grep -o '^[0-9]\+' 2>/dev/null || echo "0")
        if [[ "$peer_num" =~ ^[0-9]+$ ]] && [ "$peer_num" -gt "$LAST_PEER_NUM" ]; then
          LAST_PEER_NUM=$peer_num
        fi
      fi
    done
  fi
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
    
    # Check if peers directory exists and has .info files
    if [ ! -d /etc/wireguard/peers ] || [ -z "$(find /etc/wireguard/peers -name "*.info" -type f 2>/dev/null)" ]; then
        whiptail --title "Info" --msgbox "No peers found to remove." 8 78
        return
    fi

    local options=()
    for f in /etc/wireguard/peers/*.info; do
        # Ensure the file exists and is a regular file
        if [ -f "$f" ]; then
            local peer_name=$(grep '^PEER_NAME=' "$f" 2>/dev/null | cut -d'=' -f2)
            local base_filename=$(basename "$f" .info)
            if [ -n "$peer_name" ]; then
                options+=("$base_filename" "Peer: ${peer_name}")
            fi
        fi
    done
    
    if [ ${#options[@]} -eq 0 ]; then
        whiptail --title "Info" --msgbox "No valid peers found to remove." 8 78
        return
    fi

    PEER_TO_REMOVE=$(whiptail --title "Remove Peer" --menu "Select a peer to remove:" 20 78 12 "${options[@]}" 3>&2 2>&1 1>&3) || true
    
    if [ -n "$PEER_TO_REMOVE" ]; then
        local peer_public_key=$(grep 'PublicKey' "/etc/wireguard/peers/${PEER_TO_REMOVE}.conf" | awk '{print $3}')
        whiptail --title "Removing Peer" --infobox "Removing peer ${peer_public_key}..." 8 78
        wg set wg0 peer "${peer_public_key}" remove
        rm "/etc/wireguard/peers/${PEER_TO_REMOVE}.conf"
        rm "/etc/wireguard/peers/${PEER_TO_REMOVE}.info"
        wg-quick save wg0
        whiptail --title "Success" --msgbox "Peer ${PEER_TO_REMOVE} and its configurations have been removed." 8 78
    fi
}

# Function to manage ports for a specific peer
manage_ports_vps() {
    check_root
    
    # Check if peers directory exists and has .info files
    if [ ! -d /etc/wireguard/peers ] || [ -z "$(find /etc/wireguard/peers -name "*.info" -type f 2>/dev/null)" ]; then
        whiptail --title "Info" --msgbox "No peers found. Please add a peer before managing ports." 8 78
        return
    fi
    
    local options=()
    for f in /etc/wireguard/peers/*.info; do
        # Ensure the file exists and is a regular file
        if [ -f "$f" ]; then
            local peer_name=$(grep '^PEER_NAME=' "$f" 2>/dev/null | cut -d'=' -f2)
            local base_filename=$(basename "$f")
            if [ -n "$peer_name" ]; then
                options+=("$base_filename" "Peer: ${peer_name}")
            fi
        fi
    done
    
    if [ ${#options[@]} -eq 0 ]; then
        whiptail --title "Info" --msgbox "No valid peers found for port management." 8 78
        return
    fi

    PEER_INFO_FILE=$(whiptail --title "Manage Ports" --menu "Select a peer to manage ports for:" 20 78 12 "${options[@]}" 3>&2 2>&1 1>&3) || true
    
    if [ -n "$PEER_INFO_FILE" ]; then
        source "/etc/wireguard/peers/${PEER_INFO_FILE}"
        
        # Check if VPS is initialized
        if [ ! -f /etc/wireguard/wirewarp.conf ]; then
            whiptail --title "Error" --msgbox "VPS is not initialized. Please run Step 1 (Initialize Server) first." 8 78
            return
        fi
        source /etc/wireguard/wirewarp.conf # Get VPS_PUBLIC_INTERFACE

        ACTION=$(whiptail --title "Port Management for ${PEER_NAME}" --menu "Choose an action:" 15 60 2 "add" "Add a new port forward" "remove" "Remove an existing port forward" 3>&2 2>&1 1>&3) || true
        PROTO=$(whiptail --title "Port Management for ${PEER_NAME}" --menu "Choose a protocol:" 15 60 3 "tcp" "" "udp" "" "both" "Forward both TCP and UDP" 3>&2 2>&1 1>&3) || true
        PORT_INPUT=$(whiptail --title "Port Management for ${PEER_NAME}" --inputbox "Enter port(s):\n• Single port: 80\n• Multiple ports: 80,443,8080\n• Port range: 8000-8010\n• Mixed: 80,443,8000-8005" 12 70 "" 3>&1 1>&2 2>&3) || true

        if [ -z "$ACTION" ] || [ -z "$PROTO" ] || [ -z "$PORT_INPUT" ]; then
          whiptail --title "Error" --msgbox "All fields are mandatory. Aborting." 8 78
          return
        fi
        
        # Function to expand port ranges and comma-separated ports
        expand_ports() {
            local input="$1"
            local ports=()
            
            # Split by comma
            IFS=',' read -ra PORT_PARTS <<< "$input"
            
            for part in "${PORT_PARTS[@]}"; do
                # Trim whitespace
                part=$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                
                if [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
                    # Handle range (e.g., 8000-8010)
                    local start_port=$(echo "$part" | cut -d'-' -f1)
                    local end_port=$(echo "$part" | cut -d'-' -f2)
                    
                    if [ "$start_port" -le "$end_port" ] && [ "$start_port" -ge 1 ] && [ "$end_port" -le 65535 ]; then
                        for ((p=start_port; p<=end_port; p++)); do
                            ports+=("$p")
                        done
                    else
                        whiptail --title "Error" --msgbox "Invalid port range: $part\nRange must be 1-65535 and start <= end." 8 78
                        return 1
                    fi
                elif [[ "$part" =~ ^[0-9]+$ ]]; then
                    # Handle single port
                    if [ "$part" -ge 1 ] && [ "$part" -le 65535 ]; then
                        ports+=("$part")
                    else
                        whiptail --title "Error" --msgbox "Invalid port: $part\nPort must be between 1 and 65535." 8 78
                        return 1
                    fi
                else
                    whiptail --title "Error" --msgbox "Invalid port format: $part\nUse single ports (80), ranges (8000-8010), or comma-separated (80,443)." 10 78
                    return 1
                fi
            done
            
            # Remove duplicates and sort
            printf '%s\n' "${ports[@]}" | sort -nu
        }
        
        # Expand the port input
        EXPANDED_PORTS=$(expand_ports "$PORT_INPUT")
        if [ $? -ne 0 ]; then
            return
        fi
        
        # Convert to array
        readarray -t PORTS_ARRAY <<< "$EXPANDED_PORTS"
        
        if [ ${#PORTS_ARRAY[@]} -eq 0 ]; then
            whiptail --title "Error" --msgbox "No valid ports found in input: $PORT_INPUT" 8 78
            return
        fi
        
        # Confirm action for multiple ports
        if [ ${#PORTS_ARRAY[@]} -gt 1 ]; then
            local port_list=$(printf '%s, ' "${PORTS_ARRAY[@]}")
            port_list=${port_list%, }  # Remove trailing comma
            
            if ! whiptail --title "Confirm Multiple Ports" --yesno "You are about to $ACTION ${#PORTS_ARRAY[@]} ports for protocol $PROTO:\n\n$port_list\n\nContinue?" 12 78; then
                return
            fi
        fi
        
        manage_rule() {
            local l_action=$1; local l_proto=$2; local l_port=$3
            local grep_rule="-A PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} -m ${l_proto} --dport ${l_port} -j DNAT --to-destination ${VM_PRIVATE_IP}"
            if [ "$l_action" == "add" ]; then
                if ! iptables-save | grep -- "$grep_rule" > /dev/null 2>&1; then
                    iptables -t nat -A PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} --dport ${l_port} -j DNAT --to-destination ${VM_PRIVATE_IP}
                    echo "✓ Added ${l_proto}/${l_port}"
                else
                    echo "! ${l_proto}/${l_port} already exists"
                fi
            elif [ "$l_action" == "remove" ]; then
                if iptables-save | grep -- "$grep_rule" > /dev/null 2>&1; then
                    iptables -t nat -D PREROUTING -i ${VPS_PUBLIC_INTERFACE} -p ${l_proto} --dport ${l_port} -j DNAT --to-destination ${VM_PRIVATE_IP}
                    echo "✓ Removed ${l_proto}/${l_port}"
                else
                    echo "! ${l_proto}/${l_port} not found"
                fi
            fi
        }

        # Process all ports
        whiptail --title "Processing Ports" --infobox "Processing ${#PORTS_ARRAY[@]} port(s)..." 8 78
        sleep 1
        
        # Collect results for display
        RESULTS=()
        
        case "$PROTO" in
            tcp|udp) 
                for port in "${PORTS_ARRAY[@]}"; do
                    result=$(manage_rule "$ACTION" "$PROTO" "$port")
                    RESULTS+=("$result")
                done
                ;;
            both)
                for port in "${PORTS_ARRAY[@]}"; do
                    result_tcp=$(manage_rule "$ACTION" "tcp" "$port")
                    result_udp=$(manage_rule "$ACTION" "udp" "$port")
                    RESULTS+=("$result_tcp" "$result_udp")
                done
                ;;
        esac
        
        # Display results
        local results_text=""
        for result in "${RESULTS[@]}"; do
            results_text+="$result\n"
        done
        
        if [ ${#PORTS_ARRAY[@]} -eq 1 ]; then
            whiptail --title "Port Management Complete" --msgbox "Result:\n\n$results_text" 10 78
        else
            whiptail --title "Bulk Port Management Complete" --msgbox "Processed ${#PORTS_ARRAY[@]} port(s):\n\n$results_text" 20 78
        fi

        whiptail --title "Port Management" --infobox "Saving persistent firewall rules..." 8 78
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null
        else
            # Fallback for systems without netfilter-persistent
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        whiptail --title "Success" --msgbox "Port rules updated successfully." 8 78
    fi
}

# Function to view ports for a specific peer
view_ports_vps() {
    check_root
    
    # Check if peers directory exists and has .info files
    if [ ! -d /etc/wireguard/peers ] || [ -z "$(find /etc/wireguard/peers -name "*.info" -type f 2>/dev/null)" ]; then
        whiptail --title "Info" --msgbox "No peers found to view ports for." 8 78
        return
    fi
    
    local options=()
    for f in /etc/wireguard/peers/*.info; do
        # Ensure the file exists and is a regular file
        if [ -f "$f" ]; then
            local peer_name=$(grep '^PEER_NAME=' "$f" 2>/dev/null | cut -d'=' -f2)
            local base_filename=$(basename "$f")
            if [ -n "$peer_name" ]; then
                options+=("$base_filename" "Peer: ${peer_name}")
            fi
        fi
    done
    
    if [ ${#options[@]} -eq 0 ]; then
        whiptail --title "Info" --msgbox "No valid peers found to view ports for." 8 78
        return
    fi

    PEER_INFO_FILE=$(whiptail --title "View Ports" --menu "Select a peer to view ports for:" 20 78 12 "${options[@]}" 3>&2 2>&1 1>&3) || true

    if [ -n "$PEER_INFO_FILE" ]; then
        source "/etc/wireguard/peers/${PEER_INFO_FILE}"
        
        # Check if VPS is initialized
        if [ ! -f /etc/wireguard/wirewarp.conf ]; then
            whiptail --title "Error" --msgbox "VPS is not initialized. Please run Step 1 (Initialize Server) first." 8 78
            return
        fi
        source /etc/wireguard/wirewarp.conf
        
        local rules=$(iptables-save | grep -- "-A PREROUTING -i ${VPS_PUBLIC_INTERFACE}" | grep -- "-j DNAT --to-destination ${VM_PRIVATE_IP}" || true)
        
        if [ -z "$rules" ]; then
            whiptail --title "Forwarded Ports" --msgbox "No active WireWarp port forwarding rules found for peer '${PEER_NAME}'." 10 78
        else
            local formatted_rules=$(echo "$rules" | awk '{print "Protocol: " $6 ", Port: " $10}')
            whiptail --title "Active Ports for ${PEER_NAME}" --msgbox "The following ports are being forwarded to ${VM_PRIVATE_IP}:\n\n${formatted_rules}" 20 78
        fi
    fi
}

# Function to fix routing issues in existing installations
fix_routing() {
    check_root
    if [ ! -f /etc/wireguard/wg0.conf ]; then
        whiptail --title "Error" --msgbox "No WireGuard configuration found. Please initialize first." 8 78
        return
    fi
    
    if [ ! -f /etc/wireguard/wirewarp.conf ]; then
        whiptail --title "Error" --msgbox "WireWarp configuration not found. This might not be a WireWarp installation." 8 78
        return
    fi
    
    source /etc/wireguard/wirewarp.conf
    
    # Check if route already exists
    if ip route show | grep -q "10.99.0.0/16 dev wg0"; then
        whiptail --title "Info" --msgbox "VM network routing is already configured correctly." 8 78
        return
    fi
    
    if (whiptail --title "Fix Routing Issue" --yesno "This will update your WireGuard configuration to fix port forwarding routing issues.\n\nThis will:\n• Add VM network routes (10.99.0.0/16)\n• Update FORWARD rules to allow new connections\n• Restart WireGuard service\n\nContinue?" 15 78); then
        whiptail --title "Fixing Routing" --infobox "Updating WireGuard configuration..." 8 78
        
        # Stop WireGuard
        systemctl stop wg-quick@wg0 >/dev/null 2>&1 || true
        
        # Update the configuration
        sed -i "s|PostUp = .*|PostUp = iptables -A FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT; iptables -A FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE; ip route add 10.99.0.0/16 dev %i|" /etc/wireguard/wg0.conf
        sed -i "s|PostDown = .*|PostDown = iptables -D FORWARD -i %i -o ${VPS_PUBLIC_INTERFACE} -j ACCEPT; iptables -D FORWARD -i ${VPS_PUBLIC_INTERFACE} -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${VPS_PUBLIC_INTERFACE} -j MASQUERADE; ip route del 10.99.0.0/16 dev %i \|\| true|" /etc/wireguard/wg0.conf
        
        # Restart WireGuard
        systemctl start wg-quick@wg0
        
        # Test routing
        if ip route show | grep -q "10.99.0.0/16 dev wg0"; then
            whiptail --title "✅ Routing Fixed" --msgbox "Routing has been fixed successfully!\n\nVM network routes are now properly configured.\nPort forwarding should work correctly now." 10 78
        else
            whiptail --title "⚠️ Warning" --msgbox "Configuration updated but route may not be active.\nPlease check 'ip route show' and restart WireGuard if needed." 8 78
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
    # Add '|| true' to prevent the script from exiting if wg show fails (e.g., interface is down)
    wg_status=$(wg show 2>&1 || true)
    if [ -z "$wg_status" ]; then
        wg_status="WireGuard interface (wg0) is not active or does not exist."
    fi
    
    # Also show routing information for VPS installations
    if [ -f /etc/wireguard/vps_private.key ]; then
        vm_route_status=""
        if ip route show | grep -q "10.99.0.0/16 dev wg0"; then
            vm_route_status="\n\n✅ VM Network Routing: CONFIGURED"
        else
            vm_route_status="\n\n❌ VM Network Routing: MISSING\n(Use 'Fix Routing Issues' option if port forwarding doesn't work)"
        fi
        wg_status="${wg_status}${vm_route_status}"
    fi
    
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
            # VPS Server cleanup
            whiptail --title "Uninstalling..." --infobox "Cleaning up VPS server configuration..." 8 78
            if [ -f /etc/wireguard/wirewarp.conf ]; then
                source /etc/wireguard/wirewarp.conf
                iptables -t nat -F PREROUTING 2>/dev/null || true
            fi
            apt-get purge -y wireguard netfilter-persistent >/dev/null
            rm -rf /etc/wireguard
            whiptail --title "Info" --msgbox "VPS cleanup complete." 8 78
        elif [ -f /etc/wireguard/wg0.conf ]; then
            # Client cleanup (Proxmox or other client)
            whiptail --title "Uninstalling..." --infobox "Cleaning up client configuration..." 8 78
            
            # Remove bridge configurations from /etc/network/interfaces
            sed -i '/# WireWarp Bridge for vmbr1/,/^$/d' /etc/network/interfaces 2>/dev/null || true
            sed -i '/# WireWarp Tunnel Bridge - Start/,/# WireWarp Tunnel Bridge - End/d' /etc/network/interfaces 2>/dev/null || true
            
            # Try to bring down common bridge names
            for bridge in vmbr1 vmbr2 vmbr3; do
                ifdown "$bridge" >/dev/null 2>&1 || true
            done
            
            # Remove iptables NAT rules related to WireWarp
            iptables-save | grep -v "POSTROUTING.*10\.99\." | iptables-restore 2>/dev/null || true
            
            apt-get purge -y wireguard iptables-persistent >/dev/null 2>&1 || true
            rm -rf /etc/wireguard
            whiptail --title "Info" --msgbox "Client cleanup complete. A reboot is recommended to fully clean network configuration." 8 78
        else
            # Generic cleanup if no specific installation type detected
            whiptail --title "Uninstalling..." --infobox "Performing generic WireGuard cleanup..." 8 78
            apt-get purge -y wireguard iptables-persistent netfilter-persistent >/dev/null 2>&1 || true
            rm -rf /etc/wireguard
            whiptail --title "Info" --msgbox "Generic cleanup complete. Please manually check for any remaining configuration files." 8 78
        fi
    fi
}

# --- Main Menu ---
check_root
install_packages whiptail
cleanup_corrupted_files  # Clean up any corrupted files from previous failed runs

while true; do
  CHOICE=$(whiptail --title "WireWarp - Multi-Tunnel Manager" --menu "What do you want to do?" 22 78 8 \
    "1" "[VPS] Initialize Server" \
    "2" "[VPS] Add New Peer" \
    "3" "[VPS] Remove Peer" \
    "4" "[VPS] Manage Ports for a Peer" \
    "5" "[VPS] View Ports for a Peer" \
    "6" "[VPS] Fix Routing Issues" \
    "7" "[All] Check Tunnel Status" \
    "8" "[All] Uninstall WireWarp" 3>&2 2>&1 1>&3)
  
  case $CHOICE in
    1) vps_init ;;
    2) add_peer_vps ;;
    3) remove_peer_vps ;;
    4) manage_ports_vps ;;
    5) view_ports_vps ;;
    6) fix_routing ;;
    7) check_status ;;
    8) uninstall ;;
    *) break ;; # Exit on Esc/Cancel
  esac
done 
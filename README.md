# WireWarp

WireWarp is an interactive script to set up a robust, NAT-based WireGuard server that can manage multiple client tunnels. This allows virtual machines on different remote networks to have all of their traffic securely routed through the public IP of a central VPS.

## Architecture

This architecture uses a standard NAT-based approach that is simple, secure, and universally compatible.

1.  **WireWarp Server (VPS):** Runs the main WireGuard service and a management script. It dynamically adds and removes clients (peers).
2.  **WireWarp Client (e.g., Proxmox Host):** Runs a simple, non-interactive script to configure itself as a peer to the server. It acts as a router for its local VMs.
3.  **Windows VM:** Is configured with a private IP address and uses its local Proxmox host as its gateway.

## How to Use

The project now consists of two scripts:
*   `wirewarp.sh`: The interactive management script for your central VPS.
*   `wirewarp-client.sh`: The non-interactive setup script for your client machines.

### Server Setup (VPS)
Run the interactive script on your central VPS. It will guide you through the process.
```bash
sudo bash -c "$(curl -fsSL https://gitea.step1.ro/step1nu/wirewarp/raw/branch/main/wirewarp.sh)"
```

1.  **Initialize Server (Option 1):** Run this once to set up the main WireGuard service on your VPS. It will display the server's public key, which you will need when adding clients.
2.  **Add New Peer (Option 2):** Run this for every new client (e.g., every Proxmox host) you want to connect.
    *   It will ask for a name for the peer.
    *   It will then generate and display a **single command** for you to run on your client machine. This command contains all the necessary keys and IP addresses.

### Client Setup (Proxmox Host)
1.  **Run the Command:** After adding a peer on the server, copy the complete command that the server script provides you. It will look something like this:
    ```bash
    bash -c "$(curl ...)" -- '<private_key>' '<tunnel_ip>' ...
    ```
2.  **Execute it** on your Proxmox host (or other client machine). You will need to replace `YOUR_VPS_IP_OR_HOSTNAME` with the actual public IP of your VPS.
3.  The client script will automatically configure the WireGuard interface and the local network bridge.

### Windows VM Setup
After the client setup is complete, configure your Windows VM with the IP addresses that the server script provided you when you added the peer. The settings will be:
*   **IP address:** `10.99.X.2`
*   **Subnet mask:** `255.255.255.0`
*   **Default gateway:** `10.99.X.1`
*   **Preferred DNS server:** `1.1.1.1`
*   Ensure any other network adapters have **no gateway** set.

### Operations
*   **[VPS] Manage Forwarded Ports (Option 4):** Add or remove port forwarding rules for your VM.
*   **[VPS] View Forwarded Ports (Option 5):** Display a list of all currently active port forwarding rules created by WireWarp.
*   **[All] Check Tunnel Status (Option 6):** Check the live status of the WireGuard interface.
*   **[All] Uninstall WireWarp (Option 7):** Completely remove all changes made by the script.

### Port Forwarding

To open ports for your game server, SSH into your **remote VPS** and use the helper script. The script can manage `tcp`, `udp`, or `both` protocols simultaneously.

**To add a port for both TCP and UDP (ideal for game servers):**
```bash
/usr/local/bin/manage-ports.sh add both 27016
```

**To add a single port:**
```bash
/usr/local/bin/manage-ports.sh add tcp 80
```

**To remove a port:**
```bash
/usr/local/bin/manage-ports.sh remove both 27016
``` 
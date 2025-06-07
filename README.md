# WireWarp

WireWarp is an interactive script to set up a robust, NAT-based WireGuard tunnel. This allows a virtual machine (e.g., a Windows VM on Proxmox) on a local network to have all of its traffic routed through the public IP of a remote VPS. This is ideal for hosting game servers or other services from home.

## Architecture (Final)

This new, more stable architecture uses a standard NAT-based approach that is simpler and avoids platform-specific networking bugs.

1.  **Remote VPS (Ubuntu):** Runs a WireGuard server. All traffic from the tunnel is NAT'd, and it forwards specific ports to the Windows VM's private IP address.
2.  **Proxmox Host (Debian-based):** Runs a WireGuard client and acts as a simple router for the Windows VM. It gives the VM internet access via the tunnel.
3.  **Windows VM:** Has two network interfaces.
    *   **NIC 1 (WAN):** Connected to a private Proxmox bridge (`vmbr1`). It has a private IP address and uses the Proxmox host as its gateway. All its traffic goes through the tunnel.
    *   **NIC 2 (LAN):** Connected to your main Proxmox bridge (`vmbr0`). This provides access to your local network for RDP and file sharing.

## How to Use

To run the script, use the following command. It needs to be run with root privileges.

*   On systems that use `sudo` (like Ubuntu):
    ```bash
    sudo bash -c "$(curl -fsSL https://gitea.step1.ro/step1nu/wirewarp/raw/branch/main/wirewarp.sh)"
    ```

*   On systems where you are already `root` (like Proxmox):
    ```bash
    bash -c "$(curl -fsSL https://gitea.step1.ro/step1nu/wirewarp/raw/branch/main/wirewarp.sh)"
    ```

The script will launch a menu-driven interface.

### Setup Workflow
1.  **[Uninstall First]** Run the script on both the Proxmox host and the VPS and choose **Option 6: Uninstall WireWarp** to ensure a clean state.
2.  **[VPS] Step 1: Initialize VPS** - Run option `1` on your remote VPS to generate its keys.
3.  **[Proxmox] Step 2: Initialize Proxmox Host** - Run option `2` on your Proxmox host. This will create the `vmbr1` bridge and configure the tunnel.
4.  **[VPS] Step 3: Complete VPS Setup** - Run option `3` on your VPS. This will link the two peers and start the tunnel. At the end, it will display the correct network settings for your Windows VM.

### Windows VM Setup

After the tunnel is active, configure your Windows VM according to the instructions displayed at the end of Step 3. The settings will be:

*   **Primary Network Card (the one on `vmbr1`):**
    *   **IP address:** `10.99.0.2`
    *   **Subnet mask:** `255.255.255.0`
    *   **Default gateway:** `10.99.0.1`
    *   **Preferred DNS server:** `1.1.1.1` (or your choice)

*   **Secondary Network Card (the one on `vmbr0` for RDP):**
    *   Configure with a static IP from your local LAN (e.g., `192.168.20.32`).
    *   Leave the **Default gateway** field **blank**.

### Operations
*   **[VPS] Manage Forwarded Ports (Option 4):** Add or remove port forwarding rules for your VM.
*   **[All] Check Tunnel Status (Option 5):** Check the live status of the WireGuard interface.
*   **[All] Uninstall WireWarp (Option 6):** Completely remove all changes made by the script.

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
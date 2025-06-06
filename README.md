# WireGuard Transparent Tunnel for Game Servers

This project provides an interactive script to set up a transparent network tunnel. This allows a virtual machine (e.g., a Windows VM on Proxmox) on a local network to use the public IP address of a remote VPS. This is ideal for hosting game servers or other services from home, behind a NAT, while appearing to have a static public IP.

## Architecture

The setup consists of three main components:

1.  **Remote VPS (Ubuntu):** Runs a WireGuard server and handles port forwarding.
2.  **Proxmox Host (Debian-based):** Runs a WireGuard client and provides a dedicated network bridge to the VM.
3.  **Windows VM:** Has two network interfaces—one for the tunnel (WAN) and one for the local network (LAN).

<br/>

![WireGuard Transparent Tunnel Architecture](https://mermaid.ink/svg/eyJjb2RlIjoiZ3JhcGggVEQ7XG4gICAgc3ViZ3JhcGggXCJJbnRlcm5ldFwiXG4gICAgICAgIFVzZXJzKFwiR2FtZSBQbGF5ZXJzIC8gVXNlcnNcIik7XG4gICAgZW5kXG5cbiAgICBzdWJncmFwaCBcIlJlbW90ZSBWUFNcIlxuICAgICAgICBkaXJlY3Rpb24gTFI7XG4gICAgICAgIFZQU19JUFtcIlB1YmxpYyBJUFxcbihWUFNfUFVCTElDX0lQKSlcIl07XG4gICAgICAgIFdHX1NlcnZlcltcIldpcmVHdWFyZCBTZXJ2ZXIgKHdnMClcXG4xMC4wLjAuMS8yNFwiXTtcbiAgICAgICAgSVBUYWJsZXNbXCJGaXJld2FsbCAvIE5BVFxcbihQb3J0IEZvcndhcmRpbmcpXCJdO1xuICAgICAgICBWUFNfSVAgLS0gXCJldGgwXCIgLS0-IElQVGFibGVzO1xuICAgICAgICBJUFRhYmxlcyAtLSAgXCJGb3J3YXJkaW5nXCIgLS0-IFdHX1NlcnZlcjtcbiAgICBlbmRcblxuICAgIHN1YmdyYXBoIFwiWW91ciBIb21lIE5ldHdvcmtcIlxuICAgICAgICBkaXJlY3Rpb24gTFI7XG4gICAgICAgIFByb3htb3hfSVBbXCJIb21lIFB1YmxpYyBJUFxcbihQUk9YTU9YX1BVQkxJQ19JUCkpXCJdO1xuICAgICAgICBcbiAgICAgICAgc3ViZ3JhcGggXCJQcm94bW94IEhvc3RcIlxuICAgICAgICAgICAgV0dfQ2xpZW50W1wiV2lyZUd1YXJkIENsaWVudCAod2cwKVxcbjEwLjAuMC4yLzI0XCJdO1xuICAgICAgICAgICAgQnJpZGdlX1dHW1wiTGludXggQnJpZGdlICh2bWJyMSlcIl07XG4gICAgICAgICAgICBCcmlkZ2VfTEFOW1wiTGludXggQnJpZGdlICh2bWJyMClcIl07XG4gICAgICAgICAgICBcbiAgICAgICAgICAgIFdHX0NsaWVudCAtLSAgXCJSb3V0ZXMgdHJhZmZpY1wiIC0tPiBCcmlkZ2VfV0c7XG4gICAgICAgIGVuZFxuXG4gICAgICAgIHN1YmdyYXBoIFwiV2luZG93cyBWTVwiXG4gICAgICAgICAgICBOSUNfV0FOXFwiTklDIDEgKFdBTilcXG5JUDogVlBTX1BVQkxJQ19JUFxcbkdXOiAxMC4wLjAuMVwiXTtcbiAgICAgICAgICAgIE5JQ19MQU5bXCJOSUMgMiAoTEFOKVxcbklQOiAxOTIuMTY4LjEueFxcbk5vIEdhdGV3YXlcIl07XG4gICAgICAgIGVuZFxuXG4gICAgICAgIFByb3htb3hfSVAgLS0gXCJJbnRlcm5ldFwiIC0tPiBCcmlkZ2VfTEFOO1xuICAgICAgICBCcmlkZ2VfTEFOIC0tIFwidmV0aFwiIC0tPiBOSUNfTEFOO1xuICAgICAgICBCcmlkZ2VfV0cgLS0gXCJ2ZXRoXCIgLS0-IE5JQ19XQU47XG4gICAgZW5kXG5cbiAgICBVc2VycyAtLSAgXCJUQ1AvVURQIFRyYWZmaWNcIiAtLT4gVlBTX0lQO1xuICAgIFdHX1NlcnZlciAtLSAgXCJXaXJlR3VhcmQgVHVubmVsXCIgLS0-IFdHX0NsaWVudDtcbiAgICBOSUNfV0FOIC0tIFwiQWxsIEludGVybmV0IFRyYWZmaWNcIiAtLT4gQnJpZGdlX1dHO1xuICAgIE5JQ19MQU4gLS0gXCJMb2NhbCBBY2Nlc3NcIiAtLT4gQnJpZGdlX0xBTjtcbiIsIm1lcm1haWQiOnsidGhlbWUiOiJkZWZhdWx0In0sInVwZGF0ZUVkaXRvciI6ZmFsc2UsImF1dG9TeW5jIjp0cnVlLCJ1cGRhdGVEaWFncmFtIjpmYWxzZX0)

## How to Use

This project now uses a single, interactive script. You can run it directly from your Gitea server or any shell using `curl`.

**Run the script using:**
```bash
curl -sSL https://gitea.step1.ro/step1nu/wirewarp/raw/branch/main/wirewarp.sh | sudo bash
```

The script will present a menu. Follow the steps in order:

### Step 1: Initialize VPS
*   Run the script on your **remote Ubuntu VPS**.
*   Choose option `1`.
*   The script will install WireGuard, generate keys, and output the **VPS Public Key**.
*   **Copy the public key.** You'll need it for the next step.

### Step 2: Initialize Proxmox Host
*   Run the same script on your **local Proxmox host**.
*   Choose option `2`.
*   The script will ask you for:
    *   Your VPS's public IP or DDNS hostname.
    *   The VPS public key you just copied.
    *   The VPS public IP again (this is used to configure the firewall rules).
*   It will then configure the Proxmox side of the tunnel and output the **Proxmox Public Key**.
*   **Copy this public key.** A reboot of Proxmox is recommended after this step.

### Step 3: Complete VPS Setup
*   Run the script one last time on your **remote Ubuntu VPS**.
*   Choose option `3`.
*   The script will ask you for:
    *   The Proxmox public key you just copied.
    *   Your Proxmox server's public IP or DDNS hostname.
    *   Your VPS's public IP address.
*   It will create the final WireGuard configuration, install a port management helper script, and start the tunnel.

Your tunnel is now active!

### Windows VM Setup

After the scripts are done, configure your Windows VM:
1.  Add a second network device to the VM, connected to the new `vmbr1` bridge.
2.  Statically configure the IP address of this new network card to be the **public IP of your VPS**, with a gateway of `10.0.0.1`.
3.  Ensure your LAN-facing network card in the VM has **no gateway** set.

### Port Forwarding

To open ports for your game server, SSH into your **remote VPS** and use the helper script.

**To add a port:**
```bash
/usr/local/bin/manage-ports.sh add tcp 27016
```

**To remove a port:**
```bash
/usr/local/bin/manage-ports.sh remove tcp 27016
``` 
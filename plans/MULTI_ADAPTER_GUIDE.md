# Multi-Adapter Setup Guide
**Using Multiple Public IPs for Different Services on One Windows VM**

---

## Use Case

Run multiple services (e.g., 2+ DayZ servers, multiple game servers, web apps) on a single Windows VM, each with its own public IP address for:
- **Isolation:** One service getting DDoSed doesn't affect others
- **Port reuse:** Run multiple servers on the same port (e.g., 2302) with different IPs
- **Load distribution:** Spread bandwidth across multiple VPS IPs
- **Better reputation:** Gaming traffic separate from web traffic

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    VPS (Multi-IP)                       │
│  Public IP 1: 1.2.3.4  │  Public IP 2: 1.2.3.5         │
│         ↓              │         ↓                       │
│    WireWarp Peer 1     │    WireWarp Peer 2            │
│    (10.99.1.0/24)      │    (10.99.2.0/24)             │
└──────────┬─────────────┴──────────┬────────────────────┘
           │                        │
           │ WireGuard Tunnel       │ WireGuard Tunnel
           │                        │
┌──────────┴────────────────────────┴────────────────────┐
│              Proxmox Host                              │
│  wg0 → vmbr1           │  wg1 → vmbr2                  │
│  (10.99.1.1)           │  (10.99.2.1)                  │
└──────────┬─────────────┴──────────┬────────────────────┘
           │                        │
           │                        │
┌──────────┴────────────────────────┴────────────────────┐
│               Windows VM                               │
│                                                         │
│  Adapter 1 (vmbr1)         Adapter 2 (vmbr2)           │
│  IP: 10.99.1.2             IP: 10.99.2.2               │
│  Gateway: 10.99.1.1        Gateway: (none)             │
│                                                         │
│  ┌────────────────┐         ┌────────────────┐         │
│  │ DayZ Server 1  │         │ DayZ Server 2  │         │
│  │ Bind: 10.99.1.2│         │ Bind: 10.99.2.2│         │
│  │ Port: 2302     │         │ Port: 2302     │         │
│  └────────────────┘         └────────────────┘         │
└─────────────────────────────────────────────────────────┘

Result:
Players connect to 1.2.3.4:2302 → DayZ Server 1
Players connect to 1.2.3.5:2302 → DayZ Server 2
(Same port, different IPs!)
```

---

## Prerequisites

1. **VPS with Multiple Public IPs**
   - Most VPS providers offer additional IPs for $1-3/month each
   - Ensure all IPs are assigned to the same network interface (or different ones)
   - Common providers: Hetzner, OVH, DigitalOcean, Vultr

2. **WireWarp Multi-IP Support**
   - Requires Phase 1 implementation (see IMPROVEMENT_PLAN.md)
   - VPS must be configured to manage IP pools

3. **Proxmox Host**
   - Sufficient resources to run multiple WireGuard tunnels
   - Multiple bridge interfaces available (vmbr1, vmbr2, etc.)

4. **Windows VM**
   - Multiple virtual network adapters
   - Sufficient resources for multiple game servers

---

## Step-by-Step Setup

### **Step 1: Configure VPS with Multiple IPs**

#### 1.1 Add Public IPs to VPS
Most providers allow you to assign additional IPs via their control panel. After assignment, configure the network interface:

**On Debian/Ubuntu VPS:**
```bash
# Check current IPs
ip addr show

# If using single interface with multiple IPs:
# Edit /etc/network/interfaces
auto eth0
iface eth0 inet static
    address 1.2.3.4
    netmask 255.255.255.0
    gateway 1.2.3.1

auto eth0:1
iface eth0:1 inet static
    address 1.2.3.5
    netmask 255.255.255.0

# Restart networking
systemctl restart networking

# Verify
ip addr show eth0
```

#### 1.2 Initialize WireWarp with Multi-IP Support
```bash
# Run wirewarp.sh
sudo bash wirewarp.sh

# Option 1: Initialize Server
# When prompted, enter all available public IPs:
#   - Primary IP: 1.2.3.4 (eth0)
#   - Additional IPs: 1.2.3.5 (eth0:1)

# This creates IP pool configuration
```

---

### **Step 2: Create WireWarp Peers (One per VM Adapter)**

#### 2.1 Add First Peer (for Adapter 1)
```bash
sudo bash wirewarp.sh

# Option 2: Add New Peer
#   - Peer name: windows_vm_adapter1
#   - Assign to IP: 1.2.3.4 (select from pool)

# Output will show:
#   - Tunnel IP: 10.0.0.2
#   - VM Network: 10.99.1.0/24
#   - VM Gateway: 10.99.1.1
#   - VM Private IP: 10.99.1.2
#   - Client setup command (save this!)
```

**Example client command:**
```bash
bash -c "$(curl -fsSL https://example.com/wirewarp-client-multi.sh)" -- \
  '<private_key_1>' \
  '10.0.0.2' \
  '<server_public_key>' \
  'YOUR_VPS_IP:51820' \
  '10.99.1.1' \
  '1.1.1.1' \
  'vmbr1' \
  '0'  # ← Tunnel ID (0 = wg0)
```

#### 2.2 Add Second Peer (for Adapter 2)
```bash
sudo bash wirewarp.sh

# Option 2: Add New Peer
#   - Peer name: windows_vm_adapter2
#   - Assign to IP: 1.2.3.5 (select from pool)

# Output will show:
#   - Tunnel IP: 10.0.0.3
#   - VM Network: 10.99.2.0/24
#   - VM Gateway: 10.99.2.1
#   - VM Private IP: 10.99.2.2
#   - Client setup command (save this!)
```

**Example client command:**
```bash
bash -c "$(curl -fsSL https://example.com/wirewarp-client-multi.sh)" -- \
  '<private_key_2>' \
  '10.0.0.3' \
  '<server_public_key>' \
  'YOUR_VPS_IP:51820' \
  '10.99.2.1' \
  '1.1.1.1' \
  'vmbr2' \
  '1'  # ← Tunnel ID (1 = wg1)
```

---

### **Step 3: Setup Multiple Tunnels on Proxmox**

**Important:** Current `wirewarp-client.sh` only supports ONE tunnel. Use the enhanced script below or run manually.

#### 3.1 Setup First Tunnel (wg0 → vmbr1)
```bash
# On Proxmox host
curl -fsSL https://example.com/wirewarp-client-multi.sh | bash -s -- \
  '<private_key_1>' \
  '10.0.0.2' \
  '<server_public_key>' \
  'YOUR_VPS_IP:51820' \
  '10.99.1.1' \
  '1.1.1.1' \
  'vmbr1' \
  '0'
```

This creates:
- `/etc/wireguard/wg0.conf`
- Network bridge `vmbr1` with IP 10.99.1.1
- Enabled and started `wg-quick@wg0` service

#### 3.2 Setup Second Tunnel (wg1 → vmbr2)
```bash
# On Proxmox host
curl -fsSL https://example.com/wirewarp-client-multi.sh | bash -s -- \
  '<private_key_2>' \
  '10.0.0.3' \
  '<server_public_key>' \
  'YOUR_VPS_IP:51820' \
  '10.99.2.1' \
  '1.1.1.1' \
  'vmbr2' \
  '1'
```

This creates:
- `/etc/wireguard/wg1.conf`
- Network bridge `vmbr2` with IP 10.99.2.1
- Enabled and started `wg-quick@wg1` service

#### 3.3 Verify Tunnels
```bash
# Check WireGuard status
wg show wg0
wg show wg1

# Check bridges
ip addr show vmbr1
ip addr show vmbr2

# Test connectivity
ping -c 3 10.0.0.1  # VPS tunnel IP
```

---

### **Step 4: Configure Windows VM with Multiple Adapters**

#### 4.1 Add Network Adapters in Proxmox
1. Open Proxmox web interface
2. Select your Windows VM
3. Go to **Hardware** tab
4. Click **Add** → **Network Device**
   - Bridge: `vmbr1`
   - Model: `VirtIO` (or `E1000` for compatibility)
   - Firewall: (optional)
5. Click **Add** → **Network Device** again
   - Bridge: `vmbr2`
   - Model: `VirtIO`
6. Start the VM

#### 4.2 Install VirtIO Drivers in Windows (if needed)
If using VirtIO network adapters:
1. Download VirtIO drivers: https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/
2. Install drivers
3. Reboot Windows VM

#### 4.3 Configure Network Adapters in Windows

**Open Network Connections:**
- Press `Win + R`, type `ncpa.cpl`, press Enter

**Configure Adapter 1 (Ethernet):**
1. Right-click → Properties
2. Select **Internet Protocol Version 4 (TCP/IPv4)** → Properties
3. Select **Use the following IP address:**
   - IP address: `10.99.1.2`
   - Subnet mask: `255.255.255.0`
   - Default gateway: `10.99.1.1`
   - Preferred DNS: `1.1.1.1`
4. Click OK

**Configure Adapter 2 (Ethernet 2):**
1. Right-click → Properties
2. Select **Internet Protocol Version 4 (TCP/IPv4)** → Properties
3. Select **Use the following IP address:**
   - IP address: `10.99.2.2`
   - Subnet mask: `255.255.255.0`
   - Default gateway: **LEAVE BLANK** ⚠️
   - DNS: **LEAVE BLANK** ⚠️
4. Click OK

**⚠️ Critical:** Only Adapter 1 should have a default gateway. Otherwise, Windows will have routing conflicts.

#### 4.4 Advanced Routing Configuration (Optional)

If you need both adapters to route traffic independently:

**Open PowerShell as Administrator:**
```powershell
# Show current routes
Get-NetRoute

# Add route for traffic from 10.99.2.2 to use Adapter 2
New-NetRoute -DestinationPrefix 0.0.0.0/0 `
  -InterfaceAlias "Ethernet 2" `
  -NextHop 10.99.2.1 `
  -RouteMetric 10

# Set route metric (lower = higher priority)
# Adapter 1 should have lower metric (default route)
Set-NetIPInterface -InterfaceAlias "Ethernet" -InterfaceMetric 1
Set-NetIPInterface -InterfaceAlias "Ethernet 2" -InterfaceMetric 10
```

---

### **Step 5: Configure Applications to Bind to Specific IPs**

Most server applications allow binding to a specific IP address. This is the **easiest and most reliable** method.

#### 5.1 DayZ Server Example

**Server 1 Configuration (serverDZ_1.cfg):**
```
hostname = "My DayZ Server 1 - PvE";
password = "";
passwordAdmin = "adminpass";
maxPlayers = 60;

// CRITICAL: Bind to Adapter 1 IP
ip = "10.99.1.2";
port = 2302;

// Additional ports (Steam query, etc.)
steamQueryPort = 2303;
```

**Server 2 Configuration (serverDZ_2.cfg):**
```
hostname = "My DayZ Server 2 - PvP";
password = "";
passwordAdmin = "adminpass";
maxPlayers = 60;

// CRITICAL: Bind to Adapter 2 IP
ip = "10.99.2.2";
port = 2302;  // Same port, different IP!

steamQueryPort = 2303;
```

**Launch Scripts:**

**start_server1.bat:**
```batch
@echo off
cd /d "C:\DayZServer"
start "DayZ Server 1" /high DayZServer_x64.exe ^
  -config=serverDZ_1.cfg ^
  -port=2302 ^
  -profiles=ServerProfiles1 ^
  -dologs ^
  -adminlog ^
  -netlog ^
  -freezecheck
```

**start_server2.bat:**
```batch
@echo off
cd /d "C:\DayZServer"
start "DayZ Server 2" /high DayZServer_x64.exe ^
  -config=serverDZ_2.cfg ^
  -port=2302 ^
  -profiles=ServerProfiles2 ^
  -dologs ^
  -adminlog ^
  -netlog ^
  -freezecheck
```

#### 5.2 Minecraft Server Example

**Server 1 (server1.properties):**
```properties
server-ip=10.99.1.2
server-port=25565
```

**Server 2 (server2.properties):**
```properties
server-ip=10.99.2.2
server-port=25565
```

#### 5.3 Generic Application (Command Line)

Many applications support binding via command line:
```bash
# Web server
nginx -c /etc/nginx/nginx1.conf  # Listen on 10.99.1.2:80
nginx -c /etc/nginx/nginx2.conf  # Listen on 10.99.2.2:80

# Node.js
node server.js --host=10.99.1.2 --port=3000
node server.js --host=10.99.2.2 --port=3000

# Python Flask
flask run --host=10.99.1.2 --port=5000
flask run --host=10.99.2.2 --port=5000
```

#### 5.4 Windows Firewall Configuration

**Allow traffic on both adapters:**
```powershell
# Allow DayZ Server 1 on Adapter 1
New-NetFirewallRule -DisplayName "DayZ Server 1" `
  -Direction Inbound `
  -LocalAddress 10.99.1.2 `
  -LocalPort 2302-2305 `
  -Protocol UDP `
  -Action Allow

# Allow DayZ Server 2 on Adapter 2
New-NetFirewallRule -DisplayName "DayZ Server 2" `
  -Direction Inbound `
  -LocalAddress 10.99.2.2 `
  -LocalPort 2302-2305 `
  -Protocol UDP `
  -Action Allow
```

---

### **Step 6: Configure Port Forwarding on VPS**

#### 6.1 Forward Ports for Server 1 (IP 1.2.3.4 → 10.99.1.2)
```bash
# On VPS
sudo bash wirewarp.sh

# Option 4: Manage Ports for a Peer
#   - Select peer: windows_vm_adapter1
#   - Action: add
#   - Protocol: both (TCP + UDP)
#   - Ports: 2302-2305
```

This creates iptables rules:
```bash
iptables -t nat -A PREROUTING -i eth0 -d 1.2.3.4 -p udp --dport 2302 -j DNAT --to-destination 10.99.1.2
iptables -t nat -A PREROUTING -i eth0 -d 1.2.3.4 -p udp --dport 2303 -j DNAT --to-destination 10.99.1.2
# ... etc
```

#### 6.2 Forward Ports for Server 2 (IP 1.2.3.5 → 10.99.2.2)
```bash
# On VPS
sudo bash wirewarp.sh

# Option 4: Manage Ports for a Peer
#   - Select peer: windows_vm_adapter2
#   - Action: add
#   - Protocol: both
#   - Ports: 2302-2305
```

This creates iptables rules:
```bash
iptables -t nat -A PREROUTING -i eth0 -d 1.2.3.5 -p udp --dport 2302 -j DNAT --to-destination 10.99.2.2
iptables -t nat -A PREROUTING -i eth0 -d 1.2.3.5 -p udp --dport 2303 -j DNAT --to-destination 10.99.2.2
# ... etc
```

#### 6.3 Verify Port Forwarding
```bash
# On VPS, check NAT rules
iptables -t nat -L PREROUTING -n -v | grep DNAT

# Should show rules for both IPs:
# ... to:10.99.1.2 (for 1.2.3.4)
# ... to:10.99.2.2 (for 1.2.3.5)
```

---

## Testing & Verification

### Test 1: Network Connectivity
**On Windows VM:**
```powershell
# Test Adapter 1
Test-NetConnection -ComputerName 8.8.8.8 -SourceAddress 10.99.1.2

# Test Adapter 2
Test-NetConnection -ComputerName 8.8.8.8 -SourceAddress 10.99.2.2
```

### Test 2: Check Public IPs
**On Windows VM, open PowerShell:**
```powershell
# Check what public IP each adapter sees
# Using curl to ifconfig.me

# Adapter 1
curl.exe --interface 10.99.1.2 ifconfig.me
# Should return: 1.2.3.4

# Adapter 2
curl.exe --interface 10.99.2.2 ifconfig.me
# Should return: 1.2.3.5
```

### Test 3: Port Listening
**On Windows VM:**
```powershell
# Check if servers are listening on correct IPs
netstat -an | findstr "2302"

# Should show:
# UDP    10.99.1.2:2302         *:*
# UDP    10.99.2.2:2302         *:*
```

### Test 4: External Connectivity
**From external computer:**
```bash
# Test Server 1
nc -zvu 1.2.3.4 2302

# Test Server 2
nc -zvu 1.2.3.5 2302

# Or use game-specific tools
# DayZ: Check server browser
# Minecraft: Add server with IP:port
```

---

## Troubleshooting

### Issue: Windows Can't Reach Internet on Adapter 2

**Cause:** No default gateway on Adapter 2

**Solution:** This is intentional. Adapter 2 should only be used for inbound connections or when applications explicitly bind to it.

**Alternative:** If you need Adapter 2 to have internet access:
```powershell
# Add specific route for Adapter 2
New-NetRoute -DestinationPrefix 0.0.0.0/0 `
  -InterfaceAlias "Ethernet 2" `
  -NextHop 10.99.2.1 `
  -RouteMetric 20  # Higher than Adapter 1's metric
```

### Issue: Application Ignores IP Binding

**Cause:** Some applications don't support IP binding or ignore the setting

**Solution:** Use Windows Firewall or routing rules to force traffic:
```powershell
# Force application to use specific adapter
# (Advanced, requires third-party tools like ForceBindIP)
```

### Issue: Port Forwarding Not Working

**Symptoms:** Players can't connect, ports appear closed

**Diagnosis:**
```bash
# On VPS, check iptables
iptables -t nat -L PREROUTING -n -v | grep <port>

# On Proxmox, check WireGuard
wg show wg0
wg show wg1

# On Windows, check firewall
Get-NetFirewallRule | Where-Object {$_.LocalPort -eq 2302}
```

**Common Fixes:**
1. Ensure Windows Firewall allows the port
2. Verify application is actually listening (`netstat -an`)
3. Check WireGuard tunnel is up (`wg show`)
4. Verify iptables rules on VPS

### Issue: VMs Can Communicate with Each Other (Shouldn't)

**Cause:** WireGuard AllowedIPs includes entire 10.99.0.0/16 network

**Solution:** Modify WireGuard config on Proxmox to isolate peers:
```bash
# In /etc/wireguard/wg0.conf
AllowedIPs = 10.0.0.0/24, 10.99.1.0/24  # Only peer 1's network
# NOT: AllowedIPs = 10.0.0.0/24, 10.99.0.0/16
```

### Issue: High Latency or Packet Loss

**Diagnosis:**
```bash
# On Proxmox
ping -I wg0 10.0.0.1
ping -I wg1 10.0.0.1

# Check WireGuard stats
wg show wg0 | grep handshake
wg show wg1 | grep handshake
```

**Possible Causes:**
- VPS overloaded
- Network congestion
- MTU issues (try setting MTU=1420 in WireGuard config)

---

## Advanced Configurations

### Configuration 1: More Than 2 Adapters

**Scenario:** Run 4 game servers, each with unique public IP

**Setup:**
- VPS: 4 public IPs (1.2.3.4, 1.2.3.5, 1.2.3.6, 1.2.3.7)
- Proxmox: 4 tunnels (wg0-wg3), 4 bridges (vmbr1-vmbr4)
- Windows: 4 network adapters

**Limits:**
- Proxmox: No practical limit (100+ tunnels possible)
- Windows: Supports many adapters (64+)
- VPS: Depends on provider (usually 4-16 IPs available)

### Configuration 2: Multiple VMs Sharing IPs

**Scenario:** 2 Windows VMs, each using 2 different IPs

**Setup:**
```
VPS IPs: 1.2.3.4, 1.2.3.5
  ↓         ↓
Peer1    Peer2
(VM1A)   (VM1B)  ← Windows VM 1, 2 adapters
  ↓         ↓
Peer3    Peer4
(VM2A)   (VM2B)  ← Windows VM 2, 2 adapters
```

Result:
- VM1 Adapter A: Uses 1.2.3.4
- VM1 Adapter B: Uses 1.2.3.5
- VM2 Adapter A: Uses 1.2.3.4 (same IP, different ports!)
- VM2 Adapter B: Uses 1.2.3.5

### Configuration 3: IPv6 Support

**When implemented (see IMPROVEMENT_PLAN.md Phase 8):**
- Each adapter can have both IPv4 and IPv6
- Dual-stack game servers
- Better connectivity for IPv6-native clients

---

## Performance Considerations

### Bandwidth

**Per-Tunnel Overhead:**
- WireGuard: ~60-100 bytes per packet
- Negligible CPU overhead (1-5%)

**Bottlenecks:**
- VPS bandwidth limit (usually 1-10 Gbps)
- Home internet upload (typically 10-100 Mbps)
- Proxmox host CPU (encryption)

**Optimization:**
- Use modern CPU with AES-NI for WireGuard
- Distribute bandwidth-heavy services across multiple IPs
- Monitor with `iftop` or `vnstat`

### Resource Usage

**VPS:**
- WireGuard: ~5-10 MB RAM per peer
- iptables: Minimal overhead
- 10 peers ≈ 100 MB RAM

**Proxmox:**
- Each tunnel: ~10-20 MB RAM
- 4 tunnels ≈ 80 MB RAM
- Negligible CPU when idle

**Windows VM:**
- Each adapter: ~10 MB RAM
- No significant CPU overhead

---

## Security Considerations

### Network Isolation

**Default:** Peers CAN communicate through VPS tunnel network (10.0.0.0/24)

**To isolate peers:**
```bash
# On VPS, in /etc/wireguard/wg0.conf
# Add after [Interface] section:
PostUp = iptables -A FORWARD -s 10.99.1.0/24 -d 10.99.2.0/24 -j DROP
PostUp = iptables -A FORWARD -s 10.99.2.0/24 -d 10.99.1.0/24 -j DROP
```

### Firewall Rules

**On Windows VM, block inter-adapter traffic:**
```powershell
# Prevent Adapter 1 from talking to Adapter 2's network
New-NetFirewallRule -DisplayName "Block Inter-Adapter" `
  -Direction Outbound `
  -LocalAddress 10.99.1.2 `
  -RemoteAddress 10.99.2.0/24 `
  -Action Block
```

### DDoS Protection

**Benefits of Multi-IP Setup:**
- One service getting attacked doesn't affect others
- Can disable/null-route single IP without taking down all services

**Additional Protection:**
- Use Cloudflare in front of web services
- VPS provider DDoS mitigation (OVH, Hetzner have built-in)
- Fail2ban for SSH

---

## Cost Analysis

### Example Setup: 2 DayZ Servers

**Hardware:**
- VPS: $5/mo (Hetzner CX21: 2 vCPU, 4GB RAM)
- Additional IP: $1/mo
- **Total VPS:** $6/mo

**Alternative (Dedicated Game Hosting):**
- 1 DayZ server: $15-30/mo
- 2 servers: $30-60/mo

**Savings:** $24-54/mo ($288-648/year)

**Pros of Self-Hosting:**
- Full control (mods, configs, restarts)
- Better performance (dedicated resources)
- Learn system administration skills

**Cons:**
- Initial setup time (2-4 hours)
- Maintenance required
- Need home hardware

---

## Future Enhancements

### When Web GUI is Implemented (Phase 5)

**Visual Network Designer:**
```
[Drag & Drop Interface]

VPS: 1.2.3.4    VPS: 1.2.3.5
    │               │
    ├─ Port 2302 ───┼─→ VM: 10.99.1.2 (DayZ 1)
    ├─ Port 80 ─────┼─→ VM: 10.99.1.2 (Web)
    │               │
                    └─→ Port 2302 → VM: 10.99.2.2 (DayZ 2)
```

**One-Click Setup:**
1. Select "Multi-Adapter VM"
2. Choose number of adapters
3. System auto-configures everything
4. Display network config for Windows

### When Agent is Implemented (Phase 4)

**Automatic Windows Configuration:**
- Agent on Windows VM
- Auto-detect network adapters
- One-click IP configuration
- Automatic application binding detection

---

## References

### WireGuard Documentation
- Official site: https://www.wireguard.com/
- Man page: `man wg`

### Proxmox Documentation
- Network configuration: https://pve.proxmox.com/wiki/Network_Configuration

### Windows Networking
- PowerShell network commands: `Get-Help *-Net*`
- Network interface configuration: `ncpa.cpl`

### DayZ Server Setup
- Bohemia Interactive wiki: https://community.bistudio.com/wiki/DayZ:Server_Configuration

---

## Support

For issues specific to this setup:
1. Check IMPROVEMENT_PLAN.md for roadmap
2. Open issue on GitHub
3. Join community Discord (when available)

---

**Document Version:** 1.0
**Last Updated:** 2025-10-14
**Status:** Pending implementation of multi-tunnel support

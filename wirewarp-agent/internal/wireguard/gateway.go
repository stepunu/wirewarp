package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	rtTablesPath = "/etc/iproute2/rt_tables"
	wgTableID    = "51820"
	replyTableID = "100"
	replyTableName = "tunnel"

	// ip rule priorities — lower value = higher precedence
	prioControlException = "99"  // control server bypass
	prioVPSException     = "100"
	prioLANException     = "200"
	prioForwardLAN    = "5000" // gateway mode only
	prioForwardSelf   = "5100"
	prioReplyMark     = "30000"
)

// GatewayConfig holds all the parameters needed to configure policy routing on a gateway client.
type GatewayConfig struct {
	TunnelIface    string // e.g. "wg0"
	LANIface       string // e.g. "eth0"
	VPSEndpointIP  string // public IP of the VPS (traffic to this stays on main table)
	VPSTunnelIP    string // VPS's tunnel IP, e.g. "10.0.0.1"
	GatewayTunnelIP string // this machine's tunnel IP, e.g. "10.0.0.3"
	GatewayLANIP   string // this machine's LAN IP, e.g. "192.168.20.110"
	LANNetwork     string // e.g. "192.168.20.0/24"
	IsGateway      bool   // if false, skip LAN-forwarding rules and Docker rules
	// ControlServerIP is the IP of the WireWarp control server. Traffic to this IP
	// must bypass the tunnel so the agent can maintain its WebSocket connection.
	ControlServerIP string
}

// ApplyGatewayRouting performs the full 7-step policy routing setup.
// It always flushes existing rules first to stay idempotent.
func ApplyGatewayRouting(cfg GatewayConfig) error {
	if err := ensureRTTable(); err != nil {
		return fmt.Errorf("rt_tables: %w", err)
	}
	if err := applySysctl(cfg.TunnelIface, cfg.LANIface); err != nil {
		return fmt.Errorf("sysctl: %w", err)
	}
	if err := flushRoutes(cfg); err != nil {
		return fmt.Errorf("flush routes: %w", err)
	}
	if err := flushIPRules(cfg); err != nil {
		return fmt.Errorf("flush ip rules: %w", err)
	}
	flushMangleRules(cfg.TunnelIface) // best-effort; ignore errors

	if err := applyRoutingTables(cfg); err != nil {
		return fmt.Errorf("routing tables: %w", err)
	}
	if err := applyIPRules(cfg); err != nil {
		return fmt.Errorf("ip rules: %w", err)
	}
	if err := applyMangleRules(cfg.TunnelIface); err != nil {
		return fmt.Errorf("mangle rules: %w", err)
	}
	if err := applyNATAndForwarding(cfg); err != nil {
		return fmt.Errorf("NAT/forwarding: %w", err)
	}
	if err := applyMSSClamping(cfg.TunnelIface); err != nil {
		return fmt.Errorf("MSS clamping: %w", err)
	}
	return nil
}

// TeardownGatewayRouting removes all rules and routes added by ApplyGatewayRouting.
func TeardownGatewayRouting(cfg GatewayConfig) error {
	flushRoutes(cfg)      //nolint:errcheck
	flushIPRules(cfg)     //nolint:errcheck
	flushMangleRules(cfg.TunnelIface)

	// Remove NAT MASQUERADE
	ipt("-t", "nat", "-D", "POSTROUTING", "-o", cfg.TunnelIface, "-j", "MASQUERADE")

	// Remove MSS clamping
	ipt("-t", "mangle", "-D", "POSTROUTING",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-o", cfg.TunnelIface, "-j", "TCPMSS", "--clamp-mss-to-pmtu")

	return nil
}

// --- step implementations ---

func ensureRTTable() error {
	if _, err := os.Stat(rtTablesPath); os.IsNotExist(err) {
		if err := os.MkdirAll("/etc/iproute2", 0755); err != nil {
			return err
		}
		content := "255 local\n254 main\n253 default\n0 unspec\n100 tunnel\n"
		return os.WriteFile(rtTablesPath, []byte(content), 0644)
	}

	data, err := os.ReadFile(rtTablesPath)
	if err != nil {
		return err
	}
	if !strings.Contains(string(data), replyTableID+" "+replyTableName) {
		f, err := os.OpenFile(rtTablesPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = fmt.Fprintf(f, "%s %s\n", replyTableID, replyTableName)
		return err
	}
	return nil
}

func applySysctl(tunnelIface, lanIface string) error {
	settings := [][]string{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.rp_filter", "0"},
		{"net.ipv4.conf.default.rp_filter", "0"},
		{"net.ipv4.conf." + lanIface + ".rp_filter", "0"},
		{"net.ipv4.conf." + tunnelIface + ".rp_filter", "0"},
	}
	for _, kv := range settings {
		out, err := exec.Command("sysctl", "-w", kv[0]+"="+kv[1]).CombinedOutput()
		if err != nil {
			return fmt.Errorf("sysctl -w %s=%s: %w — %s", kv[0], kv[1], err, out)
		}
	}
	return nil
}

func flushRoutes(cfg GatewayConfig) error {
	exec.Command("ip", "route", "flush", "table", wgTableID).Run()
	exec.Command("ip", "route", "flush", "table", replyTableName).Run()
	return nil
}

func flushIPRules(cfg GatewayConfig) error {
	for _, prio := range []string{prioControlException, prioVPSException, prioLANException, prioForwardLAN, prioForwardSelf, prioReplyMark, "1000", "2000"} {
		exec.Command("ip", "rule", "del", "priority", prio).Run()
	}
	return nil
}

func flushMangleRules(tunnelIface string) {
	ipt("-t", "mangle", "-D", "PREROUTING", "-i", tunnelIface, "-j", "MARK", "--set-mark", "0x1")
	ipt("-t", "mangle", "-D", "PREROUTING", "-i", tunnelIface, "-j", "CONNMARK", "--save-mark")
	ipt("-t", "mangle", "-D", "OUTPUT", "-j", "CONNMARK", "--restore-mark")
}

func applyRoutingTables(cfg GatewayConfig) error {
	// Outbound tunnel traffic table
	if err := ip("route", "add", "default", "dev", cfg.TunnelIface, "table", wgTableID); err != nil {
		return fmt.Errorf("add wg route table: %w", err)
	}
	// Reply traffic table — routes back via VPS tunnel IP
	if err := ip("route", "add", "default", "via", cfg.VPSTunnelIP, "dev", cfg.TunnelIface, "table", replyTableName); err != nil {
		return fmt.Errorf("add reply route table: %w", err)
	}
	return nil
}

func applyIPRules(cfg GatewayConfig) error {
	// Priority 100: VPS endpoint traffic stays on main table (prevents tunnel loop)
	if err := ip("rule", "add", "to", cfg.VPSEndpointIP, "table", "main", "priority", prioVPSException); err != nil {
		return err
	}
	// Priority 99: Control server traffic stays on main table (keeps WebSocket alive)
	if cfg.ControlServerIP != "" && cfg.ControlServerIP != cfg.VPSEndpointIP {
		if err := ip("rule", "add", "to", cfg.ControlServerIP, "table", "main", "priority", prioControlException); err != nil {
			return err
		}
	}
	// Priority 200: LAN traffic stays local
	if err := ip("rule", "add", "to", cfg.LANNetwork, "table", "main", "priority", prioLANException); err != nil {
		return err
	}
	// Priority 5000: Forward LAN devices through tunnel (gateway mode only)
	if cfg.IsGateway {
		if err := ip("rule", "add", "from", cfg.LANNetwork, "table", wgTableID, "priority", prioForwardLAN); err != nil {
			return err
		}
	}
	// Priority 5100: Forward this machine's own traffic through tunnel
	if err := ip("rule", "add", "from", cfg.GatewayTunnelIP, "table", wgTableID, "priority", prioForwardSelf); err != nil {
		return err
	}
	if err := ip("rule", "add", "from", cfg.GatewayLANIP, "table", wgTableID, "priority", prioForwardSelf); err != nil {
		return err
	}
	// Priority 30000: Return traffic marked by mangle rules goes back via tunnel
	if err := ip("rule", "add", "fwmark", "0x1", "table", replyTableName, "priority", prioReplyMark); err != nil {
		return err
	}
	return nil
}

func applyMangleRules(tunnelIface string) error {
	if err := iptE("-t", "mangle", "-A", "PREROUTING", "-i", tunnelIface, "-j", "MARK", "--set-mark", "0x1"); err != nil {
		return err
	}
	if err := iptE("-t", "mangle", "-A", "PREROUTING", "-i", tunnelIface, "-j", "CONNMARK", "--save-mark"); err != nil {
		return err
	}
	if err := iptE("-t", "mangle", "-A", "OUTPUT", "-j", "CONNMARK", "--restore-mark"); err != nil {
		return err
	}
	return nil
}

func applyNATAndForwarding(cfg GatewayConfig) error {
	// Allow all forwarded traffic
	if err := iptE("-P", "FORWARD", "ACCEPT"); err != nil {
		return err
	}
	// MASQUERADE outbound tunnel traffic
	if err := iptCheckOrInsert(
		[]string{"-t", "nat", "-C", "POSTROUTING", "-o", cfg.TunnelIface, "-j", "MASQUERADE"},
		[]string{"-t", "nat", "-A", "POSTROUTING", "-o", cfg.TunnelIface, "-j", "MASQUERADE"},
	); err != nil {
		return err
	}
	// Docker compatibility — only if DOCKER-USER chain exists (gateway mode only)
	if cfg.IsGateway && dockerUserChainExists() {
		iptCheckOrInsert( //nolint:errcheck
			[]string{"-C", "DOCKER-USER", "-i", cfg.TunnelIface, "-o", cfg.LANIface, "-j", "ACCEPT"},
			[]string{"-I", "DOCKER-USER", "-i", cfg.TunnelIface, "-o", cfg.LANIface, "-j", "ACCEPT"},
		)
		iptCheckOrInsert( //nolint:errcheck
			[]string{"-C", "DOCKER-USER", "-i", cfg.LANIface, "-o", cfg.TunnelIface, "-j", "ACCEPT"},
			[]string{"-I", "DOCKER-USER", "-i", cfg.LANIface, "-o", cfg.TunnelIface, "-j", "ACCEPT"},
		)
	}
	return nil
}

func applyMSSClamping(tunnelIface string) error {
	return iptCheckOrInsert(
		[]string{"-t", "mangle", "-C", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", tunnelIface, "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		[]string{"-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", tunnelIface, "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	)
}

func dockerUserChainExists() bool {
	err := exec.Command("iptables", "-L", "DOCKER-USER", "-n").Run()
	return err == nil
}

// SaveIPTables persists iptables rules so they survive reboots.
func SaveIPTables() error {
	out, err := exec.Command("netfilter-persistent", "save").CombinedOutput()
	if err != nil {
		return fmt.Errorf("netfilter-persistent save: %w — %s", err, out)
	}
	return nil
}

// --- low-level helpers ---

// ip runs an `ip` command with explicit arguments.
func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w — %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// ipt runs an iptables command, ignoring errors (for cleanup/delete operations).
func ipt(args ...string) {
	exec.Command("iptables", args...).Run()
}

// iptE runs an iptables command and returns errors.
func iptE(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w — %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// iptCheckOrInsert runs the check command; if it fails (rule absent), runs the insert command.
func iptCheckOrInsert(check, insert []string) error {
	if exec.Command("iptables", check...).Run() == nil {
		return nil // rule already present
	}
	return iptE(insert...)
}

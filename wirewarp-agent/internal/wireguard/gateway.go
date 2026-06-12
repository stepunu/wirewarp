package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const rtTablesPath = "/etc/iproute2/rt_tables"
const publicInboundTunnelFwmark int64 = 0x101

// GatewayConfig holds all the parameters needed to configure per-attachment
// policy routing on a gateway client. Each attachment owns one set of
// these — one tunnel iface, one fwmark, one route table.
//
// Gateways are inbound-only in this architecture: LAN-originated traffic
// goes via the LAN's normal default router. We do NOT install the legacy
// `ip rule from <LANNetwork> table <wg>` rule. The per-attachment routing
// here only handles the *reply path* for inbound DNAT'd flows: traffic
// arrives via wgN, gets fwmark=FW, conntrack stores it, replies match
// fwmark via CONNMARK restore, ip rule sends them back through wgN.
type GatewayConfig struct {
	TunnelIface     string // e.g. "wg0", "wg1"
	LANIface        string // e.g. "eth0"
	VPSTunnelIP     string // peer's tunnel IP, e.g. "10.21.0.1" (gateway of this attachment's reply route)
	GatewayTunnelIP string // this attachment's tunnel IP on the gateway side
	GatewayLANIP    string // this machine's LAN IP
	LANNetwork      string // e.g. "192.168.1.0/24"
	WGSubnet        string // attachment's tunnel /24, e.g. "10.21.0.0/24"
	IsGateway       bool   // gateway-mode flag (controls Docker compat rules)

	// Per-attachment routing knobs allocated by the control server.
	Fwmark        string // "0x101", "0x102", ...
	RouteTableID  string // "100", "101", "102", ...
	ReplyPriority string // ip rule priority for the fwmark→table lookup, e.g. "30000"
}

func (g GatewayConfig) routeTableName() string {
	if g.RouteTableID == "" {
		return ""
	}
	return "wirewarp_" + g.RouteTableID
}

// ApplyGatewayRouting performs the per-attachment routing setup. Each call
// is idempotent: it flushes its own attachment's rules first, then re-adds
// them, so reattaches are safe.
func ApplyGatewayRouting(cfg GatewayConfig) error {
	if cfg.Fwmark == "" || cfg.RouteTableID == "" || cfg.ReplyPriority == "" {
		return fmt.Errorf("gateway: fwmark, route_table_id, and reply_priority are required")
	}
	if err := ensureRTTableEntry(cfg.RouteTableID, cfg.routeTableName()); err != nil {
		return fmt.Errorf("rt_tables: %w", err)
	}
	if err := applySysctl(cfg.TunnelIface, cfg.LANIface); err != nil {
		return fmt.Errorf("sysctl: %w", err)
	}
	if err := EnsureOutputConnmark(); err != nil {
		return fmt.Errorf("output connmark: %w", err)
	}

	// Flush this attachment's routes / rules / mangle entries before re-asserting.
	flushAttachmentRoutes(cfg)
	flushAttachmentIPRules(cfg)
	flushAttachmentMangle(cfg)

	if err := applyAttachmentRoute(cfg); err != nil {
		return fmt.Errorf("route: %w", err)
	}
	if err := applyAttachmentIPRule(cfg); err != nil {
		return fmt.Errorf("ip rule: %w", err)
	}
	if err := applyAttachmentMangle(cfg); err != nil {
		return fmt.Errorf("mangle: %w", err)
	}
	if err := applyAttachmentNAT(cfg); err != nil {
		return fmt.Errorf("NAT: %w", err)
	}
	if err := applyMSSClamping(cfg.TunnelIface); err != nil {
		return fmt.Errorf("MSS clamping: %w", err)
	}
	return nil
}

// TeardownGatewayRouting removes the per-attachment routes / rules /
// iptables entries added by ApplyGatewayRouting. The global OUTPUT CONNMARK
// restore rule is left in place — other attachments may still depend on it.
func TeardownGatewayRouting(cfg GatewayConfig) error {
	flushAttachmentRoutes(cfg)
	flushAttachmentIPRules(cfg)
	flushAttachmentMangle(cfg)

	if cfg.LANIface != "" && cfg.WGSubnet != "" {
		ipt("-t", "nat", "-D", "POSTROUTING", "-s", cfg.WGSubnet, "-o", cfg.LANIface, "-j", "MASQUERADE")
	}
	if cfg.LANIface != "" && cfg.TunnelIface != "" {
		ipt(iptablesAction(gatewayLANMasqueradeRule(cfg), "-D")...)
		ipt("-t", "nat", "-D", "POSTROUTING", "-i", cfg.TunnelIface, "-o", cfg.LANIface, "-j", "MASQUERADE")
	}
	// Legacy single-mark MASQUERADE from older agent versions; harmless if absent.
	if cfg.LANIface != "" {
		ipt("-t", "nat", "-D", "POSTROUTING", "-m", "mark", "--mark", "0x1", "-o", cfg.LANIface, "-j", "MASQUERADE")
	}

	// MSS clamping is per-tunnel-iface
	ipt("-t", "mangle", "-D", "POSTROUTING",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-o", cfg.TunnelIface, "-j", "TCPMSS", "--clamp-mss-to-pmtu")

	return nil
}

// EnsureOutputConnmark installs the global mangle CONNMARK restore rules.
// Two hooks are needed:
//
//  1. OUTPUT  — covers locally-originated replies (gateway itself answering).
//  2. PREROUTING (all interfaces, non-tunnel) — covers FORWARDED replies
//     coming back from a LAN device through the gateway. Without this,
//     reply-path traffic for inbound DNAT'd flows has no fwmark restored
//     and falls through to the main routing table → exits via the LAN's
//     default router → asymmetric routing → connection failure.
//
// CONNMARK already disambiguates by stored mark, so single global rules
// cover replies for every attachment.
func EnsureOutputConnmark() error {
	if err := iptCheckOrInsert(
		[]string{"-t", "mangle", "-C", "OUTPUT", "-j", "CONNMARK", "--restore-mark"},
		[]string{"-t", "mangle", "-A", "OUTPUT", "-j", "CONNMARK", "--restore-mark"},
	); err != nil {
		return err
	}
	// PREROUTING restore covers forwarded replies. Match `! -i wg+` so we
	// don't double-restore on the inbound tunnel direction (where we set
	// CONNMARK in the per-attachment rule below).
	return iptCheckOrInsert(
		[]string{"-t", "mangle", "-C", "PREROUTING", "!", "-i", "wg+", "-j", "CONNMARK", "--restore-mark"},
		[]string{"-t", "mangle", "-A", "PREROUTING", "!", "-i", "wg+", "-j", "CONNMARK", "--restore-mark"},
	)
}

// --- per-attachment step implementations ---

func ensureRTTableEntry(tableID, tableName string) error {
	if _, err := os.Stat(rtTablesPath); os.IsNotExist(err) {
		if err := os.MkdirAll("/etc/iproute2", 0755); err != nil {
			return err
		}
		content := "255 local\n254 main\n253 default\n0 unspec\n" +
			fmt.Sprintf("%s %s\n", tableID, tableName)
		return os.WriteFile(rtTablesPath, []byte(content), 0644)
	}

	data, err := os.ReadFile(rtTablesPath)
	if err != nil {
		return err
	}
	// Match by id-prefix only: "<id> " — so renaming the human label later
	// doesn't create a duplicate row.
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == tableID {
			return nil
		}
	}
	f, err := os.OpenFile(rtTablesPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", tableID, tableName)
	return err
}

func applySysctl(tunnelIface, lanIface string) error {
	settings := [][]string{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.rp_filter", "0"},
		{"net.ipv4.conf.default.rp_filter", "0"},
	}
	if lanIface != "" {
		settings = append(settings, []string{"net.ipv4.conf." + lanIface + ".rp_filter", "0"})
	}
	if tunnelIface != "" {
		settings = append(settings, []string{"net.ipv4.conf." + tunnelIface + ".rp_filter", "0"})
	}
	for _, kv := range settings {
		out, err := exec.Command("sysctl", "-w", kv[0]+"="+kv[1]).CombinedOutput()
		if err != nil {
			return fmt.Errorf("sysctl -w %s=%s: %w — %s", kv[0], kv[1], err, out)
		}
	}
	return nil
}

func flushAttachmentRoutes(cfg GatewayConfig) {
	if cfg.RouteTableID != "" {
		exec.Command("ip", "route", "flush", "table", cfg.RouteTableID).Run()
	}
}

func flushAttachmentIPRules(cfg GatewayConfig) {
	if cfg.ReplyPriority == "" {
		return
	}
	for exec.Command("ip", "rule", "del", "priority", cfg.ReplyPriority).Run() == nil {
	}
}

func flushAttachmentMangle(cfg GatewayConfig) {
	if cfg.TunnelIface == "" {
		return
	}
	// Current rule (this agent version): single CONNMARK --set-mark.
	if cfg.Fwmark != "" {
		ipt("-t", "mangle", "-D", "PREROUTING", "-i", cfg.TunnelIface, "-j", "CONNMARK", "--set-mark", cfg.Fwmark)
	}
	// Legacy MARK + CONNMARK-save pair (early multi-server-gateway prototype).
	// Caused a routing loop because the inbound packet's MARK was matched by
	// the per-attachment ip rule and re-sent out the same wg interface.
	if cfg.Fwmark != "" {
		ipt("-t", "mangle", "-D", "PREROUTING", "-i", cfg.TunnelIface, "-j", "MARK", "--set-mark", cfg.Fwmark)
	}
	ipt("-t", "mangle", "-D", "PREROUTING", "-i", cfg.TunnelIface, "-j", "CONNMARK", "--save-mark")
	// Pre-multi-server-gateway hardcoded mark.
	ipt("-t", "mangle", "-D", "PREROUTING", "-i", cfg.TunnelIface, "-j", "MARK", "--set-mark", "0x1")
}

func applyAttachmentRoute(cfg GatewayConfig) error {
	if err := ip(
		"route", "add", "default",
		"via", cfg.VPSTunnelIP, "dev", cfg.TunnelIface,
		"table", cfg.RouteTableID,
	); err != nil {
		return err
	}
	// LAN destinations always exit via LAN, never via the tunnel — even
	// when this table is reached by a fwmark restore (e.g. CONNMARK on a
	// reply-side packet) or an egress pin. Without this, kernel-generated
	// ICMP frag-needed errors aimed at LAN hosts get marked with the
	// inbound flow's CONNMARK at OUTPUT, then misrouted into the tunnel
	// because the table only has a `default via wgN` route. That
	// black-holes PMTU discovery for inbound port forwards (visible
	// symptom: HTTPS handshakes stall mid-TLS while small HTTP replies
	// still work).
	if cfg.LANNetwork != "" && cfg.LANIface != "" {
		if err := ip(
			"route", "add", cfg.LANNetwork, "dev", cfg.LANIface,
			"table", cfg.RouteTableID,
		); err != nil {
			return err
		}
	}
	return nil
}

func applyAttachmentIPRule(cfg GatewayConfig) error {
	return ip(
		"rule", "add", "fwmark", cfg.Fwmark,
		"table", cfg.RouteTableID,
		"priority", cfg.ReplyPriority,
	)
}

func applyAttachmentMangle(cfg GatewayConfig) error {
	// CONNMARK --set-mark sets the conntrack entry's mark directly without
	// touching the packet's nfmark. This avoids the routing-loop trap of
	// using `MARK --set-mark` on the inbound side: a packet whose MARK is
	// the per-attachment fwmark would match the same `ip rule fwmark X
	// table N` rule we install for the *reply* path, which routes via wgN
	// — sending the inbound packet straight back into the tunnel.
	//
	// On the reply path (PREROUTING ! -i wg+ -j CONNMARK --restore-mark),
	// the conntrack mark is restored to nfmark, which is what we want for
	// routing the reply via the matching attachment.
	return iptE("-t", "mangle", "-A", "PREROUTING", "-i", cfg.TunnelIface, "-j", "CONNMARK", "--set-mark", cfg.Fwmark)
}

func applyAttachmentNAT(cfg GatewayConfig) error {
	if err := iptE("-P", "FORWARD", "ACCEPT"); err != nil {
		return err
	}
	// Do not SNAT public DNAT flows forwarded from the primary VPS tunnel to
	// LAN services. The original client IP must reach the service/edge so
	// internal-only allowlists cannot be bypassed by seeing the gateway's LAN IP.
	if cfg.LANIface != "" && cfg.TunnelIface != "" {
		// Remove the older, too-narrow rule. It only matched source addresses
		// inside the WireGuard subnet, so internet-sourced DNAT traffic kept
		// its original source and could not reliably return.
		if cfg.WGSubnet != "" {
			ipt("-t", "nat", "-D", "POSTROUTING", "-s", cfg.WGSubnet, "-o", cfg.LANIface, "-j", "MASQUERADE")
		}
		// Remove the first broad tunnel-ingress attempt. nat/POSTROUTING cannot
		// reliably match the input interface, so current rules key off CONNMARK.
		ipt("-t", "nat", "-D", "POSTROUTING", "-i", cfg.TunnelIface, "-o", cfg.LANIface, "-j", "MASQUERADE")
		rule := gatewayLANMasqueradeRule(cfg)
		if !shouldApplyGatewayLANMasquerade(cfg) {
			deleteIPTablesRule(rule)
		} else {
			if err := iptCheckOrInsert(
				iptablesAction(rule, "-C"),
				iptablesAction(rule, "-A"),
			); err != nil {
				return err
			}
		}
	}
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

func shouldApplyGatewayLANMasquerade(cfg GatewayConfig) bool {
	return !isPublicInboundTunnelFwmark(cfg.Fwmark)
}

func isPublicInboundTunnelFwmark(fwmark string) bool {
	mark, err := strconv.ParseInt(strings.TrimSpace(fwmark), 0, 64)
	return err == nil && mark == publicInboundTunnelFwmark
}

func gatewayLANMasqueradeRule(cfg GatewayConfig) []string {
	return []string{
		"-t", "nat", "POSTROUTING",
		"-m", "connmark", "--mark", cfg.Fwmark,
		"-o", cfg.LANIface,
		"-j", "MASQUERADE",
	}
}

func deleteIPTablesRule(rule []string) bool {
	removed := false
	args := iptablesAction(rule, "-D")
	for exec.Command("iptables", args...).Run() == nil {
		removed = true
	}
	return removed
}

func iptablesAction(rule []string, action string) []string {
	if len(rule) >= 3 && rule[0] == "-t" {
		out := append([]string{}, rule[:2]...)
		out = append(out, action)
		out = append(out, rule[2:]...)
		return out
	}
	out := append([]string{action}, rule...)
	return out
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
		return nil
	}
	return iptE(insert...)
}

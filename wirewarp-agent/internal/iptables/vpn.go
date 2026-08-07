package iptables

import (
	"fmt"
	"os/exec"
	"strings"
)

// VpnRule describes one allow-rule materialised on the gateway for a
// specific peer (identified by source = its /32 VPN IP).
type VpnRule struct {
	Destination    string // IP or CIDR
	Protocol       string // "tcp" | "udp" | "icmp" | "any"
	PortRangeStart int    // 0 = no port match
	PortRangeEnd   int    // 0 = single-port (uses Start)
}

type vpnPeerPlan struct {
	acceptRules    [][]string
	masqueradeRule []string
}

// VpnPeerEnsureRules removes every existing rule for `srcIP` first, then
// re-applies the supplied list. This is what makes a permission-list
// edit atomic from the agent's side: the operator's new rule set is
// applied wholesale, no leftover ACCEPTs from a previous version.
//
// Full-tunnel peers get one extra ACCEPT restricted to the detected WAN
// output interface. LAN traffic still needs a normal permission rule.
func VpnPeerEnsureRules(srcIP string, fullTunnel bool, wanIface string, rules []VpnRule) error {
	if err := vpnFlushPeer(srcIP); err != nil {
		return fmt.Errorf("flush peer rules: %w", err)
	}
	plan, err := buildVpnPeerPlan(srcIP, fullTunnel, wanIface, rules)
	if err != nil {
		return err
	}
	for _, args := range plan.acceptRules {
		if err := checkOrInsert(args); err != nil {
			return fmt.Errorf("add peer rule: %w", err)
		}
	}
	if len(plan.masqueradeRule) > 0 {
		if err := checkOrAppend(plan.masqueradeRule); err != nil {
			return fmt.Errorf("vpn masquerade: %w", err)
		}
	}
	return nil
}

func buildVpnPeerPlan(srcIP string, fullTunnel bool, wanIface string, rules []VpnRule) (vpnPeerPlan, error) {
	if fullTunnel && wanIface == "" {
		return vpnPeerPlan{}, fmt.Errorf("vpn full-tunnel WAN interface is unavailable")
	}
	plan := vpnPeerPlan{acceptRules: make([][]string, 0, len(rules)+1)}
	for _, rule := range rules {
		plan.acceptRules = append(plan.acceptRules, vpnPeerRuleArgs(srcIP, rule))
	}
	if fullTunnel {
		plan.acceptRules = append(plan.acceptRules, []string{
			"FORWARD", "-s", srcIP + "/32", "-o", wanIface, "-j", "ACCEPT",
		})
		plan.masqueradeRule = []string{
			"-t", "nat", "POSTROUTING",
			"-s", srcIP + "/32",
			"-o", wanIface,
			"-j", "MASQUERADE",
		}
	}
	return plan, nil
}

// VpnEnsureMSSClamp installs (idempotently) bidirectional TCP-MSS
// clamping on the FORWARD chain for the given VPN interface. Required
// because WireGuard adds ~80 bytes of overhead per packet — without
// clamping, full-size TCP segments from LAN hosts get blackholed when
// the WG-encapsulated reply exceeds the cellular path MTU. mssValue
// should be MTU(wg-vpn0) - 40 (IP+TCP headers).
func VpnEnsureMSSClamp(iface string, mssValue int) error {
	mss := fmt.Sprintf("%d", mssValue)
	for _, dir := range [][]string{
		{"-o", iface},
		{"-i", iface},
	} {
		args := []string{
			"-t", "mangle", "FORWARD",
			dir[0], dir[1],
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mss,
		}
		if exec.Command("iptables", buildCheck(args)...).Run() == nil {
			continue
		}
		insertArgs := replaceAction(args, "-A")
		out, err := exec.Command("iptables", insertArgs...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %s: %w — %s", strings.Join(insertArgs, " "), err, out)
		}
	}
	return nil
}

// VpnRemoveMSSClamp drops the bidirectional MSS-clamp rules for `iface`.
// Called at endpoint teardown so we don't leave stale mangle entries.
func VpnRemoveMSSClamp(iface string, mssValue int) {
	mss := fmt.Sprintf("%d", mssValue)
	for _, dir := range [][]string{
		{"-o", iface},
		{"-i", iface},
	} {
		args := []string{
			"-t", "mangle", "FORWARD",
			dir[0], dir[1],
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mss,
		}
		exec.Command("iptables", buildDelete(args)...).Run() //nolint:errcheck
	}
}

// VpnFlushMSSClamps drops every mangle-FORWARD TCPMSS rule that
// mentions `iface`, regardless of the configured MSS value. Used at
// `vpn_endpoint_up` to converge to a single canonical clamp pair on
// every restart, even if a previous run had a different vpnMSS or a
// human applied an ad-hoc rule during incident response.
func VpnFlushMSSClamps(iface string) {
	out, err := exec.Command("iptables-save", "-t", "mangle").CombinedOutput()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "-A FORWARD") {
			continue
		}
		if !strings.Contains(line, "TCPMSS") {
			continue
		}
		if !strings.Contains(line, " -i "+iface+" ") && !strings.Contains(line, " -o "+iface+" ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		fields[0] = "-D"
		args := append([]string{"-t", "mangle"}, fields...)
		exec.Command("iptables", args...).Run() //nolint:errcheck — idempotent
	}
}

// VpnPeerRemoveAll removes every FORWARD ACCEPT rule whose source matches
// `srcIP`, plus any MASQUERADE pinned to that source. Called on
// vpn_peer_remove (revoke) and as the first step of an update.
func VpnPeerRemoveAll(srcIP string) error {
	return vpnFlushPeer(srcIP)
}

// VpnEnsureDefaultDrop installs (idempotently) a final FORWARD-chain
// DROP for the entire VPN /24, after all per-peer ACCEPTs. So a peer
// can only reach what its own ACCEPT rules permit; everything else is
// rejected at the gateway even if WireGuard would otherwise route it.
func VpnEnsureDefaultDrop(vpnNetwork string) error {
	args := []string{"FORWARD", "-s", vpnNetwork, "-j", "DROP"}
	return checkOrAppend(args)
}

// VpnRemoveDefaultDrop drops the default-drop rule. Called when the
// endpoint is torn down so we don't leave a dangling block on a /24
// that may later be reused for something else.
func VpnRemoveDefaultDrop(vpnNetwork string) error {
	args := []string{"FORWARD", "-s", vpnNetwork, "-j", "DROP"}
	deleteRule(args)
	return nil
}

// --- helpers ---

func vpnPeerRuleArgs(srcIP string, r VpnRule) []string {
	args := []string{"FORWARD", "-s", srcIP + "/32"}
	if r.Destination != "" {
		args = append(args, "-d", r.Destination)
	}
	proto := strings.ToLower(r.Protocol)
	if proto == "" {
		proto = "any"
	}
	if proto != "any" {
		args = append(args, "-p", proto)
		if (proto == "tcp" || proto == "udp") && r.PortRangeStart > 0 {
			args = append(args, "--dport", portRangeForIptables(r.PortRangeStart, r.PortRangeEnd))
		}
	}
	args = append(args, "-j", "ACCEPT")
	return args
}

// checkOrInsert mirrors checkOrAppend but uses -I (insert at top) so the
// rule sits ahead of any later -A appended rules in the same chain.
func checkOrInsert(args []string) error {
	if exec.Command("iptables", buildCheck(args)...).Run() == nil {
		return nil
	}
	insertArgs := replaceAction(args, "-I")
	out, err := exec.Command("iptables", insertArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w — %s", strings.Join(insertArgs, " "), err, out)
	}
	return nil
}

func portRangeForIptables(start, end int) string {
	if end <= 0 || end == start {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d:%d", start, end)
}

// vpnFlushPeer walks the live filter and nat tables and deletes every
// rule that mentions our peer's `/32`. We can't reconstruct exact rules
// (the operator may have edited the permission list — we don't know
// the old shape), so iptables-save scanning is the only safe approach.
func vpnFlushPeer(srcIP string) error {
	for _, table := range []string{"filter", "nat"} {
		out, err := exec.Command("iptables-save", "-t", table).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables-save -t %s: %w — %s", table, err, out)
		}
		for _, args := range vpnPeerDeleteArgs(srcIP, table, string(out)) {
			if delOut, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("iptables %s: %w — %s", strings.Join(args, " "), err, delOut)
			}
		}
	}
	return nil
}

func vpnPeerDeleteArgs(srcIP, table, savedRules string) [][]string {
	needles := []string{
		" -s " + srcIP + "/32",
		" -s " + srcIP + " ",
	}
	var commands [][]string
	for _, line := range strings.Split(savedRules, "\n") {
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		matched := false
		for _, needle := range needles {
			if strings.Contains(line, needle) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		fields[0] = "-D"
		commands = append(commands, append([]string{"-t", table}, fields...))
	}
	return commands
}

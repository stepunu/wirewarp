package wireguard

import (
	"fmt"
	"os/exec"
	"strings"
)

// HealAttachment inspects each piece of per-attachment routing state and
// re-installs only the items that are missing. Unlike ApplyGatewayRouting
// it does NOT flush + re-add — that would cause a momentary disruption
// every cycle even when state is correct. The intent is a low-overhead
// periodic verifier that catches drift caused by manual intervention,
// wg-quick down/up cycles, NetworkManager wipes, or any other actor that
// touches `ip rule` / `ip route` / iptables out-of-band.
//
// Returns the human-readable names of healed items (for logging). An
// empty slice + nil err means everything was already correct. Errors
// from one piece do not abort the rest of the heal — we collect what
// we can and return the first error encountered.
func HealAttachment(cfg GatewayConfig) (healed []string, firstErr error) {
	if cfg.Fwmark == "" || cfg.RouteTableID == "" || cfg.ReplyPriority == "" {
		return nil, fmt.Errorf("heal: fwmark, route_table_id, and reply_priority are required")
	}

	record := func(name string, err error) {
		if err == nil {
			healed = append(healed, name)
			return
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", name, err)
		}
	}

	// 1. rt_tables row — idempotent already.
	if err := ensureRTTableEntry(cfg.RouteTableID, cfg.routeTableName()); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("rt_tables: %w", err)
		}
	}

	// 2. sysctl — cheap to re-set; only counts as "healed" if it had to flip
	// the value (sysctl -w writes regardless, so we re-read first).
	if changed, err := ensureSysctls(cfg.TunnelIface, cfg.LANIface); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("sysctl: %w", err)
		}
	} else if changed {
		healed = append(healed, "sysctl")
	}

	// 3. Global OUTPUT + PREROUTING CONNMARK restore — already idempotent;
	// EnsureOutputConnmark only inserts if missing.
	missing, err := ensureOutputConnmarkAndReport()
	if err != nil && firstErr == nil {
		firstErr = fmt.Errorf("output connmark: %w", err)
	}
	for _, m := range missing {
		healed = append(healed, m)
	}

	// 4. Per-attachment default route in custom table.
	if !defaultRouteExists(cfg) {
		record("default-route", ip(
			"route", "add", "default",
			"via", cfg.VPSTunnelIP, "dev", cfg.TunnelIface,
			"table", cfg.RouteTableID,
		))
	}

	// 5. LAN exception in custom table (PMTUD ICMP exits via LAN, not wgN).
	if cfg.LANNetwork != "" && cfg.LANIface != "" && !lanRouteExists(cfg) {
		record("lan-route", ip(
			"route", "add", cfg.LANNetwork, "dev", cfg.LANIface,
			"table", cfg.RouteTableID,
		))
	}

	// 6. ip rule fwmark → table. This is the rule that vanished in the
	// real incident this loop is here to catch.
	if !ipRuleExists(cfg) {
		record("ip-rule-fwmark", ip(
			"rule", "add", "fwmark", cfg.Fwmark,
			"table", cfg.RouteTableID,
			"priority", cfg.ReplyPriority,
		))
	}

	// 7. mangle PREROUTING -i wgN -j CONNMARK --set-mark <fwmark>.
	if !mangleSetConnmarkExists(cfg) {
		record("mangle-setmark", iptE(
			"-t", "mangle", "-A", "PREROUTING",
			"-i", cfg.TunnelIface,
			"-j", "CONNMARK", "--set-mark", cfg.Fwmark,
		))
	}

	// 8. NAT POSTROUTING MASQUERADE for tunnel-ingress traffic toward LAN.
	if cfg.LANIface != "" && cfg.TunnelIface != "" {
		if cfg.WGSubnet != "" {
			_ = exec.Command("iptables",
				"-t", "nat", "-D", "POSTROUTING",
				"-s", cfg.WGSubnet, "-o", cfg.LANIface, "-j", "MASQUERADE",
			).Run()
		}
		_ = exec.Command("iptables",
			"-t", "nat", "-D", "POSTROUTING",
			"-i", cfg.TunnelIface, "-o", cfg.LANIface, "-j", "MASQUERADE",
		).Run()
		rule := gatewayLANMasqueradeRule(cfg)
		if !shouldApplyGatewayLANMasquerade(cfg) {
			if deleteIPTablesRule(rule) {
				healed = append(healed, "nat-masquerade-removed")
			}
		} else {
			checkArgs := iptablesAction(rule, "-C")
			insertArgs := iptablesAction(rule, "-A")
			if exec.Command("iptables", checkArgs...).Run() != nil {
				record("nat-masquerade", iptE(insertArgs...))
			}
		}
	}

	// 9. mangle POSTROUTING MSS clamp.
	if exec.Command("iptables",
		"-t", "mangle", "-C", "POSTROUTING",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-o", cfg.TunnelIface, "-j", "TCPMSS", "--clamp-mss-to-pmtu",
	).Run() != nil {
		record("mss-clamp", iptE(
			"-t", "mangle", "-A", "POSTROUTING",
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-o", cfg.TunnelIface, "-j", "TCPMSS", "--clamp-mss-to-pmtu",
		))
	}

	// 10. DOCKER-USER pass-through, only for gateway-mode attachments where
	// the chain exists.
	if cfg.IsGateway && dockerUserChainExists() {
		inRule := gatewayDockerUserRule(cfg.TunnelIface, cfg.LANIface, true)
		if exec.Command("iptables", iptablesAction(inRule, "-C")...).Run() != nil {
			record("docker-user-in", iptE(iptablesAction(inRule, "-I")...))
		}
		outRule := gatewayDockerUserRule(cfg.LANIface, cfg.TunnelIface, true)
		if exec.Command("iptables", iptablesAction(outRule, "-C")...).Run() != nil {
			record("docker-user-out", iptE(iptablesAction(outRule, "-I")...))
		}
	}

	return healed, firstErr
}

// ensureSysctls re-applies the per-attachment sysctls and reports whether
// any of them had to be flipped (so the heal log only fires when there's
// real drift). sysctl -w succeeds whether the value changed or not, so we
// read first.
func ensureSysctls(tunnelIface, lanIface string) (changed bool, err error) {
	expect := [][]string{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.rp_filter", "0"},
		{"net.ipv4.conf.default.rp_filter", "0"},
	}
	if lanIface != "" {
		expect = append(expect, []string{"net.ipv4.conf." + lanIface + ".rp_filter", "0"})
	}
	if tunnelIface != "" {
		expect = append(expect, []string{"net.ipv4.conf." + tunnelIface + ".rp_filter", "0"})
	}
	for _, kv := range expect {
		cur, readErr := exec.Command("sysctl", "-n", kv[0]).Output()
		if readErr == nil && strings.TrimSpace(string(cur)) == kv[1] {
			continue
		}
		out, setErr := exec.Command("sysctl", "-w", kv[0]+"="+kv[1]).CombinedOutput()
		if setErr != nil {
			return changed, fmt.Errorf("sysctl -w %s=%s: %w — %s", kv[0], kv[1], setErr, out)
		}
		changed = true
	}
	return changed, nil
}

// ensureOutputConnmarkAndReport reapplies the global CONNMARK restore rules
// and reports which (if any) were missing. Mirrors EnsureOutputConnmark but
// surfaces the diff for the heal log.
func ensureOutputConnmarkAndReport() (healed []string, err error) {
	outputArgs := []string{"-t", "mangle", "OUTPUT", "-j", "CONNMARK", "--restore-mark"}
	if exec.Command("iptables", iptablesAction(outputArgs, "-C")...).Run() != nil {
		if e := iptE(iptablesAction(outputArgs, "-A")...); e != nil {
			return healed, e
		}
		healed = append(healed, "output-connmark-restore")
	}

	preArgs := []string{"-t", "mangle", "PREROUTING", "!", "-i", "wg+", "-j", "CONNMARK", "--restore-mark"}
	if exec.Command("iptables", iptablesAction(preArgs, "-C")...).Run() != nil {
		if e := iptE(iptablesAction(preArgs, "-A")...); e != nil {
			return healed, e
		}
		healed = append(healed, "prerouting-connmark-restore")
	}
	return healed, nil
}

// defaultRouteExists returns true iff `default via <vps_tunnel_ip> dev
// <tunnel_iface>` is present in the attachment's custom routing table.
func defaultRouteExists(cfg GatewayConfig) bool {
	out, err := exec.Command("ip", "route", "show", "table", cfg.RouteTableID).Output()
	if err != nil {
		return false
	}
	want := fmt.Sprintf("default via %s dev %s", cfg.VPSTunnelIP, cfg.TunnelIface)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), want) {
			return true
		}
	}
	return false
}

// lanRouteExists returns true iff `<lan_network> dev <lan_iface>` is
// present in the attachment's custom routing table.
func lanRouteExists(cfg GatewayConfig) bool {
	out, err := exec.Command("ip", "route", "show", "table", cfg.RouteTableID).Output()
	if err != nil {
		return false
	}
	want := fmt.Sprintf("%s dev %s", cfg.LANNetwork, cfg.LANIface)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), want) {
			return true
		}
	}
	return false
}

// ipRuleExists returns true iff there is an `ip rule` of the form
// `from all fwmark <fwmark> lookup <table>` at priority <reply_priority>.
// We match by fwmark + table rather than priority alone, so a hand-added
// rule with the right semantics at a different priority is still treated
// as "present" — avoids duplicate-installation when an operator already
// installed one manually.
func ipRuleExists(cfg GatewayConfig) bool {
	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return false
	}
	tableLabel := cfg.routeTableName()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "fwmark "+cfg.Fwmark) {
			continue
		}
		if strings.Contains(line, "lookup "+tableLabel) || strings.Contains(line, "lookup "+cfg.RouteTableID) {
			return true
		}
	}
	return false
}

// mangleSetConnmarkExists checks for the per-attachment CONNMARK --set-mark
// rule that tags inbound tunnel packets with the attachment's fwmark.
func mangleSetConnmarkExists(cfg GatewayConfig) bool {
	return exec.Command("iptables",
		"-t", "mangle", "-C", "PREROUTING",
		"-i", cfg.TunnelIface,
		"-j", "CONNMARK", "--set-mark", cfg.Fwmark,
	).Run() == nil
}

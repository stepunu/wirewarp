package iptables

import (
	"fmt"
	"os/exec"
	"strings"
)

// HealServerNetwork verifies the global network state on a tunnel-server
// agent (the VPS side) and re-installs anything that drifted. Per-forward
// DNAT/FORWARD rules are not the concern here — they are reconciled by
// the control-server replay loop on agent reconnect. This heal handles
// the host-wide pieces that are not in the database:
//
//   - net.ipv4.ip_forward sysctl
//   - POSTROUTING MASQUERADE on the public iface
//   - POSTROUTING TCPMSS clamp on the tunnel iface (paired with the
//     gateway-side clamp; without this the client → server SYN keeps mss
//     1460 and TLS handshakes blackhole on PMTUD-filtering networks)
//
// Returns the human-readable names of healed items for logging. Empty
// slice + nil err means everything was already correct.
func HealServerNetwork(publicIface, wgIface string) (healed []string, firstErr error) {
	record := func(name string, err error) {
		if err == nil {
			healed = append(healed, name)
			return
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", name, err)
		}
	}

	if changed, err := ensureIPForward(); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("ip_forward: %w", err)
		}
	} else if changed {
		healed = append(healed, "ip_forward")
	}

	if publicIface != "" {
		if exec.Command("iptables",
			"-t", "nat", "-C", "POSTROUTING",
			"-o", publicIface, "-j", "MASQUERADE",
		).Run() != nil {
			record("nat-masquerade", appendRule(
				"-t", "nat", "POSTROUTING",
				"-o", publicIface, "-j", "MASQUERADE",
			))
		}
	}

	if wgIface != "" {
		if exec.Command("iptables",
			"-t", "mangle", "-C", "POSTROUTING",
			"-o", wgIface,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu",
		).Run() != nil {
			record("mss-clamp", appendRule(
				"-t", "mangle", "POSTROUTING",
				"-o", wgIface,
				"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
				"-j", "TCPMSS", "--clamp-mss-to-pmtu",
			))
		}
	}

	return healed, firstErr
}

// ensureIPForward sets net.ipv4.ip_forward=1 only if it's currently
// something else, so the heal log doesn't fire on every cycle.
func ensureIPForward() (changed bool, err error) {
	cur, readErr := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
	if readErr == nil && strings.TrimSpace(string(cur)) == "1" {
		return false, nil
	}
	out, setErr := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if setErr != nil {
		return false, fmt.Errorf("sysctl -w ip_forward: %w — %s", setErr, out)
	}
	return true, nil
}

// appendRule runs `iptables -A <chain> <args>` and turns the table-prefix
// args into an -A invocation via the existing replaceAction helper.
func appendRule(args ...string) error {
	insertArgs := buildInsert(args)
	out, err := exec.Command("iptables", insertArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w — %s", strings.Join(insertArgs, " "), err, out)
	}
	return nil
}

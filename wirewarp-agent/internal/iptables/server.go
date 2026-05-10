package iptables

import (
	"fmt"
	"os/exec"
	"strings"
)

// ForwardRule describes a DNAT port-forwarding rule on the tunnel server.
// For single-port rules, PublicPortEnd and DestPortEnd are 0.
// For ranges, both end ports must be set (e.g. PublicPort=50000, PublicPortEnd=50100).
type ForwardRule struct {
	Protocol    string // "tcp" or "udp"
	PublicPort  int
	PublicPortEnd int // 0 = single port
	DestIP      string // destination inside the tunnel, e.g. a client tunnel IP
	DestPort    int
	DestPortEnd int // 0 = single port
}

// AddForward adds a DNAT PREROUTING rule and a FORWARD rule for the given spec.
// It checks for duplicates before inserting.
func AddForward(publicIP string, r ForwardRule) error {
	preroute := dnatArgs(publicIP, r)
	forward := forwardArgs(r)

	if err := checkOrAppend(preroute); err != nil {
		return fmt.Errorf("DNAT rule: %w", err)
	}
	if err := checkOrAppend(forward); err != nil {
		return fmt.Errorf("FORWARD rule: %w", err)
	}
	return nil
}

// RemoveForward removes the DNAT and FORWARD rules for the given spec.
func RemoveForward(publicIP string, r ForwardRule) error {
	deleteRule(dnatArgs(publicIP, r))
	deleteRule(forwardArgs(r))
	return nil
}

// EnsureMasquerade adds a POSTROUTING MASQUERADE rule for the given interface if absent.
func EnsureMasquerade(iface string) error {
	args := []string{"-t", "nat", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"}
	return checkOrAppend(args)
}

// snatArgs builds the iptables args for a per-LAN-host SNAT rule.
// The rule is inserted before the generic MASQUERADE so it wins for
// traffic originating at this specific source.
func snatArgs(iface, lanIP, publicIP string) []string {
	return []string{
		"-t", "nat", "POSTROUTING",
		"-o", iface,
		"-s", lanIP,
		"-j", "SNAT",
		"--to-source", publicIP,
	}
}

// AddLANSNAT installs (idempotently) a per-host SNAT rule that rewrites
// outbound traffic from `lanIP` on `iface` to source `publicIP`. Uses
// -I (insert) so it sits before the generic MASQUERADE in POSTROUTING
// — otherwise MASQUERADE would match first and pick the kernel-chosen
// primary IP.
func AddLANSNAT(iface, lanIP, publicIP string) error {
	args := snatArgs(iface, lanIP, publicIP)
	checkArgs := buildCheck(args)
	if exec.Command("iptables", checkArgs...).Run() == nil {
		return nil
	}
	insertArgs := replaceAction(args, "-I")
	out, err := exec.Command("iptables", insertArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w — %s", strings.Join(insertArgs, " "), err, out)
	}
	return nil
}

// RemoveLANSNATBySource deletes any nat POSTROUTING SNAT rules whose
// source matches `lanIP`. Walks `iptables-save -t nat` because the
// per-host SNAT's `--to-source` IP might have changed between calls,
// so we can't reconstruct the exact rule that was previously inserted
// without remembering it. Matching by `-s <lanIP>` + `SNAT` jump is
// specific enough — operators don't manually install LAN-host SNAT
// elsewhere on the VPS.
func RemoveLANSNATBySource(lanIP string) error {
	out, err := exec.Command("iptables-save", "-t", "nat").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-save: %w — %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "-A POSTROUTING") {
			continue
		}
		if !strings.Contains(line, " -s "+lanIP+"/32") && !strings.Contains(line, " -s "+lanIP+" ") {
			continue
		}
		if !strings.Contains(line, "-j SNAT") {
			continue
		}
		// Convert "-A POSTROUTING ..." to a -D delete invocation.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		fields[0] = "-D"
		args := append([]string{"-t", "nat"}, fields...)
		if delOut, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %s: %w — %s", strings.Join(args, " "), err, delOut)
		}
	}
	return nil
}

// EnableIPForward enables IPv4 packet forwarding via sysctl.
func EnableIPForward() error {
	out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl ip_forward: %w — %s", err, out)
	}
	return nil
}

// SaveRules persists iptables rules via netfilter-persistent.
func SaveRules() error {
	out, err := exec.Command("netfilter-persistent", "save").CombinedOutput()
	if err != nil {
		return fmt.Errorf("netfilter-persistent save: %w — %s", err, out)
	}
	return nil
}

// --- helpers ---

func dnatArgs(publicIP string, r ForwardRule) []string {
	// iptables DNAT destination uses hyphen for port ranges: "ip:start-end"
	var dst string
	if r.DestPortEnd > 0 {
		dst = fmt.Sprintf("%s:%d-%d", r.DestIP, r.DestPort, r.DestPortEnd)
	} else {
		dst = fmt.Sprintf("%s:%d", r.DestIP, r.DestPort)
	}
	// iptables --dport uses colon for ranges: "start:end"
	var dport string
	if r.PublicPortEnd > 0 {
		dport = fmt.Sprintf("%d:%d", r.PublicPort, r.PublicPortEnd)
	} else {
		dport = fmt.Sprintf("%d", r.PublicPort)
	}
	args := []string{"-t", "nat", "PREROUTING",
		"-p", r.Protocol,
		"-j", "DNAT",
		"--to-destination", dst,
		"--dport", dport,
	}
	if publicIP != "" {
		args = append(args, "-d", publicIP)
	}
	return args
}

func forwardArgs(r ForwardRule) []string {
	var dport string
	if r.DestPortEnd > 0 {
		dport = fmt.Sprintf("%d:%d", r.DestPort, r.DestPortEnd)
	} else {
		dport = fmt.Sprintf("%d", r.DestPort)
	}
	return []string{"FORWARD",
		"-p", r.Protocol,
		"-d", r.DestIP,
		"--dport", dport,
		"-j", "ACCEPT",
	}
}

// checkOrAppend uses `iptables -C` to check; inserts with `-A` if absent.
func checkOrAppend(args []string) error {
	// Build check args: replace the chain position (index 1 in args, after optional -t table)
	// args format is either: ["-t", "nat", "CHAIN", ...flags] or ["CHAIN", ...flags]
	checkArgs := buildCheck(args)
	if exec.Command("iptables", checkArgs...).Run() == nil {
		return nil // already present
	}
	insertArgs := buildInsert(args)
	out, err := exec.Command("iptables", insertArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w — %s", strings.Join(insertArgs, " "), err, out)
	}
	return nil
}

func deleteRule(args []string) {
	deleteArgs := buildDelete(args)
	exec.Command("iptables", deleteArgs...).Run()
}

// buildCheck converts rule args with a plain chain name to a -C check invocation.
func buildCheck(args []string) []string {
	return replaceAction(args, "-C")
}

func buildInsert(args []string) []string {
	return replaceAction(args, "-A")
}

func buildDelete(args []string) []string {
	return replaceAction(args, "-D")
}

// replaceAction rewrites args so the chain token is preceded by action (-C/-A/-D).
// Input format: ["-t", "nat", "CHAIN", ...] or ["CHAIN", ...]
// Output: ["-t", "nat", "-C", "CHAIN", ...] or ["-C", "CHAIN", ...]
func replaceAction(args []string, action string) []string {
	result := make([]string, 0, len(args)+1)
	i := 0
	// Copy leading "-t table" if present.
	if len(args) >= 2 && args[0] == "-t" {
		result = append(result, args[0], args[1])
		i = 2
	}
	// Next token is the chain name — insert action before it.
	result = append(result, action)
	result = append(result, args[i:]...)
	return result
}

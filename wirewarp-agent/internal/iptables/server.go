package iptables

import (
	"fmt"
	"os/exec"
	"strings"
)

// ForwardRule describes a DNAT port-forwarding rule on the tunnel server.
type ForwardRule struct {
	Protocol    string // "tcp" or "udp"
	PublicPort  int
	DestIP      string // destination inside the tunnel, e.g. a client tunnel IP
	DestPort    int
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
	dst := fmt.Sprintf("%s:%d", r.DestIP, r.DestPort)
	args := []string{"-t", "nat", "PREROUTING",
		"-p", r.Protocol,
		"-j", "DNAT",
		"--to-destination", dst,
		"--dport", fmt.Sprintf("%d", r.PublicPort),
	}
	if publicIP != "" {
		args = append(args, "-d", publicIP)
	}
	return args
}

func forwardArgs(r ForwardRule) []string {
	return []string{"FORWARD",
		"-p", r.Protocol,
		"-d", r.DestIP,
		"--dport", fmt.Sprintf("%d", r.DestPort),
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

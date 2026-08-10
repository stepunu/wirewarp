package iptables

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

const lanSNATComment = "wirewarp-lan-snat"
const serverMasqueradeComment = "wirewarp-server-masquerade"

type LANSNATPin struct {
	LANIP    string
	PublicIP string
}

// ForwardRule describes a DNAT port-forwarding rule on the tunnel server.
// For single-port rules, PublicPortEnd and DestPortEnd are 0.
// For ranges, both end ports must be set (e.g. PublicPort=50000, PublicPortEnd=50100).
type ForwardRule struct {
	Protocol      string // "tcp" or "udp"
	PublicPort    int
	PublicPortEnd int    // 0 = single port
	DestIP        string // destination inside the tunnel, e.g. a client tunnel IP
	DestPort      int
	DestPortEnd   int // 0 = single port
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
	var firstErr error
	if err := deleteRuleIfPresent(dnatArgs(publicIP, r)); err != nil {
		firstErr = fmt.Errorf("DNAT rule: %w", err)
	}
	if err := deleteRuleIfPresent(forwardArgs(r)); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("FORWARD rule: %w", err)
	}
	return firstErr
}

// RemoveForwardAndSave removes and persists a forward. If persistence fails,
// it restores only the exact rules that existed before this command.
func RemoveForwardAndSave(publicIP string, r ForwardRule) error {
	dnat := dnatArgs(publicIP, r)
	forward := forwardArgs(r)
	dnatPresent, err := ruleExists(dnat)
	if err != nil {
		return fmt.Errorf("inspect DNAT rule: %w", err)
	}
	forwardPresent, err := ruleExists(forward)
	if err != nil {
		return fmt.Errorf("inspect FORWARD rule: %w", err)
	}
	if err := RemoveForward(publicIP, r); err != nil {
		return err
	}
	if err := SaveRules(); err != nil {
		rollbackErr := restoreForwardRules(dnat, forward, dnatPresent, forwardPresent)
		if rollbackErr != nil {
			return fmt.Errorf("save removed forward: %w; rollback failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("save removed forward: %w; previous state restored", err)
	}
	return nil
}

func restoreForwardRules(dnat, forward []string, dnatPresent, forwardPresent bool) error {
	var failures []string
	if dnatPresent {
		if err := checkOrAppend(dnat); err != nil {
			failures = append(failures, fmt.Sprintf("DNAT rule: %v", err))
		}
	}
	if forwardPresent {
		if err := checkOrAppend(forward); err != nil {
			failures = append(failures, fmt.Sprintf("FORWARD rule: %v", err))
		}
	}
	if err := SaveRules(); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

// EnsureMasquerade adds a POSTROUTING MASQUERADE rule for the given interface if absent.
func EnsureMasquerade(iface string) error {
	return checkOrAppend(serverMasqueradeArgs(iface))
}

// RemoveMasquerade removes the exact WireWarp server MASQUERADE rule from
// iface. A missing rule is already the desired state.
func RemoveMasquerade(iface string) error {
	return deleteRuleIfPresent(serverMasqueradeArgs(iface))
}

func serverMasqueradeArgs(iface string) []string {
	return []string{
		"-t", "nat", "POSTROUTING", "-o", iface,
		"-m", "comment", "--comment", serverMasqueradeComment,
		"-j", "MASQUERADE",
	}
}

// CleanupServerNAT removes server-owned NAT state from an old public
// interface. Both cleanup steps run so one failure does not leave more stale
// state than necessary. The first error is returned for a later retry.
func CleanupServerNAT(iface string) error {
	var firstErr error
	if err := ReconcileLANSNAT(iface, nil); err != nil {
		firstErr = fmt.Errorf("LAN SNAT cleanup: %w", err)
	}
	if err := RemoveMasquerade(iface); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("masquerade cleanup: %w", err)
	}
	return firstErr
}

// EnsureMSSClamp installs a mangle POSTROUTING TCPMSS --clamp-mss-to-pmtu rule
// on the given tunnel interface. Mirror of the gateway-side clamp in
// wireguard.applyMSSClamping — without this on the VPS, the client→server SYN
// crossing the VPS keeps its mss=1460 untouched, so the LAN service replies
// with full-sized segments that don't fit inside wg0's 1420 MTU. Path-MTU
// discovery relies on ICMP frag-needed making it back to the originating
// client; mobile carriers and strict NATs often filter that ICMP, producing
// a blackhole where TCP handshakes complete but TLS records stall mid-stream.
// Clamping at the egress of the VPS's tunnel iface fixes both directions for
// every inbound DNAT'd flow.
func EnsureMSSClamp(iface string) error {
	args := []string{
		"-t", "mangle", "POSTROUTING",
		"-o", iface,
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
	}
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
		"-m", "comment", "--comment", lanSNATComment,
		"-j", "SNAT",
		"--to-source", publicIP,
	}
}

// ReconcileLANSNAT replaces all WireWarp per-host SNAT rules on iface with
// pins. Legacy untagged rules use the exact shape created by older agents.
// Compatibility assumes operators do not create that LAN-host SNAT shape on
// the managed public interface.
func ReconcileLANSNAT(iface string, pins []LANSNATPin) error {
	current, err := currentLANSNATRules(iface)
	if err != nil {
		return err
	}
	return replaceLANSNATRules(iface, current, pins)
}

// ReconcileLANSNATAndSave applies and persists desired state. A failed
// mutation or save restores and persists the complete pre-command state.
func ReconcileLANSNATAndSave(iface string, pins []LANSNATPin) error {
	before, err := currentLANSNATRules(iface)
	if err != nil {
		return err
	}

	originalErr := replaceLANSNATRules(iface, before, pins)
	if originalErr == nil {
		originalErr = SaveRules()
	}
	if originalErr == nil {
		return nil
	}

	return rollbackLANSNATFailure("reconcile LAN SNAT", iface, before, originalErr)
}

// SetLANSNATAndSave changes one source pin while preserving every other
// managed rule. Any mutation or save failure restores the complete snapshot.
func SetLANSNATAndSave(iface, lanIP, publicIP string, clear bool) error {
	before, err := currentLANSNATRules(iface)
	if err != nil {
		return err
	}

	var firstDeleteErr error
	for _, rule := range before {
		if !lanSNATRuleMatchesSource(rule, lanIP) {
			continue
		}
		args := buildDelete(rule)
		if out, deleteErr := exec.Command("iptables", args...).CombinedOutput(); deleteErr != nil && firstDeleteErr == nil {
			firstDeleteErr = fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), deleteErr, out)
		}
	}
	originalErr := firstDeleteErr
	if originalErr == nil && !clear {
		originalErr = AddLANSNAT(iface, lanIP, publicIP)
	}
	if originalErr == nil {
		originalErr = SaveRules()
	}
	if originalErr == nil {
		return nil
	}
	return rollbackLANSNATFailure("set LAN SNAT", iface, before, originalErr)
}

func rollbackLANSNATFailure(operation, iface string, before [][]string, originalErr error) error {
	rollbackErr := restoreLANSNATRules(iface, before)
	if rollbackErr != nil {
		return fmt.Errorf("%s: %w; rollback failed: %v", operation, originalErr, rollbackErr)
	}
	return fmt.Errorf("%s: %w; previous state restored", operation, originalErr)
}

func lanSNATRuleMatchesSource(rule []string, lanIP string) bool {
	source, ok := ruleFlagValue(rule, "-s")
	if !ok {
		return false
	}
	want, err := netip.ParseAddr(lanIP)
	if err != nil {
		return false
	}
	if prefix, err := netip.ParsePrefix(source); err == nil {
		return prefix.Bits() == 32 && prefix.Addr() == want
	}
	got, err := netip.ParseAddr(source)
	return err == nil && got == want
}

func currentLANSNATRules(iface string) ([][]string, error) {
	out, err := exec.Command("iptables-save", "-t", "nat").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables-save: %w: %s", err, out)
	}
	return lanSNATRules(string(out), iface), nil
}

func replaceLANSNATRules(iface string, current [][]string, pins []LANSNATPin) error {
	var firstDeleteErr error
	for _, rule := range current {
		args := buildDelete(rule)
		if delOut, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			if firstDeleteErr == nil {
				firstDeleteErr = fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, delOut)
			}
		}
	}
	if firstDeleteErr != nil {
		return firstDeleteErr
	}

	desired := append([]LANSNATPin(nil), pins...)
	sort.Slice(desired, func(i, j int) bool {
		if desired[i].LANIP == desired[j].LANIP {
			return desired[i].PublicIP < desired[j].PublicIP
		}
		return desired[i].LANIP < desired[j].LANIP
	})
	for _, pin := range desired {
		if err := AddLANSNAT(iface, pin.LANIP, pin.PublicIP); err != nil {
			return err
		}
	}
	return nil
}

func restoreLANSNATRules(iface string, before [][]string) error {
	var failures []string
	current, err := currentLANSNATRules(iface)
	if err != nil {
		failures = append(failures, err.Error())
	} else {
		for _, rule := range current {
			args := buildDelete(rule)
			if out, deleteErr := exec.Command("iptables", args...).CombinedOutput(); deleteErr != nil {
				failures = append(failures, fmt.Sprintf("iptables %s: %v: %s", strings.Join(args, " "), deleteErr, out))
			}
		}
	}

	// Insert in reverse so the pre-command managed-rule order is retained.
	for i := len(before) - 1; i >= 0; i-- {
		if addErr := insertLANSNATRuleIfMissing(before[i]); addErr != nil {
			failures = append(failures, addErr.Error())
		}
	}
	if saveErr := SaveRules(); saveErr != nil {
		failures = append(failures, saveErr.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func insertLANSNATRuleIfMissing(rule []string) error {
	checkArgs := buildCheck(rule)
	checkOut, err := exec.Command("iptables", checkArgs...).CombinedOutput()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(checkArgs, " "), err, checkOut)
	}
	insertArgs := replaceAction(rule, "-I")
	insertOut, err := exec.Command("iptables", insertArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(insertArgs, " "), err, insertOut)
	}
	return nil
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

func lanSNATDeleteRules(saveOutput, iface string) [][]string {
	rules := lanSNATRules(saveOutput, iface)
	for i := range rules {
		rules[i] = buildDelete(rules[i])
	}
	return rules
}

func lanSNATRules(saveOutput, iface string) [][]string {
	var rules [][]string
	for _, line := range strings.Split(saveOutput, "\n") {
		fields := strings.Fields(line)
		normalizeIPTablesSaveFields(fields)
		if !isWireWarpLANSNATRule(fields, iface) {
			continue
		}
		fields = fields[1:]
		rules = append(rules, append([]string{"-t", "nat"}, fields...))
	}
	return rules
}

func normalizeIPTablesSaveFields(fields []string) {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--comment" {
			fields[i+1] = strings.Trim(fields[i+1], `"`)
		}
	}
}

func isWireWarpLANSNATRule(fields []string, iface string) bool {
	if len(fields) != 10 && len(fields) != 14 {
		return false
	}
	if fields[0] != "-A" || fields[1] != "POSTROUTING" {
		return false
	}
	if value, ok := ruleFlagValue(fields, "-o"); !ok || value != iface {
		return false
	}
	source, ok := ruleFlagValue(fields, "-s")
	if !ok || !isIPv4Host(source) {
		return false
	}
	if value, ok := ruleFlagValue(fields, "-j"); !ok || value != "SNAT" {
		return false
	}
	toSource, ok := ruleFlagValue(fields, "--to-source")
	if !ok || !isIPv4Address(toSource) {
		return false
	}
	comment, hasComment := ruleFlagValue(fields, "--comment")
	if len(fields) == 10 {
		return !hasComment
	}
	module, hasModule := ruleFlagValue(fields, "-m")
	return hasModule && module == "comment" && hasComment && comment == lanSNATComment
}

func ruleFlagValue(fields []string, flag string) (string, bool) {
	for i := 2; i+1 < len(fields); i++ {
		if fields[i] == flag {
			return fields[i+1], true
		}
	}
	return "", false
}

func isIPv4Host(value string) bool {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().Is4() && prefix.Bits() == 32
	}
	return isIPv4Address(value)
}

func isIPv4Address(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4()
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

func deleteRuleIfPresent(args []string) error {
	checkArgs := buildCheck(args)
	checkOut, err := exec.Command("iptables", checkArgs...).CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil
		}
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(checkArgs, " "), err, checkOut)
	}

	deleteArgs := buildDelete(args)
	deleteOut, err := exec.Command("iptables", deleteArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(deleteArgs, " "), err, deleteOut)
	}
	return nil
}

func ruleExists(args []string) (bool, error) {
	checkArgs := buildCheck(args)
	out, err := exec.Command("iptables", checkArgs...).CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("iptables %s: %w: %s", strings.Join(checkArgs, " "), err, out)
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

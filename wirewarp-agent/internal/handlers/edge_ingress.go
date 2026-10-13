package handlers

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/wirewarp/agent/internal/config"
)

const edgeIngressChain = "WW-EDGE-INGRESS"
const edgeIngressComment = "wirewarp-edge-ingress"

var edgeIPTables = func(ctx context.Context, args ...string) ([]byte, error) {
	bin := resolveBin("iptables", "/usr/sbin/iptables", "/sbin/iptables")
	return exec.CommandContext(ctx, bin, append([]string{"-w", "5"}, args...)...).CombinedOutput()
}

var edgeIPTablesRestore = func(ctx context.Context, input string) error {
	bin := resolveBin("iptables-restore", "/usr/sbin/iptables-restore", "/sbin/iptables-restore")
	cmd := exec.CommandContext(ctx, bin, "--wait", "5", "--noflush")
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply owned edge INPUT rules: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// One filter-table commit replaces the owned chain and moves its exact jump.
// Other INPUT rules and all routing, NAT, and FORWARD rules remain untouched.
func reconcileEdgeIngress(ctx context.Context, ingress []config.EdgePublicIngress) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	input, err := edgeIPTables(ctx, "-S", "INPUT")
	if err != nil {
		return fmt.Errorf("inspect INPUT rules: %w: %s", err, strings.TrimSpace(string(input)))
	}
	chain, err := edgeIPTables(ctx, "-S", edgeIngressChain)
	if err != nil && !missingOwnedChain(ctx, "filter", edgeIngressChain, string(chain)) {
		return fmt.Errorf("inspect owned edge chain: %w: %s", err, strings.TrimSpace(string(chain)))
	}
	exists := err == nil
	jump := "-A INPUT -m comment --comment " + edgeIngressComment + " -j " + edgeIngressChain
	jumps := 0
	for _, line := range strings.Split(string(input), "\n") {
		// iptables -S may quote comment strings.
		if strings.ReplaceAll(strings.TrimSpace(line), `"`, "") == jump {
			jumps++
		}
	}
	rules := edgeIngressRules(ingress)
	if len(rules) == 0 && !exists && jumps == 0 {
		return nil
	}
	var transaction strings.Builder
	transaction.WriteString("*filter\n")
	if len(rules) > 0 {
		transaction.WriteString(":" + edgeIngressChain + " - [0:0]\n")
	}
	if exists || len(rules) > 0 {
		transaction.WriteString("-F " + edgeIngressChain + "\n")
	}
	for _, rule := range rules {
		transaction.WriteString(rule + "\n")
	}
	for i := 0; i < jumps; i++ {
		transaction.WriteString(strings.Replace(jump, "-A", "-D", 1) + "\n")
	}
	if len(rules) > 0 {
		transaction.WriteString("-I INPUT 1 -m comment --comment " + edgeIngressComment + " -j " + edgeIngressChain + "\n")
	} else if exists {
		transaction.WriteString("-X " + edgeIngressChain + "\n")
	}
	transaction.WriteString("COMMIT\n")
	return edgeIPTablesRestore(ctx, transaction.String())
}

func missingEdgeChain(output string) bool {
	output = strings.ToLower(strings.TrimSpace(output))
	return strings.Contains(output, "no chain/target/match by that name") || strings.HasPrefix(output, "chain ") && strings.HasSuffix(output, " does not exist")
}

// iptables-nft 1.8.9 reports absent chains as incompatible. Only a complete,
// successful table inventory can prove absence for that ambiguous diagnostic.
func missingOwnedChain(ctx context.Context, table, chain, output string) bool {
	if missingEdgeChain(output) {
		return true
	}
	if !strings.Contains(strings.ToLower(output), "is incompatible, use 'nft' tool") {
		return false
	}
	listing, err := edgeIPTables(ctx, "-t", table, "-S")
	if err != nil {
		return false
	}
	required := map[string][]string{"filter": {"INPUT", "FORWARD", "OUTPUT"}, "nat": {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"}}[table]
	if len(required) == 0 {
		return false
	}
	policies := map[string]bool{}
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// Warnings about omitted incompatible chains invalidate the inventory.
		if len(fields) < 2 {
			return false
		}
		switch fields[0] {
		case "-P":
			if len(fields) != 3 || fields[2] != "ACCEPT" && fields[2] != "DROP" {
				return false
			}
			policies[fields[1]] = true
		case "-N":
			if len(fields) != 2 {
				return false
			}
		case "-A":
			if len(fields) < 4 {
				return false
			}
		default:
			return false
		}
		if fields[1] == chain {
			return false
		}
		for i := 2; i+1 < len(fields); i++ {
			if (fields[i] == "-j" || fields[i] == "-g") && strings.Trim(fields[i+1], `"`) == chain {
				return false
			}
		}
	}
	for _, parent := range required {
		if !policies[parent] {
			return false
		}
	}
	return true
}

func (h *EdgeHandlers) removeEdgeIngress() error {
	if h.applyIngress == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return h.applyIngress(ctx, nil)
}

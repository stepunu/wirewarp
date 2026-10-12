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
	if err != nil && !missingEdgeChain(string(chain)) {
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
	output = strings.ToLower(output)
	return strings.Contains(output, "no chain/target/match by that name") || strings.Contains(output, "does not exist")
}

func (h *EdgeHandlers) removeEdgeIngress() error {
	if h.applyIngress == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return h.applyIngress(ctx, nil)
}

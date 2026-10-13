package firewall

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// WithoutOwnership returns the exact legacy form of a tagged command.
func WithoutOwnership(args []string) []string {
	out := []string{}
	for i := 0; i < len(args); i++ {
		if i+3 < len(args) && args[i] == "-m" && args[i+1] == "comment" && args[i+2] == "--comment" && comments[args[i+3]] {
			i += 3
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// Insert places a scoped allowance after protection jumps and before UFW.
// It never changes the parent chain's policy or any foreign rule.
func Insert(ctx context.Context, args []string) error {
	return insert(ctx, args, Run)
}

func insert(ctx context.Context, args []string, run func(context.Context, string, string, ...string) ([]byte, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	table, index := "filter", 0
	if len(args) > 2 && args[0] == "-t" {
		table, index = args[1], 2
	}
	if index+1 >= len(args) {
		return fmt.Errorf("invalid owned firewall insertion")
	}
	chain := args[index+1]
	if table != "filter" || chain != "FORWARD" && chain != "INPUT" && chain != "OUTPUT" {
		_, err := run(ctx, "", "iptables", args...)
		return err
	}
	out, err := run(ctx, "", "iptables", "-w", "5", "-t", table, "-S", chain)
	if err != nil {
		return fmt.Errorf("inspect guard precedence: %w", err)
	}
	position := 1
	seenForeign := false
	appendOwned := flag(args, "-j") == "DROP"
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "-A "+chain+" ") {
			continue
		}
		fields := strings.Fields(line)
		target := flag(fields, "-j")
		if target == "WW-SITE-FWD" || target == "WW-SITE-IN" || target == "WW-SITE-OUT" || target == "WW-EDGE-INGRESS" {
			if seenForeign {
				return fmt.Errorf("owned firewall guard must precede forwarding allowances")
			}
			position++
		} else {
			if appendOwned && !seenForeign && comments[flag(fields, "--comment")] {
				position++
			} else {
				seenForeign = true
			}
		}
	}
	next := append([]string{}, args[:index]...)
	next = append(next, "-I", chain, fmt.Sprint(position))
	next = append(next, args[index+2:]...)
	if _, err := run(ctx, "", "iptables", next...); err != nil {
		return fmt.Errorf("insert owned firewall rule: %w", err)
	}
	return nil
}

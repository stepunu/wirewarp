package firewall

import (
	"context"
	"strings"
	"testing"
)

func TestScopedAllowAndVPNDropPreserveGuardPrecedence(t *testing.T) {
	listing := "-P FORWARD DROP\n-A FORWARD -m comment --comment wirewarp-site-links -j WW-SITE-FWD\n-A FORWARD -s 10.0.0.2/32 -m comment --comment wirewarp-vpn-peer -j ACCEPT\n-A FORWARD -j ufw-before-forward\n"
	for _, target := range []string{"ACCEPT", "DROP"} {
		t.Run(target, func(t *testing.T) {
			command := ""
			run := func(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "-S") {
					return []byte(listing), nil
				}
				command = strings.Join(args, " ")
				return nil, nil
			}
			args := []string{"-A", "FORWARD", "-s", "10.0.0.0/24", "-m", "comment", "--comment", "wirewarp-vpn-drop", "-j", target}
			if err := insert(context.Background(), args, run); err != nil {
				t.Fatal(err)
			}
			position := "2"
			if target == "DROP" {
				position = "3"
			}
			if !strings.HasPrefix(command, "-I FORWARD "+position+" ") {
				t.Fatal("unsafe owned rule ordering", command)
			}
		})
	}
}

func TestScopedAllowRejectsDisplacedGuardBeforeEffects(t *testing.T) {
	mutated := false
	run := func(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "-S") {
			return []byte("-A FORWARD -j ufw-before-forward\n-A FORWARD -m comment --comment wirewarp-site-links -j WW-SITE-FWD\n"), nil
		}
		mutated = true
		return nil, nil
	}
	if err := insert(context.Background(), []string{"-A", "FORWARD", "-i", "wg0", "-o", "eth0", "-j", "ACCEPT"}, run); err == nil || mutated {
		t.Fatal("guard displacement bypassed", err, mutated)
	}
}

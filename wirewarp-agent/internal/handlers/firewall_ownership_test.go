package handlers

import (
	"context"
	"fmt"
	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/firewall"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEdgeApplyRejectsForeignReservedChainsBeforeMutation(t *testing.T) {
	for _, chain := range []string{"WW-EDGE-INGRESS", "WW-SITE-FWD"} {
		t.Run(chain, func(t *testing.T) {
			dir := t.TempDir()
			queries := 0
			mutations := 0
			s := &firewall.Store{Path: filepath.Join(dir, "journal.json"), UFWConfig: filepath.Join(dir, "absent.conf"), Run: func(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
				queries++
				if binary != "iptables" || input != "" {
					mutations++
					return nil, fmt.Errorf("unexpected mutation")
				}
				table := args[3]
				if table == "filter" {
					return []byte("-P INPUT DROP\n-P FORWARD DROP\n-N " + chain + "\n"), nil
				}
				return nil, nil
			}}
			old := firewallOwnershipPreflight
			firewallOwnershipPreflight = s.Preflight
			t.Cleanup(func() { firewallOwnershipPreflight = old })
			oldRestore := edgeIPTablesRestore
			edgeIPTablesRestore = func(context.Context, string) error { mutations++; return nil }
			t.Cleanup(func() { edgeIPTablesRestore = oldRestore })
			cfg := &config.Config{Mode: "server", AgentID: "test-owner"}
			h := NewEdge(cfg, filepath.Join(dir, "agent.yaml"))
			err := h.applyIngress(context.Background(), []config.EdgePublicIngress{{Interface: "wg0", SourceIP: "10.20.0.1", ListenIP: "10.20.0.2"}})
			if err == nil || !strings.Contains(err.Error(), "ownership marker") || queries == 0 || mutations != 0 {
				t.Fatal("foreign reserved chain overwritten", err, queries, mutations)
			}
			site := NewSiteLinks(cfg, filepath.Join(dir, "agent.yaml"))
			if err := site.firewall(context.Background(), cfg, nil, nil, false); err == nil || mutations != 0 {
				t.Fatal("site handler overwrote reserved foreign chain", err, mutations)
			}
			if _, err := os.Stat(s.Path); !os.IsNotExist(err) {
				t.Fatal("foreign state journaled", err)
			}
		})
	}
}

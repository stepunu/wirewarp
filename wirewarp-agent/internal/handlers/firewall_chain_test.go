package handlers

import (
	"context"
	"errors"
	"fmt"
	"github.com/wirewarp/agent/internal/config"
	"strings"
	"testing"
)

func TestSiteFirstApplyUsesNftTableInventoryForMissingChains(t *testing.T) {
	oldRun, oldRestore := edgeIPTables, edgeIPTablesRestore
	t.Cleanup(func() { edgeIPTables, edgeIPTablesRestore = oldRun, oldRestore })
	cfg, p := siteFixture("hub")
	commits := 0
	edgeIPTables = func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) == 3 {
			if args[1] == "filter" {
				return []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-N FOREIGN\n-A INPUT -j FOREIGN\n"), nil
			}
			if args[1] == "mangle" {
				return []byte("-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n"), nil
			}
			return []byte("-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n"), nil
		}
		chain := args[len(args)-1]
		if strings.HasPrefix(chain, "WW-SITE-") {
			return []byte(fmt.Sprintf("iptables v1.8.9 (nf_tables): chain `%s' in table `%s' is incompatible, use 'nft' tool.\n", chain, args[1])), errors.New("exit status 1")
		}
		return []byte("-P " + chain + " ACCEPT\n"), nil
	}
	edgeIPTablesRestore = func(ctx context.Context, input string) error {
		commits++
		if strings.Contains(input, "FOREIGN") {
			t.Fatal("foreign chain touched", input)
		}
		return nil
	}
	if err := reconcileSiteFirewall(context.Background(), cfg, p, p.TransitPeers, false); err != nil {
		t.Fatal("first apply rejected proven absent nft chains", err)
	}
	if commits != 3 {
		t.Fatal("expected filter, NAT, and MSS guard commits", commits)
	}
}

func TestNftIncompatibleExistingChainAndPermissionErrorsFailClosed(t *testing.T) {
	for _, kind := range []string{"existing", "permission", "incomplete-inventory", "inventory-error", "inventory-warning", "foreign-reference"} {
		t.Run(kind, func(t *testing.T) {
			oldRun, oldRestore := edgeIPTables, edgeIPTablesRestore
			t.Cleanup(func() { edgeIPTables, edgeIPTablesRestore = oldRun, oldRestore })
			commits := 0
			edgeIPTables = func(ctx context.Context, args ...string) ([]byte, error) {
				if len(args) == 3 {
					switch kind {
					case "existing":
						return []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-N WW-SITE-FWD\n"), nil
					case "inventory-error":
						return []byte("Permission denied"), errors.New("exit status 4")
					case "inventory-warning":
						return []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n# Table `filter' contains incompatible base-chains, use 'nft' tool to list them.\n"), nil
					case "foreign-reference":
						return []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A FORWARD -j WW-SITE-FWD\n"), nil
					default:
						return []byte(""), nil
					}
				}
				if kind == "permission" {
					return []byte("Permission denied (you must be root)"), errors.New("exit status 4")
				}
				return []byte("iptables v1.8.9 (nf_tables): chain `WW-SITE-FWD' in table `filter' is incompatible, use 'nft' tool."), errors.New("exit status 1")
			}
			edgeIPTablesRestore = func(context.Context, string) error { commits++; return nil }
			cfg, p := siteFixture("hub")
			if err := reconcileSiteFirewall(context.Background(), cfg, p, p.TransitPeers, false); err == nil || commits != 0 {
				t.Fatal("unsafe chain inspection allowed mutation", err, commits)
			}
		})
	}
}

func TestEdgeFirstApplyUsesNftTableInventoryForMissingChain(t *testing.T) {
	oldRun, oldRestore := edgeIPTables, edgeIPTablesRestore
	t.Cleanup(func() { edgeIPTables, edgeIPTablesRestore = oldRun, oldRestore })
	commits := 0
	edgeIPTables = func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) == 3 {
			return []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"), nil
		}
		if args[1] == "INPUT" {
			return []byte("-P INPUT ACCEPT\n"), nil
		}
		return []byte("iptables v1.8.9 (nf_tables): chain `WW-EDGE-INGRESS' in table `filter' is incompatible, use 'nft' tool."), errors.New("exit status 1")
	}
	edgeIPTablesRestore = func(ctx context.Context, input string) error {
		commits++
		if !strings.Contains(input, ":WW-EDGE-INGRESS") {
			t.Fatal("edge chain not created")
		}
		return nil
	}
	if err := reconcileEdgeIngress(context.Background(), []config.EdgePublicIngress{{Interface: "wg0", SourceIP: "10.20.0.1", ListenIP: "10.20.0.2"}}); err != nil || commits != 1 {
		t.Fatal("edge first apply failed", err, commits)
	}
}

func TestMissingChainBackendDiagnostics(t *testing.T) {
	old := edgeIPTables
	t.Cleanup(func() { edgeIPTables = old })
	calls := 0
	edgeIPTables = func(context.Context, ...string) ([]byte, error) {
		calls++
		return nil, errors.New("unexpected inventory")
	}
	for _, message := range []string{"iptables: No chain/target/match by that name.", "iptables v1.8.10 (nf_tables): No chain/target/match by that name.", "Chain 'WW-SITE-FWD' does not exist"} {
		if !missingOwnedChain(context.Background(), "filter", "WW-SITE-FWD", message) {
			t.Fatal("known missing-chain diagnostic rejected", message)
		}
	}
	if calls != 0 {
		t.Fatal("unambiguous missing-chain diagnostics required fallback", calls)
	}
	for _, message := range []string{"Permission denied (you must be root)", "iptables: Bad argument `-S'", "iptables: Resource temporarily unavailable"} {
		if missingOwnedChain(context.Background(), "filter", "WW-SITE-FWD", message) {
			t.Fatal("real failure treated as absence", message)
		}
	}
}

package handlers

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

func TestEdgeIngressAtomicRulesAndOwnedCleanup(t *testing.T) {
	oldRun, oldRestore := edgeIPTables, edgeIPTablesRestore
	t.Cleanup(func() { edgeIPTables, edgeIPTablesRestore = oldRun, oldRestore })
	ingress := []config.EdgePublicIngress{{Interface: "wg0", SourceIP: "10.20.0.1", ListenIP: "10.20.0.2"}}
	input := "-P INPUT ACCEPT\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A INPUT -j OTHER-CHAIN\n"
	chain := ""
	var transactions []string
	edgeIPTables = func(_ context.Context, args ...string) ([]byte, error) {
		if reflect.DeepEqual(args, []string{"-S", "INPUT"}) {
			return []byte(input), nil
		}
		if !reflect.DeepEqual(args, []string{"-S", edgeIngressChain}) {
			t.Fatalf("unexpected firewall query: %v", args)
		}
		if chain == "" {
			return []byte("No chain/target/match by that name."), errors.New("missing")
		}
		return []byte(chain), nil
	}
	edgeIPTablesRestore = func(_ context.Context, body string) error { transactions = append(transactions, body); return nil }
	if err := reconcileEdgeIngress(context.Background(), ingress); err != nil {
		t.Fatal(err)
	}
	want := "*filter\n:WW-EDGE-INGRESS - [0:0]\n-F WW-EDGE-INGRESS\n-A WW-EDGE-INGRESS -i wg0 -s 10.20.0.1/32 -d 10.20.0.2/32 -p tcp -m multiport --dports 80,443 -j ACCEPT\n-A WW-EDGE-INGRESS -i lo -s 10.20.0.2/32 -d 10.20.0.2/32 -p tcp -m multiport --dports 80,443 -j ACCEPT\n-A WW-EDGE-INGRESS -d 10.20.0.2/32 -p tcp -m multiport --dports 80,443 -j DROP\n-I INPUT 1 -m comment --comment wirewarp-edge-ingress -j WW-EDGE-INGRESS\nCOMMIT\n"
	if transactions[0] != want {
		t.Fatalf("unsafe firewall transaction:\n%s", transactions[0])
	}
	// Restore removes only exact owned jumps, including duplicates and quotes.
	input += "-A INPUT -m comment --comment \"wirewarp-edge-ingress\" -j WW-EDGE-INGRESS\n-A INPUT -m comment --comment wirewarp-edge-ingress -j WW-EDGE-INGRESS\n"
	chain = "-N WW-EDGE-INGRESS\n-A WW-EDGE-INGRESS -j ACCEPT\n"
	if err := reconcileEdgeIngress(context.Background(), ingress); err != nil {
		t.Fatal(err)
	}
	if strings.Count(transactions[1], "-D INPUT -m comment --comment wirewarp-edge-ingress -j WW-EDGE-INGRESS") != 2 || !strings.Contains(transactions[1], "-I INPUT 1") {
		t.Fatal("drift did not restore first INPUT guard and remove duplicates")
	}
	if err := reconcileEdgeIngress(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	cleanup := transactions[2]
	if strings.Contains(cleanup, "-I INPUT") || !strings.Contains(cleanup, "-F WW-EDGE-INGRESS\n") || !strings.Contains(cleanup, "-X WW-EDGE-INGRESS\n") || strings.Contains(cleanup, "OTHER-CHAIN") || strings.Contains(cleanup, "-F INPUT") || strings.Contains(cleanup, "*nat") || strings.Contains(cleanup, "FORWARD") {
		t.Fatalf("cleanup changed unrelated rules:\n%s", cleanup)
	}
	input, chain = "-P INPUT ACCEPT\n", ""
	if err := reconcileEdgeIngress(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(transactions) != 3 {
		t.Fatal("empty cleanup changed an absent chain")
	}
}

func TestEdgeIngressInspectionAndCommitFailuresAreExplicit(t *testing.T) {
	oldRun, oldRestore := edgeIPTables, edgeIPTablesRestore
	t.Cleanup(func() { edgeIPTables, edgeIPTablesRestore = oldRun, oldRestore })
	edgeIPTables = func(context.Context, ...string) ([]byte, error) {
		return []byte("Permission denied"), errors.New("no privilege")
	}
	edgeIPTablesRestore = func(context.Context, string) error { t.Fatal("failed inspection wrote firewall"); return nil }
	if err := reconcileEdgeIngress(context.Background(), nil); err == nil {
		t.Fatal("inspection failure masked")
	}
	edgeIPTables = func(_ context.Context, args ...string) ([]byte, error) { return []byte("-N WW-EDGE-INGRESS\n"), nil }
	edgeIPTablesRestore = func(context.Context, string) error { return errors.New("atomic commit failed") }
	if err := reconcileEdgeIngress(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "atomic commit failed") {
		t.Fatal("atomic commit failure masked")
	}
}

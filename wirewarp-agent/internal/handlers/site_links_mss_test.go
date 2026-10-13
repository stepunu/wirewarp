package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wirewarp/agent/internal/config"
	"path/filepath"
	"strings"
	"testing"
)

func TestSiteMSSApplyFailureRetainsDenyAndOfflineRetry(t *testing.T) {
	oldRun, oldRestore, oldPreflight := edgeIPTables, edgeIPTablesRestore, firewallOwnershipPreflight
	t.Cleanup(func() {
		edgeIPTables, edgeIPTablesRestore, firewallOwnershipPreflight = oldRun, oldRestore, oldPreflight
	})
	collected := []string{}
	failed := false
	edgeIPTables = func(_ context.Context, args ...string) ([]byte, error) {
		if strings.HasPrefix(args[len(args)-1], "WW-SITE-") {
			return []byte("No chain/target/match by that name"), errors.New("exit status 1")
		}
		return []byte("-P " + args[len(args)-1] + " ACCEPT\n"), nil
	}
	edgeIPTablesRestore = func(_ context.Context, input string) error {
		collected = append(collected, input)
		if !failed && strings.Contains(input, "--set-mss 1240") {
			failed = true
			return errors.New("MSS apply denied")
		}
		return nil
	}
	firewallOwnershipPreflight = func(context.Context, map[string][]string) error { return nil }
	cfg, p := siteFixture("hub")
	path := filepath.Join(t.TempDir(), "agent.yaml")
	h := NewSiteLinks(cfg, path)
	h.ownership = func(context.Context, *config.Config, *config.SiteLinkSnapshot) error { return nil }
	h.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	h.routesApply = h.routesPreflight
	h.persistFirewall = func(context.Context) error { return nil }
	phases := []string{}
	h.SetEmit(func(_ string, payload map[string]any) error {
		phases = append(phases, payload["phase"].(string))
		return nil
	})
	raw, _ := json.Marshal(p)
	if _, err := h.handleDesired(raw); err == nil || !strings.Contains(err.Error(), "MSS apply denied") {
		t.Fatal("MSS failure hidden", err)
	}
	if cfg.Snapshot().SiteLinkApplied != nil || len(collected) == 0 || strings.Contains(collected[len(collected)-1], "--set-mss") {
		t.Fatal("failed MSS retained permissions")
	}
	for _, phase := range phases {
		if phase == "applied" {
			t.Fatal("failed clamp acknowledged applied")
		}
	}
	loaded, err := config.Load(path)
	if err != nil || loaded.SiteLinkDesired == nil || loaded.SiteLinkApplied != nil {
		t.Fatal("restart lost unapplied desired state", err)
	}
	restarted := NewSiteLinks(loaded, path)
	restarted.ownership = h.ownership
	restarted.routesPreflight = h.routesPreflight
	restarted.routesApply = h.routesApply
	restarted.persistFirewall = h.persistFirewall
	if err := restarted.reconcileLocked(context.Background()); err != nil {
		t.Fatal("offline MSS retry failed", err)
	}
	if loaded.Snapshot().SiteLinkApplied == nil || !strings.Contains(collected[len(collected)-1], "--set-mss 1240") {
		t.Fatal("offline retry did not restore clamp")
	}
}

func TestSiteMSSSelectedRolesDirectionsAndPorts(t *testing.T) {
	for _, role := range []string{"hub", "source", "destination"} {
		t.Run(role, func(t *testing.T) {
			kind := "gateway"
			if role == "hub" {
				kind = "hub"
			}
			cfg, p := siteFixture(kind)
			if role == "destination" {
				cfg.AgentID = siteBID
				cfg.Attachments[0].AttachmentID = siteBAtt
			}
			p.Links[0].AccessRules = []config.SiteLinkAccessRule{{Direction: "a_to_b", DestinationCIDRs: []string{"192.168.0.11/32"}, Protocol: "tcp", DestinationPorts: []int{8006}}}
			rules := siteFirewallRules(cfg, p, p.TransitPeers, true)[siteMSSChain]
			expected := 1
			if role == "hub" {
				expected = 2
			}
			if len(rules) != expected {
				t.Fatalf("clamp count=%d expected=%d", len(rules), expected)
			}
			for _, rule := range rules {
				for _, scope := range []string{"-p tcp --tcp-flags SYN,RST SYN", "-o wg0", "--ctorigsrc 192.168.20.0/24", "--ctorigdst 192.168.0.11/32", "--ctproto tcp", "--ctorigdstport 8006", "--set-mss 1240", "--comment " + siteComment} {
					if !strings.Contains(rule, scope) {
						t.Fatal("MSS clamp lost authorized scope", rule, scope)
					}
				}
				if role == "source" && !strings.Contains(rule, "--ctdir ORIGINAL") {
					t.Fatal("source rule affects reverse traffic")
				}
				if role == "destination" && !strings.Contains(rule, "--ctdir REPLY") {
					t.Fatal("destination rule affects new reverse traffic")
				}
			}
			if len(siteFirewallRules(cfg, p, p.TransitPeers, false)[siteMSSChain]) != 0 {
				t.Fatal("staged deny state retained active MSS rules")
			}
		})
	}
}

func TestSiteMSSDoesNotTouchDisabledUDPOrUnlinkedFlows(t *testing.T) {
	cfg, p := siteFixture("hub")
	p.Links[0].AccessRules = []config.SiteLinkAccessRule{{Direction: "a_to_b", DestinationCIDRs: []string{"192.168.0.0/24"}, Protocol: "udp"}}
	if len(siteMSSRules(cfg, p)) != 0 {
		t.Fatal("UDP flow gained TCP MSS policy")
	}
	p.Links[0].AccessRules = nil
	p.Links[0].Enabled = false
	if len(siteMSSRules(cfg, p)) != 0 {
		t.Fatal("disabled link retained TCP policy")
	}
	p.Links = nil
	if len(siteMSSRules(cfg, p)) != 0 {
		t.Fatal("unlinked inventory gained TCP policy")
	}
}

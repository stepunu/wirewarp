package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

func TestSiteHubGuardClassifiesAllAuthenticatedTunnelSources(t *testing.T) {
	for _, allow := range []bool{false, true} {
		cfg, p := siteFixture("hub")
		cfg.Server.WGInterface = "wg7"
		rules := siteFirewallRules(cfg, p, p.TransitPeers, allow)
		guard := "-A WW-SITE-FWD -i wg7 -d 192.168.20.0/24 -m comment --comment wirewarp-site-links -j DROP"
		lines := strings.Join(rules["WW-SITE-FWD"], "\n")
		if !strings.Contains(lines, guard) {
			t.Fatal("own peer tunnel source can bypass LAN classification", lines)
		}
		if allow && strings.Index(lines, guard) < strings.LastIndex(lines, "--ctdir REPLY") {
			t.Fatal("guard blocks authorized original/reply flows")
		}
		for _, line := range rules["WW-SITE-FWD"] {
			if strings.Contains(line, "-i wg7 -d ") && strings.HasSuffix(line, "-j DROP") {
				break
			}
			if !strings.Contains(line, "--ctorigsrc ") || !strings.Contains(line, "--ctorigdst ") || !strings.HasSuffix(line, "-j ACCEPT") {
				t.Fatal("unscoped trust can bypass ingress guard, including a claimed hub source IP", line)
			}
		}
		if strings.Contains(guard, "-s ") {
			t.Fatal("hub trust is based on spoofable source address")
		}
		if strings.Contains(strings.Join(rules["WW-SITE-IN"], "\n"), "-i wg7 -d ") || strings.Contains(strings.Join(rules["WW-SITE-OUT"], "\n"), "-i wg7 -d ") {
			t.Fatal("ingress guard changes hub-local management")
		}
	}
}

func TestSiteHubMissingIngressIdentityHasNoEffects(t *testing.T) {
	cfg, p := siteFixture("hub")
	cfg.Server = nil
	path := filepath.Join(t.TempDir(), "agent.yaml")
	h := NewSiteLinks(cfg, path)
	h.firewall = func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error {
		t.Fatal("missing metadata reached firewall")
		return nil
	}
	raw, _ := json.Marshal(p)
	if _, err := h.handleDesired(raw); err == nil {
		t.Fatal("missing authenticated interface accepted")
	}
	if cfg.Snapshot().SiteLinkDesired != nil {
		t.Fatal("invalid snapshot persisted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid snapshot wrote config", err)
	}
}

func TestSiteHubBootstrapStagesGuardAndHealsAfterWireGuardReady(t *testing.T) {
	cfg, p := siteFixture("hub")
	cfg.Server = nil
	p.HubWGInterface = "wg9"
	p.DesiredHash = siteSnapshotHash(p)
	path := filepath.Join(t.TempDir(), "agent.yaml")
	h := NewSiteLinks(cfg, path)
	allowed, routes := 0, 0
	h.firewall = func(_ context.Context, saved *config.Config, snapshot *config.SiteLinkSnapshot, peers []config.SiteLinkTransitPeer, allow bool) error {
		compiled := strings.Join(siteFirewallRules(saved, snapshot, peers, allow)["WW-SITE-FWD"], "\n")
		if !strings.Contains(compiled, "-i wg9 -d 192.168.20.0/24 ") {
			t.Fatal("bootstrap/offline retry omitted authenticated ingress guard")
		}
		if allow {
			allowed++
		}
		return nil
	}
	oldNetwork := siteNetworkCommand
	defer func() { siteNetworkCommand = oldNetwork }()
	siteNetworkCommand = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(p.TransitPeers[0].WireGuardPublicKey + " 10.21.0.10/32,192.168.20.0/24\n" + p.TransitPeers[1].WireGuardPublicKey + " 10.21.0.20/32,192.168.0.0/24\n"), nil
	}
	h.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	h.routesApply = func(_ context.Context, _ []config.SiteLinkRoute, plan []config.SiteLinkRoute) error {
		if cfg.Snapshot().Server == nil || !cfg.Snapshot().Server.Initialized {
			t.Fatal("route installed before WireGuard initialization")
		}
		for _, route := range plan {
			if route.Interface != "wg9" {
				t.Fatal("route guessed another interface")
			}
		}
		routes++
		return nil
	}
	raw, _ := json.Marshal(p)
	if _, err := h.handleDesired(raw); !errors.Is(err, errSitePeerPending) {
		t.Fatal("bootstrap did not retain pending ownership", err)
	}
	saved, err := config.Load(path)
	if err != nil || saved.Snapshot().SiteLinkDesired == nil || saved.Snapshot().SiteLinkDesired.HubWGInterface != "wg9" || saved.Snapshot().SiteLinkApplied != nil || allowed != 0 || routes != 0 {
		t.Fatal("bootstrap did not persist only deny intent", err)
	}
	if err := h.reconcileLocked(context.Background()); !errors.Is(err, errSitePeerPending) {
		t.Fatal("pre-WG retry forgot pending guard", err)
	}
	if err := cfg.UpdateAndSave(path, func(next *config.Config) error {
		next.Server = &config.ServerState{WGInterface: "wg9", Initialized: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.reconcileLocked(context.Background()); err != nil {
		t.Fatal("WireGuard init did not heal retained target", err)
	}
	if cfg.Snapshot().SiteLinkApplied == nil || allowed != 1 || routes != 1 {
		t.Fatal("ready target did not converge")
	}
}

func TestSiteHubIngressMetadataCannotRetargetSavedNetworking(t *testing.T) {
	for _, name := range []string{"wg0 -j ACCEPT", "wg8"} {
		cfg, p := siteFixture("hub")
		p.HubWGInterface = name
		p.DesiredHash = siteSnapshotHash(p)
		if err := validateSiteSnapshot(cfg, p); err == nil {
			t.Fatal("invalid or conflicting interface accepted", name)
		}
	}
}

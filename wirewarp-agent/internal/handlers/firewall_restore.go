package handlers

import (
	"context"
	"fmt"
	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/firewall"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var firewallOwnershipPreflight = firewall.Preflight

func preflightFirewallOwnership(ctx context.Context, saved *config.Config) error {
	legacy := map[string][]string{"filter": {}, "nat": {}, "mangle": {}}
	add := func(table, line string) {
		line = strings.ReplaceAll(line, " -m comment --comment wirewarp-edge-ingress", "")
		line = strings.ReplaceAll(line, " -m comment --comment wirewarp-site-links", "")
		legacy[table] = append(legacy[table], line)
	}
	for _, line := range edgeIngressRules(savedEdgeIngress(saved)) {
		add("filter", line)
	}
	if saved.SiteLinkDesired != nil && validateSiteSnapshot(saved, saved.SiteLinkDesired) == nil {
		for _, allow := range []bool{false, true} {
			if allow && saved.SiteLinkApplied == nil {
				continue
			}
			p := saved.SiteLinkDesired
			if allow {
				p = saved.SiteLinkApplied
			}
			for chain, rules := range siteFirewallRules(saved, p, siteUnionPeers(saved.SiteLinkGuardPeers, p.TransitPeers), allow) {
				table := "filter"
				if chain == "WW-SITE-NAT" {
					table = "nat"
				}
				for _, line := range rules {
					add(table, line)
				}
			}
		}
	}
	return firewallOwnershipPreflight(ctx, legacy)
}

func ConfigureFirewallPersistence(cfg *config.Config, path string) {
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	firewall.Configure(func() (string, string) { return cfg.Snapshot().AgentID, path }, func(ctx context.Context) error {
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		return EnsureRoutingUnitContext(ctx, binary, path)
	}, func(in, out string) bool {
		saved := cfg.Snapshot()
		if !saved.Gateway() {
			return false
		}
		for _, att := range saved.Attachments {
			if att.IsGateway && (in == att.WGInterface && out == att.LANIface || out == att.WGInterface && in == att.LANIface) {
				return true
			}
		}
		return false
	})
}
func RestoreFirewall(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := firewall.Check(ctx); err != nil {
		return err
	}
	if err := firewall.Restore(ctx); err != nil {
		return fmt.Errorf("restore owned firewall journal: %w", err)
	}
	if err := RestoreEdgeIngressGuard(ctx, cfg); err != nil {
		return err
	}
	return RestoreSiteLinkGuard(ctx, cfg)
}

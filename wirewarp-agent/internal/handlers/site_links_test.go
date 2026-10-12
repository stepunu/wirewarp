package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

const siteHubID = "00000000-0000-4000-8000-000000000001"
const siteAID = "00000000-0000-4000-8000-000000000002"
const siteBID = "00000000-0000-4000-8000-000000000003"
const siteAAtt = "00000000-0000-4000-8000-000000000004"
const siteBAtt = "00000000-0000-4000-8000-000000000005"
const siteLinkID = "00000000-0000-4000-8000-000000000006"

func siteFixture(role string) (*config.Config, *config.SiteLinkSnapshot) {
	keyA := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	keyB := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	gateway := true
	p := &config.SiteLinkSnapshot{SchemaVersion: 1, Revision: 1, NodeRole: role, Links: []config.SiteLink{{ID: siteLinkID, Enabled: true, HubAgentID: siteHubID, SiteA: config.SiteLinkSite{GatewayAgentID: siteAID, AttachmentID: siteAAtt, Subnets: []string{"192.168.20.0/24"}}, SiteB: config.SiteLinkSite{GatewayAgentID: siteBID, AttachmentID: siteBAtt, Subnets: []string{"192.168.0.0/24"}}, AllowNewAToB: true, SNATAtA: "preserve", SNATAtB: "gateway_lan_ip"}}, TransitPeers: []config.SiteLinkTransitPeer{{GatewayAgentID: siteAID, AttachmentID: siteAAtt, AdvertisedSubnets: []string{"192.168.20.0/24"}, WireGuardPublicKey: keyA}, {GatewayAgentID: siteBID, AttachmentID: siteBAtt, AdvertisedSubnets: []string{"192.168.0.0/24"}, WireGuardPublicKey: keyB}}}
	cfg := &config.Config{Mode: "server", AgentID: siteHubID, Server: &config.ServerState{Initialized: true, WGInterface: "wg0"}}
	if role == "gateway" {
		cfg = &config.Config{Mode: "client", AgentID: siteAID, IsGateway: &gateway, Attachments: []config.AttachmentState{{AttachmentID: siteAAtt, IsGateway: true, WGInterface: "wg0", LANIface: "eth0", LANIP: "192.168.20.110", LANNetwork: "192.168.20.0/24", VPSTunnelIP: "10.21.0.1", ServerPublicKey: keyB, Fwmark: "0x101"}}}
	}
	p.DesiredHash = siteSnapshotHash(p)
	return cfg, p
}

func TestSiteSnapshotValidationBeforeEffects(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*config.Config, *config.SiteLinkSnapshot)
	}{
		{"plain-client", func(c *config.Config, p *config.SiteLinkSnapshot) {
			c.Mode = "client"
			v := false
			c.IsGateway = &v
			p.NodeRole = "gateway"
		}},
		{"node-bound", func(c *config.Config, p *config.SiteLinkSnapshot) { c.AgentID = siteBID }},
		{"overlap", func(c *config.Config, p *config.SiteLinkSnapshot) {
			p.TransitPeers[1].AdvertisedSubnets = []string{"192.168.20.0/24"}
		}},
		{"invalid-key", func(c *config.Config, p *config.SiteLinkSnapshot) { p.TransitPeers[1].WireGuardPublicKey = "invalid" }},
		{"outside-rule", func(c *config.Config, p *config.SiteLinkSnapshot) {
			p.Links[0].AccessRules = []config.SiteLinkAccessRule{{Direction: "a_to_b", DestinationCIDRs: []string{"10.0.0.0/8"}, Protocol: "tcp"}}
		}},
		{"bad-port", func(c *config.Config, p *config.SiteLinkSnapshot) {
			p.Links[0].AccessRules = []config.SiteLinkAccessRule{{Direction: "a_to_b", DestinationCIDRs: []string{"192.168.0.0/24"}, Protocol: "icmp", DestinationPorts: []int{80}}}
		}},
		{"ipv6", func(c *config.Config, p *config.SiteLinkSnapshot) {
			p.TransitPeers[0].AdvertisedSubnets = []string{"fd00::/64"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, p := siteFixture("hub")
			test.change(cfg, p)
			p.DesiredHash = siteSnapshotHash(p)
			h := NewSiteLinks(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
			h.firewall = func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error {
				t.Fatal("invalid snapshot reached firewall")
				return nil
			}
			h.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error {
				t.Fatal("invalid snapshot reached route preflight")
				return nil
			}
			raw, _ := json.Marshal(p)
			if _, err := h.handleDesired(raw); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestSiteHashAndRevisionRejectTampering(t *testing.T) {
	cfg, p := siteFixture("hub")
	if err := validateSiteSnapshot(cfg, p); err != nil {
		t.Fatal(err)
	}
	cfg.SiteLinkDesired = p
	copy := *p
	copy.Revision = 0
	if validateSiteSnapshot(cfg, &copy) == nil {
		t.Fatal("stale revision accepted")
	}
	copy = *p
	copy.Links = append([]config.SiteLink{}, p.Links...)
	copy.Links[0].AllowNewBToA = true
	if validateSiteSnapshot(cfg, &copy) == nil {
		t.Fatal("tampered payload accepted")
	}
	copy.DesiredHash = siteSnapshotHash(&copy)
	if validateSiteSnapshot(cfg, &copy) == nil {
		t.Fatal("equal revision conflicting hash accepted")
	}
}

func TestSitePeerReplayStaysDeniedUntilOwnershipReady(t *testing.T) {
	cfg, p := siteFixture("hub")
	path := filepath.Join(t.TempDir(), "agent.yaml")
	h := NewSiteLinks(cfg, path)
	var permissions []bool
	var phases []string
	ready := false
	h.firewall = func(_ context.Context, _ *config.Config, _ *config.SiteLinkSnapshot, _ []config.SiteLinkTransitPeer, allow bool) error {
		permissions = append(permissions, allow)
		return nil
	}
	h.ownership = func(context.Context, *config.Config, *config.SiteLinkSnapshot) error {
		if !ready {
			return errors.New("peer missing")
		}
		return nil
	}
	h.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	h.routesApply = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	h.SetEmit(func(_ string, payload map[string]any) error {
		phases = append(phases, payload["phase"].(string))
		return nil
	})
	raw, _ := json.Marshal(p)
	if _, err := h.handleDesired(raw); err == nil {
		t.Fatal("missing peer reported success")
	}
	saved, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.SiteLinkDesired == nil || saved.SiteLinkApplied != nil || len(saved.SiteLinkGuardPeers) == 0 {
		t.Fatal("pending target/guard not persisted")
	}
	for _, allow := range permissions {
		if allow {
			t.Fatal("missing peer enabled transit")
		}
	}
	ready = true
	restarted := NewSiteLinks(saved, path)
	restarted.firewall = h.firewall
	restarted.ownership = h.ownership
	restarted.routesPreflight = h.routesPreflight
	restarted.routesApply = h.routesApply
	restarted.SetEmit(func(_ string, payload map[string]any) error {
		phases = append(phases, payload["phase"].(string))
		return nil
	})
	if err := restarted.reconcileLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if saved.Snapshot().SiteLinkApplied == nil || phases[len(phases)-1] != "applied" {
		t.Fatal("ready replay not applied")
	}
}

func TestSitePermissionsUseOriginalDirectionAndScopedSNAT(t *testing.T) {
	cfg, p := siteFixture("gateway")
	cfg.AgentID = siteBID
	cfg.Attachments[0].AttachmentID = siteBAtt
	cfg.Attachments[0].LANNetwork = "192.168.0.0/24"
	cfg.Attachments[0].LANIP = "192.168.0.110"
	rules := siteFirewallRules(cfg, p, p.TransitPeers, true)
	forward := strings.Join(rules["WW-SITE-FWD"], "\n")
	if !strings.Contains(forward, "--ctorigsrc 192.168.20.0/24 --ctorigdst 192.168.0.0/24") || !strings.Contains(forward, "--ctdir REPLY --ctstate ESTABLISHED,RELATED") {
		t.Fatal("stateful reply lacks original-direction scope")
	}
	if strings.Contains(forward, "--ctorigsrc 192.168.0.0/24 --ctorigdst 192.168.20.0/24") {
		t.Fatal("reverse new direction allowed")
	}
	nat := strings.Join(rules["WW-SITE-NAT"], "\n")
	if !strings.Contains(nat, "-o eth0") || !strings.Contains(nat, "--mark 0x101") || !strings.Contains(nat, "--to-source 192.168.0.110") {
		t.Fatal("destination SNAT not scoped to attachment/LAN")
	}
	p.Links[0].SNATAtB = "preserve"
	nat = strings.Join(siteFirewallRules(cfg, p, p.TransitPeers, true)["WW-SITE-NAT"], "\n")
	if !strings.Contains(nat, "-j ACCEPT") || strings.Contains(nat, "SNAT") {
		t.Fatal("preserve does not bypass generic masquerade")
	}
}

func TestSiteNonemptyRulesDoNotOpenUnmatchedDirection(t *testing.T) {
	_, p := siteFixture("hub")
	p.Links[0].AllowNewBToA = true
	p.Links[0].AccessRules = []config.SiteLinkAccessRule{{Direction: "a_to_b", DestinationCIDRs: []string{"192.168.0.10/32"}, Protocol: "tcp", DestinationPorts: []int{443}}}
	flows := compileSiteFlows(p)
	if len(flows) != 1 || flows[0].port != 443 || flows[0].destination != "192.168.0.10/32" || flows[0].source != "192.168.20.0/24" {
		t.Fatal("access rule direction/destination compiler mismatch")
	}
}

func TestSiteRoutePlanIncludesOneWayRepliesBeforeLANPin(t *testing.T) {
	cfg, p := siteFixture("hub")
	routes, err := siteRoutePlan(cfg, p)
	if err != nil || len(routes) != 2 {
		t.Fatalf("one-way forward/reply routes: %v %v", routes, err)
	}
	for _, route := range routes {
		if route.Priority <= 4500 || route.Priority >= 5000 || route.Table < 60000 {
			t.Fatal("site route shares attachment table or wrong priority")
		}
	}
}

func TestSiteEmptyLinksKeepGuardInventory(t *testing.T) {
	cfg, p := siteFixture("hub")
	p.Links = nil
	rules := siteFirewallRules(cfg, p, p.TransitPeers, true)
	if len(rules["WW-SITE-DST"]) != 2 || strings.Contains(strings.Join(rules["WW-SITE-FWD"], "\n"), "ACCEPT") {
		t.Fatal("final link deletion reopened implicit transit")
	}
	routes, err := siteRoutePlan(cfg, p)
	if err != nil || len(routes) != 0 {
		t.Fatal("deleted links retained routes")
	}
}

func TestSiteApplyFailureNeverAcknowledgesApplied(t *testing.T) {
	cfg, p := siteFixture("hub")
	h := NewSiteLinks(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	h.firewall = func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error {
		return nil
	}
	h.ownership = func(context.Context, *config.Config, *config.SiteLinkSnapshot) error { return nil }
	h.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	h.routesApply = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error {
		return errors.New("route failure")
	}
	h.SetEmit(func(_ string, payload map[string]any) error {
		if payload["phase"] == "applied" {
			t.Fatal("failed host apply acknowledged")
		}
		return nil
	})
	raw, _ := json.Marshal(p)
	if _, err := h.handleDesired(raw); err == nil {
		t.Fatal("apply failure masked")
	}
	if cfg.Snapshot().SiteLinkApplied != nil {
		t.Fatal("failed apply persisted as applied")
	}
	if len(cfg.Snapshot().SiteLinkRoutes) != 2 {
		t.Fatal("partial route ownership not persisted for cleanup")
	}
}

func TestSiteTCPProbeRejectsOutOfScopeBeforeNetwork(t *testing.T) {
	cfg, p := siteFixture("gateway")
	cfg.SiteLinkDesired = p
	cfg.SiteLinkApplied = p
	h := NewSiteLinks(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	h.ownership = func(context.Context, *config.Config, *config.SiteLinkSnapshot) error {
		t.Fatal("out-of-scope probe reached network")
		return nil
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": 1, "link_id": siteLinkID, "revision": p.Revision, "desired_hash": p.DesiredHash, "direction": "b_to_a", "destination_ip": "192.168.20.10", "destination_port": 443, "protocol": "tcp", "timeout_seconds": 5})
	if _, err := h.handleTest(raw); err == nil {
		t.Fatal("reverse probe accepted")
	}
}

func TestSiteUnknownPeerKeyIsPendingGuardInventory(t *testing.T) {
	cfg, p := siteFixture("hub")
	p.TransitPeers[1].WireGuardPublicKey = ""
	p.DesiredHash = siteSnapshotHash(p)
	if err := validateSiteSnapshot(cfg, p); err != nil {
		t.Fatal(err)
	}
	old := siteNetworkCommand
	defer func() { siteNetworkCommand = old }()
	siteNetworkCommand = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("pending key reached network inspection")
		return nil, nil
	}
	if err := verifySiteOwnership(context.Background(), cfg, p); err == nil {
		t.Fatal("pending key marked ready")
	}
	rules := siteFirewallRules(cfg, p, p.TransitPeers, false)
	if len(rules["WW-SITE-DST"]) != 2 {
		t.Fatal("pending peer LAN not guarded")
	}
}

func TestSiteOwnedRoutePreflightRejectsPriorityAndTableConflicts(t *testing.T) {
	for _, test := range []struct{ name, rules, routes string }{
		{"priority", `[{"priority":4501,"table":999,"src":"192.168.20.0/24","dst":"192.168.0.0/24","protocol":242}]`, `[]`},
		{"occupied-table", `[]`, `[{"dst":"default","protocol":242}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, p := siteFixture("hub")
			plan, err := siteRoutePlan(cfg, p)
			if err != nil {
				t.Fatal(err)
			}
			old := siteNetworkCommand
			defer func() { siteNetworkCommand = old }()
			siteNetworkCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "rule show") {
					return []byte(test.rules), nil
				}
				return []byte(test.routes), nil
			}
			if preflightSiteRoutes(context.Background(), nil, plan) == nil {
				t.Fatal("conflicting host policy accepted")
			}
		})
	}
}

func TestSiteGatewayPeerCannotBypassGuardReadiness(t *testing.T) {
	cfg, p := siteFixture("hub")
	cfg.SiteLinkDesired = p
	for _, allowed := range [][]string{{"192.168.0.0/24"}, {"0.0.0.0/0"}, {"192.168.20.0/24", "192.168.0.0/24"}} {
		if err := ensureSitePeerGuard(cfg, p.TransitPeers[0].WireGuardPublicKey, allowed); err == nil {
			t.Fatal("unsafe gateway peer ownership accepted")
		}
	}
	if err := ensureSitePeerGuard(cfg, "missing", []string{"192.168.20.0/24"}); err == nil {
		t.Fatal("gateway absent from saved inventory accepted")
	}
}

func TestSiteGuardIntentPersistsBeforeFirewallFailure(t *testing.T) {
	cfg, p := siteFixture("hub")
	path := filepath.Join(t.TempDir(), "agent.yaml")
	h := NewSiteLinks(cfg, path)
	h.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	h.firewall = func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error {
		return errors.New("firewall failure")
	}
	raw, _ := json.Marshal(p)
	if _, err := h.handleDesired(raw); err == nil {
		t.Fatal("staging failure masked")
	}
	saved, err := config.Load(path)
	if err != nil || saved.SiteLinkDesired == nil || len(saved.SiteLinkGuardPeers) != 2 || saved.SiteLinkApplied != nil {
		t.Fatal("restart lost pending guard intent")
	}
}

func TestSitePolicyJSONPrefixLengthsAreNormalized(t *testing.T) {
	rule := map[string]any{"src": "192.168.20.0", "srclen": float64(24), "dst": "192.168.0.10", "dstlen": float64(32)}
	if siteRulePrefix(rule, "src") != "192.168.20.0/24" || siteRulePrefix(rule, "dst") != "192.168.0.10/32" {
		t.Fatal("Linux ip JSON prefix lengths lost")
	}
}

func TestSiteGatewayPeerInstallsDenyGuardBeforeAdmission(t *testing.T) {
	cfg, p := siteFixture("hub")
	cfg.SiteLinkDesired = p
	oldRun, oldRestore := edgeIPTables, edgeIPTablesRestore
	defer func() { edgeIPTables, edgeIPTablesRestore = oldRun, oldRestore }()
	writes := 0
	edgeIPTables = func(context.Context, ...string) ([]byte, error) { return []byte("-P FORWARD ACCEPT\n"), nil }
	edgeIPTablesRestore = func(_ context.Context, input string) error {
		if strings.Contains(input, "--ctdir ORIGINAL") {
			t.Fatal("peer admission opened permissions before ownership check")
		}
		if strings.Contains(input, "WW-SITE-DST") {
			writes++
		}
		return nil
	}
	if err := ensureSitePeerGuard(cfg, p.TransitPeers[0].WireGuardPublicKey, []string{"192.168.20.0/24", "10.21.0.10/32"}); err != nil {
		t.Fatal(err)
	}
	if writes == 0 {
		t.Fatal("gateway admitted without deny guard")
	}
	edgeIPTablesRestore = func(context.Context, string) error { return errors.New("restore failed") }
	if err := ensureSitePeerGuard(cfg, p.TransitPeers[0].WireGuardPublicKey, []string{"192.168.20.0/24"}); err == nil {
		t.Fatal("gateway admitted after guard failure")
	}
}

func TestSiteLiveHubAllowedIPsOwnershipRejectsConflicts(t *testing.T) {
	cfg, p := siteFixture("hub")
	old := siteNetworkCommand
	defer func() { siteNetworkCommand = old }()
	for _, test := range []struct {
		name, output string
		ok           bool
	}{
		{"owned", p.TransitPeers[0].WireGuardPublicKey + "\t192.168.20.0/24,10.21.0.10/32\n" + p.TransitPeers[1].WireGuardPublicKey + "\t192.168.0.0/24,10.21.0.20/32\n", true},
		{"missing", p.TransitPeers[0].WireGuardPublicKey + "\t192.168.20.0/24\n", false},
		{"broad", p.TransitPeers[0].WireGuardPublicKey + "\t0.0.0.0/0\n" + p.TransitPeers[1].WireGuardPublicKey + "\t192.168.0.0/24\n", false},
		{"foreign", p.TransitPeers[0].WireGuardPublicKey + "\t192.168.20.0/24\n" + p.TransitPeers[1].WireGuardPublicKey + "\t192.168.0.0/24\nforeign\t192.168.20.0/25\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			siteNetworkCommand = func(context.Context, string, ...string) ([]byte, error) { return []byte(test.output), nil }
			if err := verifySiteOwnership(context.Background(), cfg, p); (err == nil) != test.ok {
				t.Fatalf("ownership result: %v", err)
			}
		})
	}
}

func TestSitePendingReadinessAcknowledgesApplying(t *testing.T) {
	cfg, p := siteFixture("hub")
	p.TransitPeers[1].WireGuardPublicKey = ""
	p.DesiredHash = siteSnapshotHash(p)
	h := NewSiteLinks(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	h.firewall = func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error {
		return nil
	}
	h.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	var phases []string
	h.SetEmit(func(_ string, payload map[string]any) error {
		phases = append(phases, payload["phase"].(string))
		return nil
	})
	raw, _ := json.Marshal(p)
	if _, err := h.handleDesired(raw); err == nil {
		t.Fatal("pending ownership masked as success")
	}
	for _, phase := range phases {
		if phase != "applying" {
			t.Fatalf("pending phase: %v", phases)
		}
	}
}

func TestSiteEmptySnapshotRemainsBoundToNodeIdentity(t *testing.T) {
	cfg, p := siteFixture("hub")
	p.Links = nil
	p.OwnerAgentID = cfg.AgentID
	p.DesiredHash = siteSnapshotHash(p)
	cfg.SiteLinkDesired = p
	cfg.AgentID = siteBID
	if validateSiteSnapshot(cfg, p) == nil {
		t.Fatal("saved empty-link inventory replayed on another node")
	}
}

func TestImmutableACMECredentialsSurviveRotationAndFailedSave(t *testing.T) {
	dir := t.TempDir()
	env, token := filepath.Join(dir, "env"), filepath.Join(dir, "token")
	old := TraefikACMEParams{RFC2136Nameserver: "127.0.0.1:53", RFC2136TSIGKey: "old.", RFC2136TSIGAlgorithm: "hmac-sha256", RFC2136TSIGSecret: "b2xk"}
	next := old
	next.RFC2136TSIGKey = "new."
	next.RFC2136TSIGSecret = "bmV3"
	if _, err := applyTraefikACMESecrets(old, env, token); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(env)
	if err := persistTraefikACMESecrets(next, env, token, func() error { return errors.New("save failed") }); err == nil {
		t.Fatal("save failure masked")
	}
	after, _ := os.ReadFile(env)
	if string(before) != string(after) {
		t.Fatal("old environment not restored")
	}
	for _, p := range []TraefikACMEParams{old, next} {
		data, err := os.ReadFile(rfc2136CredentialPath(p, token))
		if err != nil || string(data) != p.RFC2136TSIGSecret {
			t.Fatal("in-flight cleanup generation lost")
		}
	}
	if !strings.Contains(string(after), "EXEC_PATH="+ACMEHookPath) || strings.Contains(string(after), "EXEC_MODE=") {
		t.Fatal("exec provider contract incorrect")
	}
}

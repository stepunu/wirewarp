package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
)

type SiteLinkHandlers struct {
	cfg             *config.Config
	cfgPath         string
	mu              sync.Mutex
	emit            atomic.Pointer[EmitFn]
	wake            chan struct{}
	firewall        func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error
	ownership       func(context.Context, *config.Config, *config.SiteLinkSnapshot) error
	routesPreflight func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error
	routesApply     func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error
	cleanup         func(context.Context, *config.Config) error
	persistFirewall func(context.Context) error
}

var errSitePeerPending = errors.New("site-link peer ownership is pending")

func (h *SiteLinkHandlers) acknowledgeError(p *config.SiteLinkSnapshot, err error) {
	phase := "error"
	if errors.Is(err, errSitePeerPending) {
		phase = "applying"
	}
	h.ack(p, phase, err)
}

func NewSiteLinks(cfg *config.Config, path string) *SiteLinkHandlers {
	return &SiteLinkHandlers{cfg: cfg, cfgPath: path, wake: make(chan struct{}, 1), firewall: reconcileSiteFirewall, ownership: verifySiteOwnership, routesPreflight: preflightSiteRoutes, routesApply: applySiteRoutes, cleanup: cleanupSiteFirewall, persistFirewall: persistSiteFirewall}
}

func (h *SiteLinkHandlers) SetEmit(fn EmitFn) { h.emit.Store(&fn) }
func (h *SiteLinkHandlers) NotifyTopologyChanged() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}
func (h *SiteLinkHandlers) Register(exec *executor.Executor) {
	exec.Register("site_link_desired_state", h.handleDesired)
	exec.Register("site_link_test", h.handleTest)
	exec.Register("site_link_teardown", h.handleTeardown)
}
func (h *SiteLinkHandlers) ack(p *config.SiteLinkSnapshot, phase string, err error) {
	fn := h.emit.Load()
	if fn == nil {
		return
	}
	payload := map[string]any{"revision": p.Revision, "desired_hash": p.DesiredHash, "phase": phase}
	if err != nil {
		payload["error"] = err.Error()
	}
	if err := (*fn)("site_link_state", payload); err != nil {
		log.Printf("[site-links] acknowledgement failed: %v", err)
	}
}

func (h *SiteLinkHandlers) handleDesired(raw json.RawMessage) (string, error) {
	p, err := decodeSiteSnapshot(raw)
	if err != nil {
		return "", err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	saved := h.cfg.Snapshot()
	if err := validateSiteSnapshot(saved, p); err != nil {
		return "", err
	}
	p.OwnerAgentID = saved.AgentID
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	plan, err := siteRoutePlan(saved, p)
	if err != nil {
		return "", err
	}
	if err := h.routesPreflight(ctx, saved.SiteLinkRoutes, plan); err != nil {
		return "", err
	}
	guard := siteUnionPeers(saved.SiteLinkGuardPeers, p.TransitPeers)
	// Persist guard intent before host effects so a crash cannot forget a new
	// advertised subnet. The controller must wait for this command before peers.
	if err := h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
		next.SiteLinkDesired = p
		next.SiteLinkApplied = nil
		next.SiteLinkGuardPeers = guard
		next.SiteLinkTeardown = nil
		return nil
	}); err != nil {
		return "", fmt.Errorf("persist site-link target: %w", err)
	}
	if err := h.firewall(ctx, saved, p, guard, false); err != nil {
		h.acknowledgeError(p, err)
		return "", fmt.Errorf("stage site-link deny guard; persisted retry required: %w", err)
	}
	h.ack(p, "applying", nil)
	if err := h.reconcileLocked(ctx); err != nil {
		h.acknowledgeError(p, err)
		return "", err
	}
	return "site-link state applied", nil
}

func (h *SiteLinkHandlers) reconcileLocked(ctx context.Context) error {
	saved := h.cfg.Snapshot()
	p := saved.SiteLinkDesired
	if p == nil {
		return nil
	}
	if err := validateSiteSnapshot(saved, p); err != nil {
		return err
	}
	guard := siteUnionPeers(saved.SiteLinkGuardPeers, p.TransitPeers)
	if err := h.firewall(ctx, saved, p, guard, false); err != nil {
		return fmt.Errorf("restore site-link deny guard: %w", err)
	}
	if err := h.ownership(ctx, saved, p); err != nil {
		return fmt.Errorf("site-link peer ownership is not ready; deny guard retained: %w", err)
	}
	plan, err := siteRoutePlan(saved, p)
	if err != nil {
		return err
	}
	if err := h.routesPreflight(ctx, saved.SiteLinkRoutes, plan); err != nil {
		return err
	}
	union := append([]config.SiteLinkRoute{}, saved.SiteLinkRoutes...)
	seen := map[string]bool{}
	for _, r := range union {
		seen[siteRouteKey(r)] = true
	}
	for _, r := range plan {
		if !seen[siteRouteKey(r)] {
			union = append(union, r)
		}
	}
	if err := h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error { next.SiteLinkRoutes = union; next.SiteLinkApplied = nil; return nil }); err != nil {
		return fmt.Errorf("persist owned site-link routes: %w", err)
	}
	if err := h.routesApply(ctx, saved.SiteLinkRoutes, plan); err != nil {
		return fmt.Errorf("apply site-link routes; deny guard retained: %w", err)
	}
	if err := h.firewall(ctx, saved, p, guard, true); err != nil {
		if rollback := h.firewall(ctx, saved, p, guard, false); rollback != nil {
			return fmt.Errorf("site-link firewall failed; deny rollback also failed: %v; %w", rollback, err)
		}
		return fmt.Errorf("apply site-link permissions; deny guard retained: %w", err)
	}
	if err := h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
		next.SiteLinkApplied = p
		next.SiteLinkGuardPeers = guard
		next.SiteLinkRoutes = plan
		return nil
	}); err != nil {
		if rollback := h.firewall(ctx, saved, p, guard, false); rollback != nil {
			return fmt.Errorf("persist applied site-link state failed; deny rollback failed: %v; %w", rollback, err)
		}
		return fmt.Errorf("persist applied site-link state; deny guard retained: %w", err)
	}
	h.ack(p, "applied", nil)
	return nil
}

func (h *SiteLinkHandlers) Start(ctx context.Context) {
	go func() {
		for {
			h.mu.Lock()
			run, cancel := context.WithTimeout(ctx, 45*time.Second)
			err := h.reconcileLocked(run)
			cancel()
			h.mu.Unlock()
			if err != nil {
				log.Printf("[site-links] degraded: %v", err)
				if p := h.cfg.Snapshot().SiteLinkDesired; p != nil {
					h.acknowledgeError(p, err)
				}
			}
			timer := time.NewTimer(30 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-h.wake:
				timer.Stop()
			case <-timer.C:
			}
		}
	}()
}

// Install saved guards before any networking lifecycle can add broad ACCEPT rules.
func RestoreSiteLinkGuard(ctx context.Context, cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	saved := cfg.Snapshot()
	if saved.SiteLinkDesired == nil && len(saved.SiteLinkGuardPeers) == 0 {
		return nil
	}
	p := saved.SiteLinkDesired
	if p == nil {
		return fmt.Errorf("saved site-link guard has no target snapshot")
	}
	if err := validateSiteSnapshot(saved, p); err != nil {
		return err
	}
	return reconcileSiteFirewall(ctx, saved, p, siteUnionPeers(saved.SiteLinkGuardPeers, p.TransitPeers), false)
}

func verifySiteOwnership(ctx context.Context, saved *config.Config, p *config.SiteLinkSnapshot) error {
	for _, peer := range p.TransitPeers {
		if peer.WireGuardPublicKey == "" {
			return fmt.Errorf("%w: gateway WireGuard public key is pending", errSitePeerPending)
		}
	}
	if p.NodeRole == "hub" {
		if saved.Server == nil || !saved.Server.Initialized || !siteInterface.MatchString(saved.Server.WGInterface) {
			return fmt.Errorf("hub WireGuard interface is not ready")
		}
		out, err := siteNetworkCommand(ctx, "wg", "show", saved.Server.WGInterface, "allowed-ips")
		if err != nil {
			return fmt.Errorf("inspect hub WireGuard peer ownership: %w", err)
		}
		actual := map[string][]netip.Prefix{}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			for _, value := range strings.Split(strings.Join(fields[1:], ""), ",") {
				prefix, err := netip.ParsePrefix(value)
				if err == nil {
					actual[fields[0]] = append(actual[fields[0]], prefix.Masked())
				}
			}
		}
		for _, peer := range p.TransitPeers {
			prefixes, ok := actual[peer.WireGuardPublicKey]
			if !ok {
				return fmt.Errorf("%w: expected gateway peer is not installed", errSitePeerPending)
			}
			for _, value := range peer.AdvertisedSubnets {
				want, _ := netip.ParsePrefix(value)
				found := false
				for key, owned := range actual {
					for _, prefix := range owned {
						if !prefix.Overlaps(want) {
							continue
						}
						if key != peer.WireGuardPublicKey || prefix != want {
							return fmt.Errorf("WireGuard AllowedIPs conflict with advertised LAN ownership")
						}
						found = true
					}
				}
				if !found || len(prefixes) == 0 {
					return fmt.Errorf("gateway advertised LAN is not installed")
				}
			}
		}
		return nil
	}
	checked := map[string]bool{}
	for _, link := range p.Links {
		for _, site := range []config.SiteLinkSite{link.SiteA, link.SiteB} {
			if site.GatewayAgentID != saved.AgentID || checked[site.AttachmentID] {
				continue
			}
			checked[site.AttachmentID] = true
			att, ok := siteAttachment(saved, site.AttachmentID)
			if !ok {
				return fmt.Errorf("gateway attachment is unavailable")
			}
			out, err := siteNetworkCommand(ctx, "wg", "show", att.WGInterface, "peers")
			if err != nil || strings.TrimSpace(string(out)) != att.ServerPublicKey {
				return fmt.Errorf("gateway tunnel peer does not match authenticated hub")
			}
			out, err = siteNetworkCommand(ctx, "wg", "show", att.WGInterface, "public-key")
			expected := ""
			for _, peer := range p.TransitPeers {
				if peer.AttachmentID == att.AttachmentID {
					expected = peer.WireGuardPublicKey
				}
			}
			if err != nil || expected == "" || strings.TrimSpace(string(out)) != expected {
				return fmt.Errorf("gateway WireGuard public key does not match attachment inventory")
			}
			out, err = siteNetworkCommand(ctx, "ip", "-4", "-j", "addr", "show", "dev", att.LANIface)
			if err != nil {
				return fmt.Errorf("gateway LAN interface is unavailable")
			}
			var addresses []struct {
				AddrInfo []struct {
					Local string `json:"local"`
				} `json:"addr_info"`
			}
			if json.Unmarshal(out, &addresses) != nil {
				return fmt.Errorf("invalid gateway LAN address inspection")
			}
			found := false
			for _, iface := range addresses {
				for _, addr := range iface.AddrInfo {
					if addr.Local == att.LANIP {
						found = true
					}
				}
			}
			if !found {
				return fmt.Errorf("gateway LAN address changed; refresh attachment metadata")
			}
		}
	}
	return nil
}

func (h *SiteLinkHandlers) handleTest(raw json.RawMessage) (string, error) {
	var p struct {
		SchemaVersion   int    `json:"schema_version"`
		LinkID          string `json:"link_id"`
		Revision        int64  `json:"revision"`
		DesiredHash     string `json:"desired_hash"`
		Direction       string `json:"direction"`
		DestinationIP   string `json:"destination_ip"`
		DestinationPort int    `json:"destination_port"`
		Protocol        string `json:"protocol"`
		TimeoutSeconds  int    `json:"timeout_seconds"`
	}
	if json.Unmarshal(raw, &p) != nil || p.SchemaVersion != 1 || p.Protocol != "tcp" || p.TimeoutSeconds != 5 || p.DestinationPort < 1 || p.DestinationPort > 65535 {
		return "", fmt.Errorf("invalid site-link TCP test")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	saved := h.cfg.Snapshot()
	applied := saved.SiteLinkApplied
	if saved.Mode != "client" || !saved.Gateway() || applied == nil || saved.SiteLinkDesired == nil || applied.Revision != p.Revision || applied.DesiredHash != p.DesiredHash || applied.Revision != saved.SiteLinkDesired.Revision || applied.DesiredHash != saved.SiteLinkDesired.DesiredHash {
		return "", fmt.Errorf("site-link test requires the current applied gateway revision")
	}
	ipText, err := edgeIPv4(p.DestinationIP)
	if err != nil {
		return "", fmt.Errorf("site-link test destination must be IPv4")
	}
	ip, _ := netip.ParseAddr(ipText)
	var att config.AttachmentState
	allowed := false
	for _, flow := range compileSiteFlows(applied) {
		if flow.linkID != p.LinkID || flow.sourceSite.GatewayAgentID != saved.AgentID || p.Direction == "a_to_b" && flow.sourceSite.AttachmentID != findSite(applied, p.LinkID, true).AttachmentID || p.Direction == "b_to_a" && flow.sourceSite.AttachmentID != findSite(applied, p.LinkID, false).AttachmentID {
			continue
		}
		dst, _ := netip.ParsePrefix(flow.destination)
		if dst.Contains(ip) && (flow.protocol == "any" || flow.protocol == "tcp") && (flow.port == 0 || flow.port == p.DestinationPort) {
			att, allowed = siteAttachment(saved, flow.sourceSite.AttachmentID)
			break
		}
	}
	if !allowed || (p.Direction != "a_to_b" && p.Direction != "b_to_a") {
		return "", fmt.Errorf("site-link test is outside current allowed direction or destination")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.ownership(ctx, saved, applied); err != nil {
		return "", err
	}
	start := time.Now()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(att.LANIP)}}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), fmt.Sprint(p.DestinationPort)))
	result := map[string]any{"connected": err == nil, "duration_ms": time.Since(start).Milliseconds()}
	if err != nil {
		result["error"] = "gateway TCP connection failed"
	} else {
		_ = conn.Close()
	}
	data, _ := json.Marshal(result)
	if err != nil {
		return string(data), fmt.Errorf("%s", data)
	}
	return string(data), nil
}

func findSite(p *config.SiteLinkSnapshot, id string, a bool) config.SiteLinkSite {
	for _, link := range p.Links {
		if link.ID == id {
			if a {
				return link.SiteA
			}
			return link.SiteB
		}
	}
	return config.SiteLinkSite{}
}

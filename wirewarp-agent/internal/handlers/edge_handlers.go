package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	"github.com/wirewarp/agent/internal/firewall"
)

// EdgeHandlers manages HTTP edge services independently of tunnel networking.
type EdgeHandlers struct {
	cfgPath         string
	cfg             *config.Config
	emit            atomic.Pointer[EmitFn]
	mu              sync.Mutex
	applyDesired    func(context.Context) error
	persistSecrets  func(TraefikACMEParams, func() error) error
	managedService  func(string) (bool, error)
	applyIngress    func(context.Context, []config.EdgePublicIngress) error
	snapshotRuntime func() (func() error, error)
	applyTraefik    func(context.Context, *config.Config) error
	ensureACMEHook  func() error
}

func NewEdge(cfg *config.Config, cfgPath string) *EdgeHandlers {
	h := &EdgeHandlers{cfg: cfg, cfgPath: cfgPath}
	h.applyDesired = h.reconcileDesiredEdge
	h.applyTraefik = h.reconcileEdgeTraefik
	h.applyIngress = func(ctx context.Context, ingress []config.EdgePublicIngress) error {
		if err := preflightFirewallOwnership(ctx, cfg.Snapshot()); err != nil {
			return err
		}
		if err := reconcileEdgeIngress(ctx, ingress); err != nil {
			return err
		}
		if err := firewall.Save(ctx); err != nil {
			return fmt.Errorf("edge ingress changed but persistence failed: %w", err)
		}
		return nil
	}
	h.ensureACMEHook = EnsureACMEDNSHook
	h.snapshotRuntime = func() (func() error, error) {
		return snapshotEdgeFiles([]string{traefikStaticCfg, traefikDynamicCfg, traefikUnitPath, traefikEnvPath, traefikCFTokenPath, "/etc/traefik/secrets/rfc2136_tsig_secret", traefikEnvPath + ".pending-restart", nginxCacheConfigPath, ACMEHookPath})
	}
	h.persistSecrets = func(p TraefikACMEParams, save func() error) error {
		if p.RFC2136Nameserver != "" {
			if err := validateRFC2136ACME(p); err != nil {
				return err
			}
			if err := h.ensureACMEHook(); err != nil {
				return fmt.Errorf("install ACME DNS helper: %w", err)
			}
		}
		return persistTraefikACMESecrets(p, traefikEnvPath, traefikCFTokenPath, save)
	}
	return h
}

func (h *EdgeHandlers) SetEmit(fn EmitFn) {
	h.emit.Store(&fn)
}

func (h *EdgeHandlers) eligible() bool {
	saved := h.cfg.Snapshot()
	return saved.Mode == "server" || saved.Mode == "client" && saved.Gateway()
}

func (h *EdgeHandlers) Register(exec *executor.Executor) {
	exec.Register("edge_node_role", h.handleNodeRole)
	commands := map[string]executor.Handler{
		"crowdsec_install":        h.handleCrowdSecInstall,
		"crowdsec_sync_whitelist": h.handleCrowdSecSyncWhitelist,
		"traefik_install":         h.handleTraefikInstall,
		"traefik_sync_config":     h.handleTraefikSyncConfig,
		"crowdsec_appsec_enable":  h.handleCrowdSecAppSecEnable,
		"edge_desired_state":      h.handleEdgeDesiredState,
		"edge_disable":            h.handleEdgeDisable,
		"edge_cache_purge":        h.handleEdgeCachePurge,
		"edge_cache_test":         h.handleEdgeCacheTest,
		"edge_route_test":         h.handleEdgeRouteTest,
	}
	for name, handler := range commands {
		exec.Register(name, func(raw json.RawMessage) (string, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if !h.eligible() {
				return "", fmt.Errorf("Security Edge requires a server or gateway node")
			}
			if h.cfg.Snapshot().EdgeDisabled && name != "edge_desired_state" && name != "edge_disable" {
				return "", fmt.Errorf("Security Edge is disabled")
			}
			if desired := h.cfg.Snapshot().EdgeDesired; desired != nil && desired.RuntimeMode == "relay_only" && name != "edge_desired_state" && name != "edge_disable" && name != "traefik_install" && name != "traefik_sync_config" {
				return "", fmt.Errorf("relay-only nodes do not run WAF or cache services")
			}
			return handler(raw)
		})
	}
}

func (h *EdgeHandlers) handleNodeRole(raw json.RawMessage) (string, error) {
	var p struct {
		IsGateway  *bool  `json:"is_gateway"`
		LANIP      string `json:"lan_ip"`
		LANNetwork string `json:"lan_network"`
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if err := json.Unmarshal(raw, &p); err != nil || p.IsGateway == nil {
		return "", fmt.Errorf("edge_node_role requires is_gateway")
	}
	if p.LANIP != "" {
		if _, err := edgeIPv4(p.LANIP); err != nil {
			return "", fmt.Errorf("gateway LAN IP requires a unicast IPv4 address")
		}
	}
	if p.LANNetwork != "" {
		prefix, err := netip.ParsePrefix(p.LANNetwork)
		ip, ipErr := netip.ParseAddr(p.LANIP)
		if err != nil || ipErr != nil || !prefix.Addr().Is4() || !prefix.Contains(ip) {
			return "", fmt.Errorf("gateway LAN network must contain the gateway IPv4 address")
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	saved := h.cfg.Snapshot()
	if saved.Mode != "client" {
		return "", fmt.Errorf("edge_node_role applies only to client nodes")
	}
	if err := h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
		value := *p.IsGateway
		next.IsGateway = &value
		if _, exists := fields["lan_ip"]; exists {
			value := p.LANIP
			next.GatewayLANIP = &value
		}
		if _, exists := fields["lan_network"]; exists {
			next.GatewayLANNetwork = p.LANNetwork
		}
		if !value {
			next.EdgeDisabled = true
		}
		return nil
	}); err != nil {
		return "", fmt.Errorf("persist edge node role: %w", err)
	}
	if !*p.IsGateway && (saved.EdgeDesired != nil || saved.EdgeRuntimePending || len(saved.EdgeIngressGuard) != 0) {
		return h.stopDisabledEdge(nil)
	}
	if !*p.IsGateway {
		return "client role saved; edge disabled", nil
	}
	return "gateway role saved; edge enablement unchanged", nil
}

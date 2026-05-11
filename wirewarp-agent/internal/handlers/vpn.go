package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"sync"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	"github.com/wirewarp/agent/internal/iptables"
	"github.com/wirewarp/agent/internal/validate"
	"github.com/wirewarp/agent/internal/wireguard"
)

// VPN constants — keep these in lockstep with the server-side
// `app/services/vpn_ops.py` notion of "what the VPN endpoint should
// look like on the wire". 1280 MTU is the homelab/cellular safe value;
// 1240 MSS = 1280 - 40 (IP + TCP headers).
const (
	vpnMTU                  = 1280
	vpnMSS                  = 1240
	vpnRoutingRulePriority  = 4500 // higher precedence than the 5000-priority LAN-source pin rules
)

// VpnHandlers manages road-warrior WireGuard endpoints — one
// `wireguard.Server` per `wg-vpnN` interface plus the iptables glue
// that gates each peer's reachable destinations. Independent of
// server/client agent mode: the type is mounted by main.go in both
// modes (in practice only gateway clients receive vpn_* commands, but
// keeping the registration mode-agnostic means the dispatcher always
// answers with a sensible "not initialised" if the server fires one
// at a non-gateway by mistake).
type VpnHandlers struct {
	cfgPath string
	cfg     *config.Config
	mu      sync.Mutex
	wgs     map[string]*wireguard.Server // keyed by interface name
	wanCache string                      // best-effort WAN interface for full-tunnel MASQUERADE
}

// NewVpnHandlers initialises any VPN endpoints from saved config so the
// gateway's wg-vpn0 (and any iptables default-drop) survives restarts.
// Peers themselves are not persisted — the control server replays them
// on (re)connect via vpn_peer_add.
func NewVpnHandlers(cfg *config.Config, cfgPath string) (*VpnHandlers, error) {
	h := &VpnHandlers{
		cfgPath: cfgPath,
		cfg:     cfg,
		wgs:     make(map[string]*wireguard.Server),
	}
	for i := range cfg.VpnEndpoints {
		ep := &cfg.VpnEndpoints[i]
		if err := h.bringEndpointUp(ep); err != nil {
			log.Printf("[vpn] WARN: failed to restore endpoint %s on startup: %v", ep.WGInterface, err)
			continue
		}
		log.Printf("[vpn] endpoint %s restored from saved config", ep.WGInterface)
	}
	return h, nil
}

// Register binds the VPN command handlers onto the executor.
func (h *VpnHandlers) Register(exec *executor.Executor) {
	exec.Register("vpn_endpoint_up", h.handleEndpointUp)
	exec.Register("vpn_endpoint_down", h.handleEndpointDown)
	exec.Register("vpn_peer_add", h.handlePeerAdd)
	exec.Register("vpn_peer_remove", h.handlePeerRemove)
	exec.Register("vpn_peer_update_rules", h.handlePeerUpdateRules)
}

// PublicKeyFor returns the running endpoint's public key, or "" if not up.
func (h *VpnHandlers) PublicKeyFor(iface string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	wg, ok := h.wgs[iface]
	if !ok || wg == nil {
		return ""
	}
	return wg.PublicKey
}

// LiveInterfaces returns the WG interface names currently up. Used by the
// websocket heartbeat to drive `wg show <iface> dump`.
func (h *VpnHandlers) LiveInterfaces() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.wgs))
	for iface := range h.wgs {
		out = append(out, iface)
	}
	return out
}

// SetWanIface stashes the WAN interface name so full-tunnel peers can
// MASQUERADE outbound. The gateway's WAN is whatever it uses for default
// internet — typically the same iface the operator port-forwards on.
// Caller passes it via main.go after determining it from the existing
// gateway-attachment state.
func (h *VpnHandlers) SetWanIface(iface string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wanCache = iface
}

// --- command handlers ---

type vpnEndpointUpParams struct {
	EndpointID  string   `json:"endpoint_id"`
	Interface   string   `json:"interface"`
	ListenPort  int      `json:"listen_port"`
	VpnNetwork  string   `json:"vpn_network"`
	VpnServerIP string   `json:"vpn_server_ip"`
	DNSServers  []string `json:"dns_servers"`
}

func (h *VpnHandlers) handleEndpointUp(raw json.RawMessage) (string, error) {
	var p vpnEndpointUpParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if p.Interface == "" || p.VpnNetwork == "" || p.VpnServerIP == "" {
		return "", fmt.Errorf("interface, vpn_network and vpn_server_ip are required")
	}
	if err := validate.Interface(p.Interface); err != nil {
		return "", err
	}
	if err := validate.Port(p.ListenPort); err != nil {
		return "", err
	}
	if err := validate.IPv4CIDR(p.VpnNetwork); err != nil {
		return "", err
	}
	if err := validate.IPv4(p.VpnServerIP); err != nil {
		return "", err
	}
	for _, ns := range p.DNSServers {
		if err := validate.IPv4(ns); err != nil {
			return "", err
		}
	}

	state := config.VpnEndpointState{
		EndpointID:  p.EndpointID,
		WGInterface: p.Interface,
		ListenPort:  p.ListenPort,
		VpnNetwork:  p.VpnNetwork,
		VpnServerIP: p.VpnServerIP,
		DNSServers:  p.DNSServers,
	}

	if err := h.bringEndpointUp(&state); err != nil {
		return "", err
	}

	h.cfg.UpsertVpnEndpoint(state)
	if err := h.cfg.Save(h.cfgPath); err != nil {
		log.Printf("[vpn] WARN: failed to save config after vpn_endpoint_up: %v", err)
	}

	pub := h.PublicKeyFor(p.Interface)
	return fmt.Sprintf("vpn endpoint %s up; public key: %s", p.Interface, pub), nil
}

type vpnEndpointDownParams struct {
	Interface string `json:"interface"`
}

func (h *VpnHandlers) handleEndpointDown(raw json.RawMessage) (string, error) {
	var p vpnEndpointDownParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.Interface(p.Interface); err != nil {
		return "", err
	}

	h.mu.Lock()
	wg, ok := h.wgs[p.Interface]
	if ok {
		delete(h.wgs, p.Interface)
	}
	h.mu.Unlock()

	if ok && wg != nil {
		if err := wg.Down(); err != nil {
			log.Printf("[vpn] WARN: wg-quick down %s: %v", p.Interface, err)
		}
	}

	saved := h.cfg.FindVpnEndpoint(p.Interface)
	if saved != nil {
		_ = iptables.VpnRemoveDefaultDrop(saved.VpnNetwork)
		removeVpnRoutingRule(saved.VpnNetwork)
	}
	iptables.VpnRemoveMSSClamp(p.Interface, vpnMSS)

	h.cfg.RemoveVpnEndpoint(p.Interface)
	if err := h.cfg.Save(h.cfgPath); err != nil {
		log.Printf("[vpn] WARN: failed to save config after vpn_endpoint_down: %v", err)
	}
	if saveErr := iptables.SaveRules(); saveErr != nil {
		log.Printf("[vpn] WARN: iptables save failed: %v", saveErr)
	}
	return fmt.Sprintf("vpn endpoint %s down", p.Interface), nil
}

type vpnPeerRulePayload struct {
	Destination    string `json:"destination"`
	Protocol       string `json:"protocol"`
	PortRangeStart int    `json:"port_range_start"`
	PortRangeEnd   int    `json:"port_range_end"`
}

type vpnPeerAddParams struct {
	Interface  string               `json:"interface"`
	VpnNetwork string               `json:"vpn_network"`
	PublicKey  string               `json:"public_key"`
	PSK        string               `json:"psk"`
	TunnelIP   string               `json:"tunnel_ip"`
	FullTunnel bool                 `json:"full_tunnel"`
	Rules      []vpnPeerRulePayload `json:"rules"`
}

func (h *VpnHandlers) handlePeerAdd(raw json.RawMessage) (string, error) {
	var p vpnPeerAddParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.Interface(p.Interface); err != nil {
		return "", err
	}
	if p.VpnNetwork != "" {
		if err := validate.IPv4CIDR(p.VpnNetwork); err != nil {
			return "", err
		}
	}
	if err := validate.WGKey(p.PublicKey); err != nil {
		return "", err
	}
	if err := validate.WGKeyOpt(p.PSK); err != nil {
		return "", err
	}
	if err := validate.IPv4(p.TunnelIP); err != nil {
		return "", err
	}
	for i := range p.Rules {
		if err := validatePeerRule(&p.Rules[i]); err != nil {
			return "", err
		}
	}

	h.mu.Lock()
	wg, ok := h.wgs[p.Interface]
	wan := h.wanCache
	h.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("vpn endpoint %s not initialised — send vpn_endpoint_up first", p.Interface)
	}

	if err := wg.AddPeer(wireguard.Peer{
		PublicKey:    p.PublicKey,
		PresharedKey: p.PSK,
		TunnelIP:     p.TunnelIP,
		AllowedIPs:   nil, // server-side AllowedIPs is just the peer's /32; the helper adds it.
	}); err != nil {
		return "", err
	}

	rules := convertRules(p.Rules)
	if err := iptables.VpnPeerEnsureRules(p.TunnelIP, p.FullTunnel, wan, rules); err != nil {
		return "", err
	}
	if p.VpnNetwork != "" {
		if err := iptables.VpnEnsureDefaultDrop(p.VpnNetwork); err != nil {
			log.Printf("[vpn] WARN: ensuring default-drop for %s: %v", p.VpnNetwork, err)
		}
	}
	if saveErr := iptables.SaveRules(); saveErr != nil {
		log.Printf("[vpn] WARN: iptables save failed: %v", saveErr)
	}
	return fmt.Sprintf("vpn peer %s added at %s with %d rule(s)", p.PublicKey[:8], p.TunnelIP, len(rules)), nil
}

type vpnPeerRemoveParams struct {
	Interface string `json:"interface"`
	PublicKey string `json:"public_key"`
	TunnelIP  string `json:"tunnel_ip"`
}

func (h *VpnHandlers) handlePeerRemove(raw json.RawMessage) (string, error) {
	var p vpnPeerRemoveParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.Interface(p.Interface); err != nil {
		return "", err
	}
	if err := validate.WGKey(p.PublicKey); err != nil {
		return "", err
	}
	if p.TunnelIP != "" {
		if err := validate.IPv4(p.TunnelIP); err != nil {
			return "", err
		}
	}

	h.mu.Lock()
	wg, ok := h.wgs[p.Interface]
	h.mu.Unlock()
	if ok {
		// RemovePeer is idempotent-safe: it returns an error if the peer
		// isn't present, which we swallow so a duplicate revoke doesn't
		// blow up.
		if err := wg.RemovePeer(p.PublicKey); err != nil {
			log.Printf("[vpn] WARN: wg.RemovePeer: %v", err)
		}
	}
	if p.TunnelIP != "" {
		if err := iptables.VpnPeerRemoveAll(p.TunnelIP); err != nil {
			return "", fmt.Errorf("flush peer iptables: %w", err)
		}
	}
	if saveErr := iptables.SaveRules(); saveErr != nil {
		log.Printf("[vpn] WARN: iptables save failed: %v", saveErr)
	}
	return fmt.Sprintf("vpn peer %s removed", p.PublicKey[:8]), nil
}

type vpnPeerUpdateRulesParams struct {
	Interface  string               `json:"interface"`
	VpnNetwork string               `json:"vpn_network"`
	TunnelIP   string               `json:"tunnel_ip"`
	FullTunnel bool                 `json:"full_tunnel"`
	Rules      []vpnPeerRulePayload `json:"rules"`
}

func (h *VpnHandlers) handlePeerUpdateRules(raw json.RawMessage) (string, error) {
	var p vpnPeerUpdateRulesParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.Interface(p.Interface); err != nil {
		return "", err
	}
	if p.VpnNetwork != "" {
		if err := validate.IPv4CIDR(p.VpnNetwork); err != nil {
			return "", err
		}
	}
	if err := validate.IPv4(p.TunnelIP); err != nil {
		return "", err
	}
	for i := range p.Rules {
		if err := validatePeerRule(&p.Rules[i]); err != nil {
			return "", err
		}
	}
	h.mu.Lock()
	wan := h.wanCache
	h.mu.Unlock()
	rules := convertRules(p.Rules)
	if err := iptables.VpnPeerEnsureRules(p.TunnelIP, p.FullTunnel, wan, rules); err != nil {
		return "", err
	}
	if p.VpnNetwork != "" {
		_ = iptables.VpnEnsureDefaultDrop(p.VpnNetwork)
	}
	if saveErr := iptables.SaveRules(); saveErr != nil {
		log.Printf("[vpn] WARN: iptables save failed: %v", saveErr)
	}
	return fmt.Sprintf("vpn peer rules for %s updated (%d rule(s))", p.TunnelIP, len(rules)), nil
}

// --- internal ---

func (h *VpnHandlers) bringEndpointUp(ep *config.VpnEndpointState) error {
	wgSrv, err := wireguard.NewServer(wireguard.ServerConfig{
		Interface:     ep.WGInterface,
		ListenPort:    ep.ListenPort,
		TunnelNetwork: ep.VpnNetwork,
		TunnelIP:      ep.VpnServerIP,
		MTU:           vpnMTU,
	})
	if err != nil {
		return fmt.Errorf("wireguard.NewServer: %w", err)
	}
	if err := wgSrv.Init(); err != nil {
		return fmt.Errorf("wg-quick up %s: %w", ep.WGInterface, err)
	}

	if err := iptables.EnableIPForward(); err != nil {
		log.Printf("[vpn] WARN: %v", err)
	}
	if err := iptables.VpnEnsureDefaultDrop(ep.VpnNetwork); err != nil {
		log.Printf("[vpn] WARN: vpn default-drop: %v", err)
	}
	// Flush any stale MSS-clamp rules (from a prior agent run with a
	// different mss value, or hand-applied via SSH during incident
	// response) before installing the canonical pair. Avoids stacked
	// duplicates on every restart.
	iptables.VpnFlushMSSClamps(ep.WGInterface)
	if err := iptables.VpnEnsureMSSClamp(ep.WGInterface, vpnMSS); err != nil {
		log.Printf("[vpn] WARN: mss clamp: %v", err)
	}

	// Critical: when this gateway also hosts wirewarp tunnel-attachment
	// LAN-source pin rules (`from <lan_ip> lookup tunnel`), those rules
	// would otherwise hijack EVERY reply destined for VPN clients and
	// route them out the wrong wgN interface. A higher-precedence
	// `to <vpn_network> lookup main` rule keeps replies routing through
	// wg-vpn0 via the kernel's main table where they belong. See the
	// 2026-05-10 debug session — without this, Traefik routes (and any
	// service on a pinned LAN host) silently fail with bidirectional
	// asymmetric traffic.
	addVpnRoutingRule(ep.VpnNetwork)

	h.mu.Lock()
	h.wgs[ep.WGInterface] = wgSrv
	h.mu.Unlock()
	return nil
}

// addVpnRoutingRule installs `ip rule add to <vpn_network> lookup main
// priority <vpnRoutingRulePriority>` if absent. Idempotent — `ip rule
// add` returns a non-zero exit when the rule already exists; we swallow
// that. Removal happens at endpoint-down via removeVpnRoutingRule.
func addVpnRoutingRule(vpnNetwork string) {
	args := []string{
		"rule", "add",
		"to", vpnNetwork,
		"lookup", "main",
		"priority", fmt.Sprintf("%d", vpnRoutingRulePriority),
	}
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		// "RTNETLINK answers: File exists" = already installed.
		// Anything else is unexpected; log once.
		if !contains(string(out), "File exists") {
			log.Printf("[vpn] WARN: ip rule add %s: %v — %s", vpnNetwork, err, out)
		}
	} else {
		log.Printf("[vpn] installed ip rule: to %s lookup main priority %d", vpnNetwork, vpnRoutingRulePriority)
	}
}

func removeVpnRoutingRule(vpnNetwork string) {
	args := []string{
		"rule", "del",
		"to", vpnNetwork,
		"lookup", "main",
		"priority", fmt.Sprintf("%d", vpnRoutingRulePriority),
	}
	exec.Command("ip", args...).Run() //nolint:errcheck — idempotent del
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func validatePeerRule(r *vpnPeerRulePayload) error {
	if r.Destination != "" {
		if err := validate.IPv4OrCIDR(r.Destination); err != nil {
			return err
		}
	}
	if r.Protocol != "" {
		switch r.Protocol {
		case "tcp", "udp", "icmp", "any", "all":
		default:
			return fmt.Errorf("validate: vpn rule protocol %q: must be tcp|udp|icmp|any|all", r.Protocol)
		}
	}
	if r.PortRangeStart != 0 {
		if err := validate.Port(r.PortRangeStart); err != nil {
			return err
		}
	}
	if r.PortRangeEnd != 0 {
		if err := validate.Port(r.PortRangeEnd); err != nil {
			return err
		}
	}
	return nil
}

func convertRules(in []vpnPeerRulePayload) []iptables.VpnRule {
	out := make([]iptables.VpnRule, 0, len(in))
	for _, r := range in {
		out = append(out, iptables.VpnRule{
			Destination:    r.Destination,
			Protocol:       r.Protocol,
			PortRangeStart: r.PortRangeStart,
			PortRangeEnd:   r.PortRangeEnd,
		})
	}
	return out
}

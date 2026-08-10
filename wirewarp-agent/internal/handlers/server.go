// Package handlers wires control-server commands to wireguard/iptables operations.
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync/atomic"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	"github.com/wirewarp/agent/internal/iptables"
	"github.com/wirewarp/agent/internal/validate"
	"github.com/wirewarp/agent/internal/wireguard"
)

// ServerHandlers holds the live WireGuard server instance and config path.
type ServerHandlers struct {
	cfgPath string
	cfg     *config.Config
	wg      *wireguard.Server
	// emit is the upstream telemetry channel set by SetEmit. See
	// ClientHandlers.emit for the same pattern.
	emit atomic.Pointer[EmitFn]
}

// NewServer initialises the WireGuard server from config and returns a handler set.
// If the server has been initialised before (cfg.Server.Initialized == true) it
// brings the interface back up immediately (offline-resilience, task 4.5).
func NewServer(cfg *config.Config, cfgPath string) (*ServerHandlers, error) {
	h := &ServerHandlers{cfgPath: cfgPath, cfg: cfg}

	if cfg.Server == nil || !cfg.Server.Initialized {
		log.Println("[server] no saved server config — waiting for wg_init command")
		return h, nil
	}

	s := cfg.Server
	wgSrv, err := wireguard.NewServer(wireguard.ServerConfig{
		Interface:     s.WGInterface,
		ListenPort:    s.WGPort,
		TunnelNetwork: s.TunnelNetwork,
		TunnelIP:      s.TunnelIP,
	})
	if err != nil {
		return nil, fmt.Errorf("wireguard.NewServer: %w", err)
	}

	if err := wgSrv.PruneStalePeerRoutes(); err != nil {
		return nil, fmt.Errorf("prune stale peer routes: %w", err)
	}
	initErr := wgSrv.Init()
	if initErr != nil {
		log.Printf("[server] WARN: failed to restore WireGuard interface on startup: %v", initErr)
	} else {
		log.Printf("[server] WireGuard interface %s restored from saved config", s.WGInterface)
		// Re-apply forwarding and NAT on startup
		if err := iptables.EnableIPForward(); err != nil {
			log.Printf("[server] WARN: %v", err)
		}
		if s.PublicIface != "" {
			if err := iptables.EnsureMasquerade(s.PublicIface); err != nil {
				log.Printf("[server] WARN: masquerade on %s: %v", s.PublicIface, err)
			}
		}
		if s.WGInterface != "" {
			if err := iptables.EnsureMSSClamp(s.WGInterface); err != nil {
				log.Printf("[server] WARN: mss clamp on %s: %v", s.WGInterface, err)
			}
		}
	}

	// Idempotently install the reboot-safe routing-restore unit on every
	// startup. EnsureRoutingUnit no-ops when the file content already
	// matches; without this hook, agents whose wg_init landed before
	// EnsureRoutingUnit existed would never get the unit (handleWGInit
	// is a one-shot — the control server doesn't replay it on reconnect).
	if exe, err := os.Executable(); err == nil {
		if err := EnsureRoutingUnit(exe, cfgPath); err != nil {
			log.Printf("[server] WARN: routing-restore unit install: %v", err)
		}
	}

	h.wg = wgSrv
	return h, nil
}

// Shutdown tears down the WireGuard interface on agent stop.
func (h *ServerHandlers) Shutdown() {
	if h.wg != nil {
		if err := h.wg.Down(); err != nil {
			log.Printf("[server] WARN: wg-quick down: %v", err)
		} else {
			log.Println("[server] WireGuard interface down")
		}
	}
}

// MeshInterfaces returns the WG interfaces this server agent uses for
// the tunnel mesh. Used by the heartbeat to surface peer stats. Server
// agents host a single wg0; clients are handled in ClientHandlers.
func (h *ServerHandlers) MeshInterfaces() []string {
	if h.cfg.Server == nil || !h.cfg.Server.Initialized {
		return nil
	}
	if h.cfg.Server.WGInterface == "" {
		return nil
	}
	return []string{h.cfg.Server.WGInterface}
}

// Register binds all server-mode command handlers onto the given executor.
func (h *ServerHandlers) Register(exec *executor.Executor) {
	exec.Register("wg_init", h.handleWGInit)
	exec.Register("wg_add_peer", h.handleAddPeer)
	exec.Register("wg_remove_peer", h.handleRemovePeer)
	exec.Register("iptables_add_forward", h.handleAddForward)
	exec.Register("iptables_remove_forward", h.handleRemoveForward)
	exec.Register("set_lan_snat", h.handleSetLANSNAT)
	exec.Register("reconcile_lan_snat", h.handleReconcileLANSNAT)
	exec.Register("crowdsec_install", h.handleCrowdSecInstall)
	exec.Register("crowdsec_sync_whitelist", h.handleCrowdSecSyncWhitelist)
	exec.Register("traefik_install", h.handleTraefikInstall)
	exec.Register("traefik_sync_config", h.handleTraefikSyncConfig)
	exec.Register("crowdsec_appsec_enable", h.handleCrowdSecAppSecEnable)
	exec.Register("edge_desired_state", h.handleEdgeDesiredState)
	exec.Register("edge_disable", h.handleEdgeDisable)
	exec.Register("edge_cache_purge", h.handleEdgeCachePurge)
	exec.Register("edge_cache_test", h.handleEdgeCacheTest)
}

// --- command handlers ---

type wgInitParams struct {
	Interface     string `json:"wg_interface"`
	ListenPort    int    `json:"wg_port"`
	TunnelNetwork string `json:"tunnel_network"`
	TunnelIP      string `json:"tunnel_ip"` // server's own tunnel IP
	PublicIface   string `json:"public_iface"`
	PublicIP      string `json:"public_ip"`
}

func (h *ServerHandlers) handleWGInit(raw json.RawMessage) (string, error) {
	var p wgInitParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.Interface(p.Interface); err != nil {
		return "", err
	}
	if err := validate.Port(p.ListenPort); err != nil {
		return "", err
	}
	if err := validate.IPv4CIDR(p.TunnelNetwork); err != nil {
		return "", err
	}
	if err := validate.IPv4(p.TunnelIP); err != nil {
		return "", err
	}
	if err := validate.PublicIface(p.PublicIface); err != nil {
		return "", err
	}
	if err := validate.IPv4(p.PublicIP); err != nil {
		return "", err
	}
	if err := h.cleanupChangedPublicIface(p.PublicIface); err != nil {
		return "", err
	}

	wgSrv, err := wireguard.NewServer(wireguard.ServerConfig{
		Interface:     p.Interface,
		ListenPort:    p.ListenPort,
		TunnelNetwork: p.TunnelNetwork,
		TunnelIP:      p.TunnelIP,
	})
	if err != nil {
		return "", err
	}
	h.wg = nil
	if err := wgSrv.PruneStalePeerRoutes(); err != nil {
		return "", fmt.Errorf("prune stale peer routes: %w", err)
	}
	if err := wgSrv.Init(); err != nil {
		return "", err
	}
	h.wg = wgSrv

	// Enable forwarding and NAT so tunnel traffic can reach the internet
	if err := configureWGInitRuntime(p); err != nil {
		return "", err
	}

	// Persist state
	nextServer := &config.ServerState{
		WGInterface:   p.Interface,
		WGPort:        p.ListenPort,
		TunnelNetwork: p.TunnelNetwork,
		TunnelIP:      p.TunnelIP,
		PublicIface:   p.PublicIface,
		PublicIP:      p.PublicIP,
		Initialized:   true,
	}
	if err := h.saveWGInitState(nextServer); err != nil {
		return "", err
	}
	h.wg = wgSrv

	if exe, err := os.Executable(); err == nil {
		if err := EnsureRoutingUnit(exe, h.cfgPath); err != nil {
			log.Printf("[server] WARN: routing-restore unit install: %v", err)
		}
	}

	return fmt.Sprintf("WireGuard interface %s initialised; public key: %s", p.Interface, wgSrv.PublicKey), nil
}

func configureWGInitRuntime(p wgInitParams) error {
	if err := iptables.EnableIPForward(); err != nil {
		return err
	}
	if err := iptables.EnsureMasquerade(p.PublicIface); err != nil {
		return fmt.Errorf("masquerade on %s: %w", p.PublicIface, err)
	}
	if err := iptables.EnsureMSSClamp(p.Interface); err != nil {
		return fmt.Errorf("mss clamp on %s: %w", p.Interface, err)
	}
	if err := iptables.SaveRules(); err != nil {
		return fmt.Errorf("save iptables rules: %w", err)
	}
	return nil
}

func (h *ServerHandlers) saveWGInitState(next *config.ServerState) error {
	old := h.cfg.Server
	h.cfg.Server = next
	if err := h.cfg.Save(h.cfgPath); err != nil {
		h.cfg.Server = old
		return fmt.Errorf("save config after wg_init: %w", err)
	}
	return nil
}

func (h *ServerHandlers) cleanupChangedPublicIface(nextIface string) error {
	if h.cfg == nil || h.cfg.Server == nil {
		return nil
	}
	oldIface := h.cfg.Server.PublicIface
	if oldIface == "" || oldIface == nextIface {
		return nil
	}
	if err := iptables.CleanupServerNAT(oldIface); err != nil {
		return fmt.Errorf("clean up old public interface %s: %w", oldIface, err)
	}
	return nil
}

type addPeerParams struct {
	Name       string   `json:"peer_name"`
	PublicKey  string   `json:"public_key"`
	TunnelIP   string   `json:"tunnel_ip"`
	AllowedIPs []string `json:"allowed_ips"`
}

func (h *ServerHandlers) handleAddPeer(raw json.RawMessage) (string, error) {
	if h.wg == nil {
		return "", fmt.Errorf("WireGuard not initialised — send wg_init first")
	}
	var p addPeerParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.PeerName(p.Name); err != nil {
		return "", err
	}
	if err := validate.WGKey(p.PublicKey); err != nil {
		return "", err
	}
	if err := validate.IPv4(p.TunnelIP); err != nil {
		return "", err
	}
	for _, a := range p.AllowedIPs {
		if err := validate.IPv4OrCIDR(a); err != nil {
			return "", err
		}
	}
	peer := wireguard.Peer{
		Name:       p.Name,
		PublicKey:  p.PublicKey,
		TunnelIP:   p.TunnelIP,
		AllowedIPs: p.AllowedIPs,
	}
	iface := "wg0"
	if h.cfg.Server != nil && h.cfg.Server.WGInterface != "" {
		iface = h.cfg.Server.WGInterface
	}
	if err := h.wg.AddPeerAndRoutes(peer, iface); err != nil {
		return "", err
	}
	return fmt.Sprintf("peer %s (%s) added", p.Name, p.TunnelIP), nil
}

type removePeerParams struct {
	PublicKey string `json:"public_key"`
}

func (h *ServerHandlers) handleRemovePeer(raw json.RawMessage) (string, error) {
	if h.wg == nil {
		return "", fmt.Errorf("WireGuard not initialised")
	}
	var p removePeerParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.WGKey(p.PublicKey); err != nil {
		return "", err
	}
	iface := "wg0"
	if h.cfg.Server != nil && h.cfg.Server.WGInterface != "" {
		iface = h.cfg.Server.WGInterface
	}
	if err := h.wg.RemovePeerAndRoutes(p.PublicKey, iface); err != nil {
		return "", err
	}
	return fmt.Sprintf("peer %s removed", p.PublicKey), nil
}

type addForwardParams struct {
	Protocol      string `json:"protocol"`
	PublicPort    int    `json:"public_port"`
	PublicPortEnd int    `json:"public_port_end"` // 0 = single port
	DestIP        string `json:"destination_ip"`
	DestPort      int    `json:"destination_port"`
	DestPortEnd   int    `json:"destination_port_end"` // 0 = single port
	PublicIP      string `json:"public_ip"`            // empty = fall back to cfg.Server.PublicIP
}

func portRangeStr(start, end int) string {
	if end > 0 {
		return fmt.Sprintf("%d-%d", start, end)
	}
	return fmt.Sprintf("%d", start)
}

func (h *ServerHandlers) handleAddForward(raw json.RawMessage) (string, error) {
	var p addForwardParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validateForwardParams(&p); err != nil {
		return "", err
	}
	publicIP := p.PublicIP
	if publicIP == "" && h.cfg.Server != nil {
		publicIP = h.cfg.Server.PublicIP
	}
	if err := validate.IPv4(publicIP); err != nil {
		return "", err
	}
	if err := iptables.AddForward(publicIP, iptables.ForwardRule{
		Protocol:      p.Protocol,
		PublicPort:    p.PublicPort,
		PublicPortEnd: p.PublicPortEnd,
		DestIP:        p.DestIP,
		DestPort:      p.DestPort,
		DestPortEnd:   p.DestPortEnd,
	}); err != nil {
		return "", err
	}
	if err := iptables.SaveRules(); err != nil {
		return "", fmt.Errorf("save added forward: %w", err)
	}
	return fmt.Sprintf("forward %s:%s → %s:%s added",
		p.Protocol, portRangeStr(p.PublicPort, p.PublicPortEnd),
		p.DestIP, portRangeStr(p.DestPort, p.DestPortEnd)), nil
}

func (h *ServerHandlers) handleRemoveForward(raw json.RawMessage) (string, error) {
	var p addForwardParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validateForwardParams(&p); err != nil {
		return "", err
	}
	publicIP := p.PublicIP
	if publicIP == "" && h.cfg.Server != nil {
		publicIP = h.cfg.Server.PublicIP
	}
	if err := validate.IPv4(publicIP); err != nil {
		return "", err
	}
	if err := iptables.RemoveForwardAndSave(publicIP, iptables.ForwardRule{
		Protocol:      p.Protocol,
		PublicPort:    p.PublicPort,
		PublicPortEnd: p.PublicPortEnd,
		DestIP:        p.DestIP,
		DestPort:      p.DestPort,
		DestPortEnd:   p.DestPortEnd,
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("forward %s:%s → %s:%s removed",
		p.Protocol, portRangeStr(p.PublicPort, p.PublicPortEnd),
		p.DestIP, portRangeStr(p.DestPort, p.DestPortEnd)), nil
}

type setLANSNATParams struct {
	LANIp    string `json:"lan_ip"`
	PublicIP string `json:"public_ip"`
	Action   string `json:"action"` // "set" | "clear"
}

type reconcileLANSNATPin struct {
	LANIP    string `json:"lan_ip"`
	PublicIP string `json:"public_ip"`
}

type reconcileLANSNATParams struct {
	Pins []reconcileLANSNATPin `json:"pins"`
}

func (h *ServerHandlers) handleReconcileLANSNAT(raw json.RawMessage) (string, error) {
	var p reconcileLANSNATParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if p.Pins == nil {
		return "", fmt.Errorf("pins must be an array")
	}
	if h.cfg.Server == nil || !h.cfg.Server.Initialized {
		return "", fmt.Errorf("server not initialised: wg_init has not been run")
	}
	iface := h.cfg.Server.PublicIface
	if err := validate.PublicIface(iface); err != nil {
		return "", err
	}

	desired := make([]iptables.LANSNATPin, 0, len(p.Pins))
	seenLANIPs := make(map[string]struct{}, len(p.Pins))
	for _, pin := range p.Pins {
		if err := validate.IPv4(pin.LANIP); err != nil {
			return "", fmt.Errorf("lan_ip: %w", err)
		}
		if err := validate.IPv4(pin.PublicIP); err != nil {
			return "", fmt.Errorf("public_ip: %w", err)
		}
		if _, duplicate := seenLANIPs[pin.LANIP]; duplicate {
			return "", fmt.Errorf("duplicate lan_ip %s", pin.LANIP)
		}
		seenLANIPs[pin.LANIP] = struct{}{}
		desired = append(desired, iptables.LANSNATPin{
			LANIP:    pin.LANIP,
			PublicIP: pin.PublicIP,
		})
	}

	if err := iptables.ReconcileLANSNATAndSave(iface, desired); err != nil {
		return "", err
	}
	return fmt.Sprintf("reconciled %d LAN SNAT pin(s)", len(desired)), nil
}

// handleSetLANSNAT installs or removes a per-LAN-host SNAT rule on the
// VPS public interface. The iptables layer snapshots all managed pins before
// the per-source change and restores them if mutation or persistence fails.
func (h *ServerHandlers) handleSetLANSNAT(raw json.RawMessage) (string, error) {
	var p setLANSNATParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if p.LANIp == "" {
		return "", fmt.Errorf("lan_ip is required")
	}
	if err := validate.IPv4(p.LANIp); err != nil {
		return "", err
	}
	if p.PublicIP != "" {
		if err := validate.IPv4(p.PublicIP); err != nil {
			return "", err
		}
	}
	if h.cfg.Server == nil || !h.cfg.Server.Initialized {
		return "", fmt.Errorf("server not initialised — wg_init has not been run")
	}
	iface := h.cfg.Server.PublicIface
	if iface == "" {
		return "", fmt.Errorf("public_iface not set on this server agent")
	}

	if p.Action == "clear" {
		if err := iptables.SetLANSNATAndSave(iface, p.LANIp, "", true); err != nil {
			return "", err
		}
		return fmt.Sprintf("snat for %s cleared", p.LANIp), nil
	}

	if p.PublicIP == "" {
		return "", fmt.Errorf("public_ip is required when action=set")
	}
	if err := iptables.SetLANSNATAndSave(iface, p.LANIp, p.PublicIP, false); err != nil {
		return "", err
	}
	return fmt.Sprintf("snat installed: %s -> %s on %s", p.LANIp, p.PublicIP, iface), nil
}

// validateForwardParams checks the protocol/port/IP fields of a port-forward
// request before they reach the iptables layer.
func validateForwardParams(p *addForwardParams) error {
	switch p.Protocol {
	case "tcp", "udp":
	default:
		return fmt.Errorf("validate: protocol %q: must be tcp or udp", p.Protocol)
	}
	if err := validate.Port(p.PublicPort); err != nil {
		return err
	}
	if p.PublicPortEnd != 0 {
		if err := validate.Port(p.PublicPortEnd); err != nil {
			return err
		}
	}
	if err := validate.Port(p.DestPort); err != nil {
		return err
	}
	if p.DestPortEnd != 0 {
		if err := validate.Port(p.DestPortEnd); err != nil {
			return err
		}
	}
	if err := validate.IPv4(p.DestIP); err != nil {
		return err
	}
	if p.PublicIP != "" {
		if err := validate.IPv4(p.PublicIP); err != nil {
			return err
		}
	}
	return nil
}

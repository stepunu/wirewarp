package handlers

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	"github.com/wirewarp/agent/internal/wireguard"
)

// ClientHandlers holds the live WireGuard client instance and config path.
type ClientHandlers struct {
	cfgPath string
	cfg     *config.Config
	wg      *wireguard.Client
}

// NewClient initialises the WireGuard client from saved config and returns a handler set.
// If a config exists and was previously initialised, it brings the interface back up
// immediately (offline-resilience, task 4.5).
func NewClient(cfg *config.Config, cfgPath string) (*ClientHandlers, error) {
	h := &ClientHandlers{cfgPath: cfgPath, cfg: cfg}

	if cfg.Client == nil || !cfg.Client.Initialized {
		log.Println("[client] no saved client config — waiting for wg_configure command")
		return h, nil
	}

	s := cfg.Client
	wgCli, err := wireguard.NewClient(wireguard.ClientConfig{
		Interface:       s.WGInterface,
		TunnelIP:        s.TunnelIP,
		ServerPublicKey: s.ServerPublicKey,
		ServerEndpoint:  s.ServerEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("wireguard.NewClient: %w", err)
	}

	if err := wgCli.Up(); err != nil {
		log.Printf("[client] WARN: failed to restore WireGuard interface on startup: %v", err)
	} else {
		log.Printf("[client] WireGuard interface %s restored from saved config", s.WGInterface)
		// Re-apply gateway routing if it was configured
		if s.Initialized {
			if err := h.applyGateway(s); err != nil {
				log.Printf("[client] WARN: failed to restore gateway routing: %v", err)
			}
		}
	}

	h.wg = wgCli
	return h, nil
}

// Register binds all client-mode command handlers onto the given executor.
func (h *ClientHandlers) Register(exec *executor.Executor) {
	exec.Register("wg_configure", h.handleWGConfigure)
	exec.Register("wg_update_endpoint", h.handleUpdateEndpoint)
	exec.Register("wg_down", h.handleWGDown)
}

// --- command handlers ---

type wgConfigureParams struct {
	Interface       string `json:"wg_interface"`
	TunnelIP        string `json:"tunnel_ip"`
	ServerPublicKey string `json:"server_public_key"`
	ServerEndpoint  string `json:"server_endpoint"`  // host:port
	VPSTunnelIP     string `json:"vps_tunnel_ip"`
	LANIface        string `json:"lan_iface"`
	LANNetwork      string `json:"lan_network"`
	LANIP           string `json:"lan_ip"`
	IsGateway       bool   `json:"is_gateway"`
}

func (h *ClientHandlers) handleWGConfigure(raw json.RawMessage) (string, error) {
	var p wgConfigureParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}

	wgCli, err := wireguard.NewClient(wireguard.ClientConfig{
		Interface:       p.Interface,
		TunnelIP:        p.TunnelIP,
		ServerPublicKey: p.ServerPublicKey,
		ServerEndpoint:  p.ServerEndpoint,
	})
	if err != nil {
		return "", err
	}
	if err := wgCli.Up(); err != nil {
		return "", err
	}
	h.wg = wgCli

	// Persist state
	h.cfg.Client = &config.ClientState{
		WGInterface:     p.Interface,
		TunnelIP:        p.TunnelIP,
		ServerPublicKey: p.ServerPublicKey,
		ServerEndpoint:  p.ServerEndpoint,
		VPSTunnelIP:     p.VPSTunnelIP,
		LANIface:        p.LANIface,
		LANNetwork:      p.LANNetwork,
		LANIP:           p.LANIP,
		IsGateway:       p.IsGateway,
		Initialized:     true,
	}
	if err := h.cfg.Save(h.cfgPath); err != nil {
		log.Printf("[client] WARN: failed to save config after wg_configure: %v", err)
	}

	// Apply gateway routing (config is already saved to h.cfg.Client above)
	if err := h.applyGateway(h.cfg.Client); err != nil {
		return "", fmt.Errorf("gateway routing: %w", err)
	}
	if saveErr := wireguard.SaveIPTables(); saveErr != nil {
		log.Printf("[client] WARN: iptables save failed: %v", saveErr)
	}

	return fmt.Sprintf("WireGuard interface %s up; public key: %s", p.Interface, wgCli.PublicKey), nil
}

type updateEndpointParams struct {
	ServerEndpoint string `json:"server_endpoint"`
}

func (h *ClientHandlers) handleUpdateEndpoint(raw json.RawMessage) (string, error) {
	if h.wg == nil {
		return "", fmt.Errorf("WireGuard not configured — send wg_configure first")
	}
	var p updateEndpointParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := h.wg.UpdateEndpoint(p.ServerEndpoint); err != nil {
		return "", err
	}
	if h.cfg.Client != nil {
		h.cfg.Client.ServerEndpoint = p.ServerEndpoint
		if err := h.cfg.Save(h.cfgPath); err != nil {
			log.Printf("[client] WARN: failed to save config after endpoint update: %v", err)
		}
	}
	return fmt.Sprintf("server endpoint updated to %s", p.ServerEndpoint), nil
}

func (h *ClientHandlers) handleWGDown(raw json.RawMessage) (string, error) {
	if h.wg == nil {
		return "already down", nil
	}
	if h.cfg.Client != nil {
		gwCfg := buildGatewayConfig(h.cfg.Client)
		wireguard.TeardownGatewayRouting(gwCfg) //nolint:errcheck
	}
	if err := h.wg.Down(); err != nil {
		return "", err
	}
	h.wg = nil
	return "WireGuard interface down", nil
}

func (h *ClientHandlers) applyGateway(s *config.ClientState) error {
	gwCfg := buildGatewayConfig(s)
	return wireguard.ApplyGatewayRouting(gwCfg)
}

func buildGatewayConfig(s *config.ClientState) wireguard.GatewayConfig {
	return wireguard.GatewayConfig{
		TunnelIface:     s.WGInterface,
		LANIface:        s.LANIface,
		VPSEndpointIP:   hostFromEndpoint(s.ServerEndpoint),
		VPSTunnelIP:     s.VPSTunnelIP,
		GatewayTunnelIP: s.TunnelIP,
		GatewayLANIP:    s.LANIP,
		LANNetwork:      s.LANNetwork,
		IsGateway:       s.IsGateway,
	}
}

// hostFromEndpoint returns the host portion of a "host:port" endpoint string.
func hostFromEndpoint(endpoint string) string {
	for i := len(endpoint) - 1; i >= 0; i-- {
		if endpoint[i] == ':' {
			return endpoint[:i]
		}
	}
	return endpoint
}

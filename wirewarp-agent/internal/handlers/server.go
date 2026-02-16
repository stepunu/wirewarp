// Package handlers wires control-server commands to wireguard/iptables operations.
package handlers

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	"github.com/wirewarp/agent/internal/iptables"
	"github.com/wirewarp/agent/internal/wireguard"
)

// ServerHandlers holds the live WireGuard server instance and config path.
type ServerHandlers struct {
	cfgPath string
	cfg     *config.Config
	wg      *wireguard.Server
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

	if err := wgSrv.Init(); err != nil {
		log.Printf("[server] WARN: failed to restore WireGuard interface on startup: %v", err)
	} else {
		log.Printf("[server] WireGuard interface %s restored from saved config", s.WGInterface)
	}

	h.wg = wgSrv
	return h, nil
}

// Register binds all server-mode command handlers onto the given executor.
func (h *ServerHandlers) Register(exec *executor.Executor) {
	exec.Register("wg_init", h.handleWGInit)
	exec.Register("wg_add_peer", h.handleAddPeer)
	exec.Register("wg_remove_peer", h.handleRemovePeer)
	exec.Register("iptables_add_forward", h.handleAddForward)
	exec.Register("iptables_remove_forward", h.handleRemoveForward)
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

	wgSrv, err := wireguard.NewServer(wireguard.ServerConfig{
		Interface:     p.Interface,
		ListenPort:    p.ListenPort,
		TunnelNetwork: p.TunnelNetwork,
		TunnelIP:      p.TunnelIP,
	})
	if err != nil {
		return "", err
	}
	if err := wgSrv.Init(); err != nil {
		return "", err
	}
	h.wg = wgSrv

	// Persist state
	h.cfg.Server = &config.ServerState{
		WGInterface:   p.Interface,
		WGPort:        p.ListenPort,
		TunnelNetwork: p.TunnelNetwork,
		TunnelIP:      p.TunnelIP,
		PublicIface:   p.PublicIface,
		PublicIP:      p.PublicIP,
		Initialized:   true,
	}
	if err := h.cfg.Save(h.cfgPath); err != nil {
		log.Printf("[server] WARN: failed to save config after wg_init: %v", err)
	}

	return fmt.Sprintf("WireGuard interface %s initialised; public key: %s", p.Interface, wgSrv.PublicKey), nil
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
	if err := h.wg.AddPeer(wireguard.Peer{
		Name:       p.Name,
		PublicKey:  p.PublicKey,
		TunnelIP:   p.TunnelIP,
		AllowedIPs: p.AllowedIPs,
	}); err != nil {
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
	if err := h.wg.RemovePeer(p.PublicKey); err != nil {
		return "", err
	}
	return fmt.Sprintf("peer %s removed", p.PublicKey), nil
}

type addForwardParams struct {
	Protocol   string `json:"protocol"`
	PublicPort int    `json:"public_port"`
	DestIP     string `json:"destination_ip"`
	DestPort   int    `json:"destination_port"`
}

func (h *ServerHandlers) handleAddForward(raw json.RawMessage) (string, error) {
	var p addForwardParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	publicIP := ""
	if h.cfg.Server != nil {
		publicIP = h.cfg.Server.PublicIP
	}
	if err := iptables.AddForward(publicIP, iptables.ForwardRule{
		Protocol:   p.Protocol,
		PublicPort: p.PublicPort,
		DestIP:     p.DestIP,
		DestPort:   p.DestPort,
	}); err != nil {
		return "", err
	}
	if saveErr := iptables.SaveRules(); saveErr != nil {
		log.Printf("[server] WARN: iptables save failed: %v", saveErr)
	}
	return fmt.Sprintf("forward %s:%d → %s:%d added", p.Protocol, p.PublicPort, p.DestIP, p.DestPort), nil
}

func (h *ServerHandlers) handleRemoveForward(raw json.RawMessage) (string, error) {
	var p addForwardParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	publicIP := ""
	if h.cfg.Server != nil {
		publicIP = h.cfg.Server.PublicIP
	}
	if err := iptables.RemoveForward(publicIP, iptables.ForwardRule{
		Protocol:   p.Protocol,
		PublicPort: p.PublicPort,
		DestIP:     p.DestIP,
		DestPort:   p.DestPort,
	}); err != nil {
		return "", err
	}
	if saveErr := iptables.SaveRules(); saveErr != nil {
		log.Printf("[server] WARN: iptables save failed: %v", saveErr)
	}
	return fmt.Sprintf("forward %s:%d → %s:%d removed", p.Protocol, p.PublicPort, p.DestIP, p.DestPort), nil
}

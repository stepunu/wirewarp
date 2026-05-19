package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	"github.com/wirewarp/agent/internal/validate"
	"github.com/wirewarp/agent/internal/wireguard"
)

// Per-attachment ip-rule priority for the reply-mark lookup.
// 30000 + ordinal — derived from the wgN suffix.
func replyPriorityForIface(iface string) string {
	if !strings.HasPrefix(iface, "wg") {
		return "30000"
	}
	suffix := iface[2:]
	if suffix == "" {
		return "30000"
	}
	// Re-emit as 30000+N. We accept the suffix verbatim to keep the priority
	// stable across restarts even if the agent doesn't re-parse the integer
	// itself; ip rule priority is just a string to the kernel.
	return fmt.Sprintf("3000%s", suffix)
}

// ClientHandlers holds one wireguard.Client instance per active attachment,
// keyed by interface name (wg0, wg1, ...).
type ClientHandlers struct {
	cfgPath string
	cfg     *config.Config
	wgs     map[string]*wireguard.Client
	// emit is the upstream telemetry channel set by SetEmit. The healer
	// goroutine (see client_heal.go) loads this atomically to push
	// heal_event frames to the control server.
	emit atomic.Pointer[EmitFn]
}

// NewClient initialises the WireGuard client(s) from saved config and
// returns a handler set. Every saved attachment is brought up immediately
// (offline-resilience).
func NewClient(cfg *config.Config, cfgPath string) (*ClientHandlers, error) {
	h := &ClientHandlers{
		cfgPath: cfgPath,
		cfg:     cfg,
		wgs:     make(map[string]*wireguard.Client),
	}

	if len(cfg.Attachments) == 0 {
		log.Println("[client] no saved attachments — waiting for wg_attach command")
		return h, nil
	}

	// Install the global mangle OUTPUT CONNMARK restore rule once. Per-
	// attachment routing only writes the PREROUTING marks; the OUTPUT side
	// is shared across attachments since CONNMARK already disambiguates.
	if err := wireguard.EnsureOutputConnmark(); err != nil {
		log.Printf("[client] WARN: failed to ensure OUTPUT CONNMARK restore: %v", err)
	}

	for i := range cfg.Attachments {
		att := &cfg.Attachments[i]
		if err := h.bringAttachmentUp(att); err != nil {
			log.Printf("[client] WARN: failed to restore attachment %s on startup: %v", att.WGInterface, err)
		} else {
			log.Printf("[client] attachment %s restored from saved config", att.WGInterface)
		}
	}

	return h, nil
}

// Shutdown tears down per-attachment routing and brings every wgN down.
func (h *ClientHandlers) Shutdown() {
	for _, att := range h.cfg.Attachments {
		gwCfg := h.buildGatewayConfig(&att)
		if err := wireguard.TeardownGatewayRouting(gwCfg); err != nil {
			log.Printf("[client] WARN: teardown gateway routing for %s: %v", att.WGInterface, err)
		}
	}
	for iface, wg := range h.wgs {
		if err := wg.Down(); err != nil {
			log.Printf("[client] WARN: wg-quick down %s: %v", iface, err)
		} else {
			log.Printf("[client] %s down", iface)
		}
	}
}

// MeshInterfaces returns every WG interface this gateway client has
// attached to a tunnel server. The heartbeat picks these up so the
// dashboard can show per-attachment peer stats. Snapshots the slice
// under the same defensive copy as the healer.
func (h *ClientHandlers) MeshInterfaces() []string {
	atts := h.snapshotAttachments()
	if len(atts) == 0 {
		return nil
	}
	out := make([]string, 0, len(atts))
	for _, a := range atts {
		if a.WGInterface != "" {
			out = append(out, a.WGInterface)
		}
	}
	return out
}

// Register binds all client-mode command handlers onto the given executor.
func (h *ClientHandlers) Register(exec *executor.Executor) {
	exec.Register("wg_attach", h.handleWGAttach)
	exec.Register("wg_detach", h.handleWGDetach)
	exec.Register("wg_update_endpoint", h.handleUpdateEndpoint)
	exec.Register("set_lan_egress", h.handleSetLANEgress)
}

// --- command handlers ---

type wgAttachParams struct {
	AttachmentID         string `json:"attachment_id"`
	WGInterface          string `json:"wg_interface"`
	TunnelIP             string `json:"tunnel_ip"`
	Fwmark               int    `json:"fwmark"`
	RouteTableID         int    `json:"route_table_id"`
	ServerEndpoint       string `json:"server_endpoint"`
	ServerPublicKey      string `json:"server_public_key"`
	ServerTunnelNetwork  string `json:"server_tunnel_network"`
	VPSTunnelIP          string `json:"vps_tunnel_ip"`
	LANIface             string `json:"lan_iface"`
	LANNetwork           string `json:"lan_network"`
	LANIP                string `json:"lan_ip"`
	IsGateway            bool   `json:"is_gateway"`
}

func (h *ClientHandlers) handleWGAttach(raw json.RawMessage) (string, error) {
	var p wgAttachParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.Interface(p.WGInterface); err != nil {
		return "", err
	}
	if err := validate.IPv4(p.TunnelIP); err != nil {
		return "", err
	}
	if err := validate.WGKey(p.ServerPublicKey); err != nil {
		return "", err
	}
	if err := validate.Endpoint(p.ServerEndpoint); err != nil {
		return "", err
	}
	if p.VPSTunnelIP != "" {
		if err := validate.IPv4(p.VPSTunnelIP); err != nil {
			return "", err
		}
	}
	if p.LANIface != "" {
		if err := validate.PublicIface(p.LANIface); err != nil {
			return "", err
		}
	}
	if p.LANNetwork != "" {
		if err := validate.IPv4CIDR(p.LANNetwork); err != nil {
			return "", err
		}
	}
	if p.LANIP != "" {
		if err := validate.IPv4(p.LANIP); err != nil {
			return "", err
		}
	}
	if p.ServerTunnelNetwork != "" {
		if err := validate.IPv4CIDR(p.ServerTunnelNetwork); err != nil {
			return "", err
		}
	}

	att := config.AttachmentState{
		AttachmentID:    p.AttachmentID,
		WGInterface:     p.WGInterface,
		TunnelIP:        p.TunnelIP,
		ServerPublicKey: p.ServerPublicKey,
		ServerEndpoint:  p.ServerEndpoint,
		VPSTunnelIP:     p.VPSTunnelIP,
		LANIface:        p.LANIface,
		LANNetwork:      p.LANNetwork,
		LANIP:           p.LANIP,
		IsGateway:       p.IsGateway,
		Fwmark:          fmt.Sprintf("0x%x", p.Fwmark),
		RouteTableID:    fmt.Sprintf("%d", p.RouteTableID),
	}
	if p.LANIface == "" {
		att.LANIface = "eth0"
	}

	if err := wireguard.EnsureOutputConnmark(); err != nil {
		log.Printf("[client] WARN: failed to ensure OUTPUT CONNMARK restore: %v", err)
	}

	wgCli, err := h.bringSingleUp(&att)
	if err != nil {
		return "", err
	}
	pubKey := wgCli.PublicKey

	h.cfg.UpsertAttachment(att)
	if err := h.cfg.Save(h.cfgPath); err != nil {
		log.Printf("[client] WARN: failed to save config after wg_attach: %v", err)
	}
	if saveErr := wireguard.SaveIPTables(); saveErr != nil {
		log.Printf("[client] WARN: iptables save failed: %v", saveErr)
	}

	return fmt.Sprintf("attachment %s up on %s; public key: %s", p.AttachmentID, p.WGInterface, pubKey), nil
}

type wgDetachParams struct {
	AttachmentID string `json:"attachment_id"`
	WGInterface  string `json:"wg_interface"`
	Fwmark       int    `json:"fwmark"`
	RouteTableID int    `json:"route_table_id"`
	LANIface     string `json:"lan_iface"`
}

func (h *ClientHandlers) handleWGDetach(raw json.RawMessage) (string, error) {
	var p wgDetachParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if p.WGInterface != "" {
		if err := validate.Interface(p.WGInterface); err != nil {
			return "", err
		}
	}
	if p.LANIface != "" {
		if err := validate.PublicIface(p.LANIface); err != nil {
			return "", err
		}
	}
	iface := p.WGInterface
	if iface == "" {
		// Best-effort lookup by attachment_id if interface wasn't specified.
		if att := h.cfg.FindAttachment(p.AttachmentID, ""); att != nil {
			iface = att.WGInterface
		}
	}
	if iface == "" {
		return "no matching attachment", nil
	}

	saved := h.cfg.FindAttachment(p.AttachmentID, iface)
	if saved != nil {
		gwCfg := h.buildGatewayConfig(saved)
		if err := wireguard.TeardownGatewayRouting(gwCfg); err != nil {
			log.Printf("[client] WARN: teardown gateway routing for %s: %v", iface, err)
		}
	} else {
		// Best-effort teardown using the params we received.
		gwCfg := wireguard.GatewayConfig{
			TunnelIface:   iface,
			LANIface:      p.LANIface,
			Fwmark:        fmt.Sprintf("0x%x", p.Fwmark),
			RouteTableID:  fmt.Sprintf("%d", p.RouteTableID),
			ReplyPriority: replyPriorityForIface(iface),
		}
		wireguard.TeardownGatewayRouting(gwCfg) //nolint:errcheck
	}

	if wg, ok := h.wgs[iface]; ok {
		if err := wg.Down(); err != nil {
			log.Printf("[client] WARN: wg-quick down %s: %v", iface, err)
		}
		delete(h.wgs, iface)
	}

	h.cfg.RemoveAttachment(iface)
	if err := h.cfg.Save(h.cfgPath); err != nil {
		log.Printf("[client] WARN: failed to save config after wg_detach: %v", err)
	}
	if saveErr := wireguard.SaveIPTables(); saveErr != nil {
		log.Printf("[client] WARN: iptables save failed: %v", saveErr)
	}

	return fmt.Sprintf("attachment %s detached", iface), nil
}

// lanEgressIPRulePriority is the ip rule priority used for per-LAN-host
// egress pinning. Sits well below the per-attachment fwmark rules (which
// start at 30000) so the explicit "from <lan_ip>" match takes precedence
// for the first packet of a NEW outbound flow (when the conntrack mark
// hasn't been set yet by a returning reply).
const lanEgressIPRulePriority = "5000"

type setLANEgressParams struct {
	LANIP        string `json:"lan_ip"`
	RouteTableID int    `json:"route_table_id"` // 0 = clear pin
	WGInterface  string `json:"wg_interface"`   // informational, not used by the rule
}

func (h *ClientHandlers) handleSetLANEgress(raw json.RawMessage) (string, error) {
	var p setLANEgressParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if p.LANIP == "" {
		return "", fmt.Errorf("lan_ip is required")
	}
	if err := validate.IPv4(p.LANIP); err != nil {
		return "", err
	}
	if p.WGInterface != "" {
		if err := validate.Interface(p.WGInterface); err != nil {
			return "", err
		}
	}

	// Always remove any existing rule for this LAN IP at our priority. ip
	// rule del is idempotent (returns non-zero if absent); we don't care.
	for {
		cmd := exec.Command(
			"ip", "rule", "del",
			"from", p.LANIP, "priority", lanEgressIPRulePriority,
		)
		if cmd.Run() != nil {
			break
		}
	}

	if p.RouteTableID == 0 {
		return fmt.Sprintf("egress pin for %s cleared", p.LANIP), nil
	}

	tableID := strconv.Itoa(p.RouteTableID)
	out, err := exec.Command(
		"ip", "rule", "add",
		"from", p.LANIP,
		"table", tableID,
		"priority", lanEgressIPRulePriority,
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip rule add: %w — %s", err, out)
	}
	return fmt.Sprintf("egress pinned: %s -> table %s (%s)", p.LANIP, tableID, p.WGInterface), nil
}

type updateEndpointParams struct {
	AttachmentID   string `json:"attachment_id"`
	WGInterface    string `json:"wg_interface"`
	ServerEndpoint string `json:"server_endpoint"`
}

func (h *ClientHandlers) handleUpdateEndpoint(raw json.RawMessage) (string, error) {
	var p updateEndpointParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := validate.Endpoint(p.ServerEndpoint); err != nil {
		return "", err
	}
	if p.WGInterface != "" {
		if err := validate.Interface(p.WGInterface); err != nil {
			return "", err
		}
	}
	iface := p.WGInterface
	if iface == "" {
		if att := h.cfg.FindAttachment(p.AttachmentID, ""); att != nil {
			iface = att.WGInterface
		}
	}
	wg, ok := h.wgs[iface]
	if !ok {
		return "", fmt.Errorf("no live attachment for interface %s", iface)
	}
	if err := wg.UpdateEndpoint(p.ServerEndpoint); err != nil {
		return "", err
	}
	if att := h.cfg.FindAttachment(p.AttachmentID, iface); att != nil {
		att.ServerEndpoint = p.ServerEndpoint
		if err := h.cfg.Save(h.cfgPath); err != nil {
			log.Printf("[client] WARN: failed to save config after endpoint update: %v", err)
		}
	}
	return fmt.Sprintf("server endpoint for %s updated to %s", iface, p.ServerEndpoint), nil
}

// --- helpers ---

func (h *ClientHandlers) bringAttachmentUp(att *config.AttachmentState) error {
	_, err := h.bringSingleUp(att)
	return err
}

func (h *ClientHandlers) bringSingleUp(att *config.AttachmentState) (*wireguard.Client, error) {
	wgCli, err := wireguard.NewClient(wireguard.ClientConfig{
		Interface:       att.WGInterface,
		TunnelIP:        att.TunnelIP,
		ServerPublicKey: att.ServerPublicKey,
		ServerEndpoint:  att.ServerEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("wireguard.NewClient: %w", err)
	}
	if err := wgCli.Up(); err != nil {
		return nil, fmt.Errorf("wg-quick up %s: %w", att.WGInterface, err)
	}
	gwCfg := h.buildGatewayConfig(att)
	if err := wireguard.ApplyGatewayRouting(gwCfg); err != nil {
		return nil, fmt.Errorf("apply gateway routing for %s: %w", att.WGInterface, err)
	}
	h.wgs[att.WGInterface] = wgCli
	return wgCli, nil
}

func (h *ClientHandlers) buildGatewayConfig(att *config.AttachmentState) wireguard.GatewayConfig {
	wgSubnet := tunnelSubnet(att.TunnelIP)
	return wireguard.GatewayConfig{
		TunnelIface:     att.WGInterface,
		LANIface:        att.LANIface,
		VPSTunnelIP:     att.VPSTunnelIP,
		GatewayTunnelIP: att.TunnelIP,
		GatewayLANIP:    att.LANIP,
		LANNetwork:      att.LANNetwork,
		WGSubnet:        wgSubnet,
		IsGateway:       att.IsGateway,
		Fwmark:          att.Fwmark,
		RouteTableID:    att.RouteTableID,
		ReplyPriority:   replyPriorityForIface(att.WGInterface),
	}
}

// tunnelSubnet derives the /24 network CIDR from a WireGuard tunnel IP.
// e.g. "10.21.0.3" → "10.21.0.0/24"
func tunnelSubnet(tunnelIP string) string {
	ip := net.ParseIP(tunnelIP).To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

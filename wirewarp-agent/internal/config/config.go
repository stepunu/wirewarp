package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/wirewarp/agent.yaml"

type Config struct {
	Mode             string `yaml:"mode"`              // "server" | "client"
	ControlServerURL string `yaml:"control_server_url"`
	AgentToken       string `yaml:"agent_token"`        // registration token (cleared after use)
	AgentJWT         string `yaml:"agent_jwt"`          // JWT issued after registration
	AgentID          string `yaml:"agent_id"`

	// Insecure opts the agent into accepting a plain http:// (and therefore
	// ws://) control-server URL. Default false. Set at install time via
	// --insecure; persisted so reconnects honour the same trust decision.
	// Intended for homelab bootstrap where TLS isn't up yet — production
	// deployments should always use https.
	Insecure bool `yaml:"insecure,omitempty"`

	// WireGuard server state (mode=server)
	Server *ServerState `yaml:"server,omitempty"`

	// Multi-attachment client state (mode=client). Replaces the legacy
	// single-peer Client field; older configs are migrated transparently.
	Attachments []AttachmentState `yaml:"attachments,omitempty"`

	// Road-warrior VPN endpoints hosted on this agent (gateway clients
	// only — the server doesn't run end-user wg). One row per
	// `wg-vpn<N>` interface. Today the model has at most one per
	// gateway; using a slice keeps room for future expansion without
	// a config migration.
	VpnEndpoints []VpnEndpointState `yaml:"vpn_endpoints,omitempty"`

	// LegacyClient is the pre-multi-server-gateway single-peer field. It is
	// only ever populated on Load when reading an old config file; we
	// immediately migrate it into Attachments and clear this field on the
	// next Save. New writes never include it (yaml `,omitempty` plus
	// post-migrate clear).
	LegacyClient *ClientState `yaml:"client,omitempty"`
}

// ServerState holds the last-known config for the tunnel server agent.
type ServerState struct {
	WGInterface   string `yaml:"wg_interface"`
	WGPort        int    `yaml:"wg_port"`
	TunnelNetwork string `yaml:"tunnel_network"`
	TunnelIP      string `yaml:"tunnel_ip"`
	PublicIface   string `yaml:"public_iface"`
	PublicIP      string `yaml:"public_ip"`
	Initialized   bool   `yaml:"initialized"`
}

// ClientState is the legacy single-peer client config. Kept here only so
// we can parse pre-multi-server-gateway agent.yaml files and migrate them
// in-place to the new Attachments slice.
type ClientState struct {
	WGInterface     string `yaml:"wg_interface"`
	TunnelIP        string `yaml:"tunnel_ip"`
	ServerPublicKey string `yaml:"server_public_key"`
	ServerEndpoint  string `yaml:"server_endpoint"`
	VPSTunnelIP     string `yaml:"vps_tunnel_ip"`
	LANIface        string `yaml:"lan_iface"`
	LANNetwork      string `yaml:"lan_network"`
	LANIP           string `yaml:"lan_ip"`
	IsGateway       bool   `yaml:"is_gateway"`
	Initialized     bool   `yaml:"initialized"`
}

// VpnEndpointState is the persisted shape of one road-warrior endpoint.
// On agent restart the handler reads this back and re-creates the wg
// interface (offline-resilience). Peers are never persisted here — the
// server replays vpn_peer_add for each profile on (re)connect.
type VpnEndpointState struct {
	EndpointID    string   `yaml:"endpoint_id"`
	WGInterface   string   `yaml:"wg_interface"`
	ListenPort    int      `yaml:"listen_port"`
	VpnNetwork    string   `yaml:"vpn_network"`
	VpnServerIP   string   `yaml:"vpn_server_ip"`
	DNSServers    []string `yaml:"dns_servers,omitempty"`
}

// AttachmentState holds the agent-side state for one peering between this
// gateway and one tunnel server. Each attachment owns one wgN interface.
type AttachmentState struct {
	AttachmentID    string `yaml:"attachment_id"`
	WGInterface     string `yaml:"wg_interface"`
	TunnelIP        string `yaml:"tunnel_ip"`
	ServerPublicKey string `yaml:"server_public_key"`
	ServerEndpoint  string `yaml:"server_endpoint"`
	VPSTunnelIP     string `yaml:"vps_tunnel_ip"`
	LANIface        string `yaml:"lan_iface"`
	LANNetwork      string `yaml:"lan_network"`
	LANIP           string `yaml:"lan_ip"`
	IsGateway       bool   `yaml:"is_gateway"`
	Fwmark          string `yaml:"fwmark"`         // hex form, e.g. "0x101"
	RouteTableID    string `yaml:"route_table_id"` // decimal, e.g. "100"
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// One-shot legacy migration: a pre-multi-server-gateway agent.yaml has
	// `client: {...}` and no `attachments:` key. Synthesize one attachment
	// row using the spec's default fwmark/route_table_id (0x101 / 100),
	// clear the legacy field, and persist.
	if cfg.LegacyClient != nil && cfg.LegacyClient.Initialized && len(cfg.Attachments) == 0 {
		c := cfg.LegacyClient
		iface := c.WGInterface
		if iface == "" {
			iface = "wg0"
		}
		cfg.Attachments = []AttachmentState{{
			AttachmentID:    "", // server fills this back via re-issued wg_attach
			WGInterface:     iface,
			TunnelIP:        c.TunnelIP,
			ServerPublicKey: c.ServerPublicKey,
			ServerEndpoint:  c.ServerEndpoint,
			VPSTunnelIP:     c.VPSTunnelIP,
			LANIface:        c.LANIface,
			LANNetwork:      c.LANNetwork,
			LANIP:           c.LANIP,
			IsGateway:       c.IsGateway,
			Fwmark:          "0x101",
			RouteTableID:    "100",
		}}
		cfg.LegacyClient = nil
		if saveErr := cfg.Save(path); saveErr != nil {
			log.Printf("[config] WARN: failed to persist legacy-client migration: %v", saveErr)
		} else {
			log.Printf("[config] migrated legacy `client:` config to attachments[0] (iface=%s)", iface)
		}
	}

	return &cfg, nil
}

func (c *Config) Save(path string) error {
	if err := os.MkdirAll("/etc/wirewarp", 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// FindAttachment returns the attachment matching the given identifier
// (preferring AttachmentID match, then WGInterface), or nil.
func (c *Config) FindAttachment(attachmentID, wgInterface string) *AttachmentState {
	for i := range c.Attachments {
		a := &c.Attachments[i]
		if attachmentID != "" && a.AttachmentID == attachmentID {
			return a
		}
		if wgInterface != "" && a.WGInterface == wgInterface {
			return a
		}
	}
	return nil
}

// UpsertAttachment inserts or replaces an attachment by WGInterface.
func (c *Config) UpsertAttachment(att AttachmentState) {
	for i := range c.Attachments {
		if c.Attachments[i].WGInterface == att.WGInterface {
			c.Attachments[i] = att
			return
		}
	}
	c.Attachments = append(c.Attachments, att)
}

// RemoveAttachment removes an attachment by WGInterface. Returns true if a
// row was removed.
func (c *Config) RemoveAttachment(wgInterface string) bool {
	for i := range c.Attachments {
		if c.Attachments[i].WGInterface == wgInterface {
			c.Attachments = append(c.Attachments[:i], c.Attachments[i+1:]...)
			return true
		}
	}
	return false
}

// FindVpnEndpoint returns the VPN endpoint matching the given interface,
// or nil.
func (c *Config) FindVpnEndpoint(wgInterface string) *VpnEndpointState {
	for i := range c.VpnEndpoints {
		if c.VpnEndpoints[i].WGInterface == wgInterface {
			return &c.VpnEndpoints[i]
		}
	}
	return nil
}

// UpsertVpnEndpoint inserts or replaces a VPN endpoint by WGInterface.
func (c *Config) UpsertVpnEndpoint(ep VpnEndpointState) {
	for i := range c.VpnEndpoints {
		if c.VpnEndpoints[i].WGInterface == ep.WGInterface {
			c.VpnEndpoints[i] = ep
			return
		}
	}
	c.VpnEndpoints = append(c.VpnEndpoints, ep)
}

// RemoveVpnEndpoint deletes a VPN endpoint by WGInterface. Returns true
// if a row was removed.
func (c *Config) RemoveVpnEndpoint(wgInterface string) bool {
	for i := range c.VpnEndpoints {
		if c.VpnEndpoints[i].WGInterface == wgInterface {
			c.VpnEndpoints = append(c.VpnEndpoints[:i], c.VpnEndpoints[i+1:]...)
			return true
		}
	}
	return false
}

package config

import (
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

	// WireGuard server state (mode=server)
	Server *ServerState `yaml:"server,omitempty"`

	// WireGuard client state (mode=client)
	Client *ClientState `yaml:"client,omitempty"`
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

// ClientState holds the last-known config for the tunnel client agent.
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

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
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

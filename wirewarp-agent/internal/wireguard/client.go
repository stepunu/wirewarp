package wireguard

import (
	"fmt"
	"os"
	"strings"
)

// clientPrivateKeyFile and clientConfigFile reuse the package-level constants
// defined in server.go — both modes use the same paths on the same machine.

// ClientConfig holds everything needed to build the client wg0.conf.
type ClientConfig struct {
	Interface    string // e.g. "wg0"
	TunnelIP     string // this client's tunnel IP, e.g. "10.0.0.3"
	ServerPublicKey string
	ServerEndpoint  string // host:port, e.g. "1.2.3.4:51820"
	// AllowedIPs for the server peer — typically the full tunnel network.
	AllowedIPs []string
}

// Client manages the WireGuard client-side interface on a gateway LXC/VM.
type Client struct {
	cfg        ClientConfig
	privateKey string
	PublicKey  string
}

// NewClient creates a Client, generating a keypair if one doesn't exist yet.
func NewClient(cfg ClientConfig) (*Client, error) {
	if err := os.MkdirAll(wgDir, 0700); err != nil {
		return nil, fmt.Errorf("create wireguard dir: %w", err)
	}

	privateKey, err := loadOrGenPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}

	publicKey, err := derivePubKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:        cfg,
		privateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// Up writes the client config and brings the interface up.
// Table = off disables wg-quick's automatic routing — the gateway module handles routing.
func (c *Client) Up() error {
	if err := c.writeConfig(); err != nil {
		return err
	}
	if interfaceExists(c.cfg.Interface) {
		return wgSyncConf(c.cfg.Interface, configFile)
	}
	return wgQuickUp(c.cfg.Interface)
}

// Down tears down the interface.
func (c *Client) Down() error {
	return wgQuickDown(c.cfg.Interface)
}

// UpdateEndpoint changes the server endpoint without tearing down the tunnel.
func (c *Client) UpdateEndpoint(newEndpoint string) error {
	c.cfg.ServerEndpoint = newEndpoint
	if err := c.writeConfig(); err != nil {
		return err
	}
	return wgSyncConf(c.cfg.Interface, configFile)
}

func (c *Client) writeConfig() error {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s/24\n", c.cfg.TunnelIP))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.privateKey))
	// Table = off: we apply routing manually via the gateway module.
	b.WriteString("Table = off\n")
	b.WriteString("\n")

	b.WriteString("[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", c.cfg.ServerPublicKey))
	b.WriteString(fmt.Sprintf("Endpoint = %s\n", c.cfg.ServerEndpoint))
	allowed := c.cfg.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(allowed, ", ")))
	b.WriteString("PersistentKeepalive = 25\n")
	b.WriteString("\n")

	return os.WriteFile(configFile, []byte(b.String()), 0600)
}

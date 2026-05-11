package wireguard

import (
	"fmt"
	"os"
	"strings"

	"github.com/wirewarp/agent/internal/validate"
)

// ClientConfig holds everything needed to build a per-interface client conf.
type ClientConfig struct {
	Interface       string // e.g. "wg0", "wg1", ...
	TunnelIP        string // this client's tunnel IP, e.g. "10.21.0.3"
	ServerPublicKey string
	ServerEndpoint  string // host:port, e.g. "1.2.3.4:51820"
	// AllowedIPs for the server peer — typically the full tunnel network.
	AllowedIPs []string
}

// Client manages one WireGuard client-side interface on a gateway LXC/VM.
// The agent may hold multiple Client instances simultaneously, one per
// attachment (one per peer tunnel server).
type Client struct {
	cfg        ClientConfig
	privateKey string
	PublicKey  string
}

// NewClient creates a Client, generating a keypair for this interface if
// one doesn't exist yet. Each interface owns its own /etc/wireguard/<iface>.key.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Interface != "" {
		if err := validate.Interface(cfg.Interface); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(wgDir, 0700); err != nil {
		return nil, fmt.Errorf("create wireguard dir: %w", err)
	}

	privateKey, err := loadOrGenPrivateKey(keyPath(cfg.Interface))
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
// Table = off disables wg-quick's automatic routing — the gateway module
// handles per-attachment routing via fwmark + route_table_id.
func (c *Client) Up() error {
	if err := c.writeConfig(); err != nil {
		return err
	}
	if interfaceExists(c.cfg.Interface) {
		return wgSyncConf(c.cfg.Interface, confPath(c.cfg.Interface))
	}
	return wgQuickUp(c.cfg.Interface)
}

// Down tears down the interface. Does NOT delete the private key file —
// the keypair survives detach so a re-attach reuses the same identity.
func (c *Client) Down() error {
	return wgQuickDown(c.cfg.Interface)
}

// UpdateEndpoint changes the server endpoint without tearing down the tunnel.
func (c *Client) UpdateEndpoint(newEndpoint string) error {
	if err := validate.Endpoint(newEndpoint); err != nil {
		return err
	}
	c.cfg.ServerEndpoint = newEndpoint
	if err := c.writeConfig(); err != nil {
		return err
	}
	return wgSyncConf(c.cfg.Interface, confPath(c.cfg.Interface))
}

func (c *Client) writeConfig() error {
	if err := validate.NoControlChars(c.cfg.TunnelIP); err != nil {
		return fmt.Errorf("client config TunnelIP: %w", err)
	}
	if err := validate.NoControlChars(c.privateKey); err != nil {
		return fmt.Errorf("client private key: %w", err)
	}
	if err := validate.NoControlChars(c.cfg.ServerPublicKey); err != nil {
		return fmt.Errorf("client ServerPublicKey: %w", err)
	}
	if err := validate.NoControlChars(c.cfg.ServerEndpoint); err != nil {
		return fmt.Errorf("client ServerEndpoint: %w", err)
	}
	for _, a := range c.cfg.AllowedIPs {
		if err := validate.NoControlChars(a); err != nil {
			return fmt.Errorf("client AllowedIPs: %w", err)
		}
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s/24\n", c.cfg.TunnelIP))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.privateKey))
	b.WriteString("Table = off\n")
	b.WriteString("\n")

	b.WriteString("[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", c.cfg.ServerPublicKey))
	if c.cfg.ServerEndpoint != "" {
		b.WriteString(fmt.Sprintf("Endpoint = %s\n", c.cfg.ServerEndpoint))
	}
	allowed := c.cfg.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(allowed, ", ")))
	b.WriteString("PersistentKeepalive = 25\n")
	b.WriteString("\n")

	return os.WriteFile(confPath(c.cfg.Interface), []byte(b.String()), 0600)
}

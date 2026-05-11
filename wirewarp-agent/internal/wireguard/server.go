package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/wirewarp/agent/internal/validate"
)

const wgDir = "/etc/wireguard"

// keyPath is the on-disk path for a per-interface WireGuard private key.
func keyPath(iface string) string {
	if iface == "" {
		iface = "wg0"
	}
	return fmt.Sprintf("%s/%s.key", wgDir, iface)
}

// confPath is the on-disk path for a per-interface wg-quick config.
func confPath(iface string) string {
	if iface == "" {
		iface = "wg0"
	}
	return fmt.Sprintf("%s/%s.conf", wgDir, iface)
}

// ServerConfig holds the parameters for initializing the WireGuard server interface.
type ServerConfig struct {
	Interface     string // e.g. "wg0"
	ListenPort    int
	TunnelNetwork string // e.g. "10.0.0.0/24"
	TunnelIP      string // e.g. "10.0.0.1"
	// MTU, if non-zero, is written into the wg-quick config so it
	// survives interface re-bring-up. 1280 is the safe default for
	// road-warrior endpoints whose peers traverse cellular networks.
	MTU int
}

// Peer represents a WireGuard peer entry.
type Peer struct {
	Name       string
	PublicKey  string
	PresharedKey string  // optional — emitted as PresharedKey when set
	TunnelIP   string   // assigned tunnel IP for this peer
	AllowedIPs []string // subnets to route through this peer
}

// Server manages the WireGuard server-side interface on a VPS.
type Server struct {
	cfg        ServerConfig
	privateKey string
	PublicKey  string
	peers      map[string]Peer // keyed by public key
}

// NewServer creates a Server, generating a keypair if one doesn't exist yet.
func NewServer(cfg ServerConfig) (*Server, error) {
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

	return &Server{
		cfg:        cfg,
		privateKey: privateKey,
		PublicKey:  publicKey,
		peers:      make(map[string]Peer),
	}, nil
}

// Init writes the per-interface conf and brings the interface up using wg
// syncconf (or wg-quick up on first run).
func (s *Server) Init() error {
	if err := s.writeConfig(); err != nil {
		return err
	}

	if !interfaceExists(s.cfg.Interface) {
		return wgQuickUp(s.cfg.Interface)
	}
	return wgSyncConf(s.cfg.Interface, confPath(s.cfg.Interface))
}

// AddPeer adds or replaces a peer and syncs the config.
func (s *Server) AddPeer(p Peer) error {
	s.peers[p.PublicKey] = p
	if err := s.writeConfig(); err != nil {
		return err
	}
	return wgSyncConf(s.cfg.Interface, confPath(s.cfg.Interface))
}

// RemovePeer removes a peer by public key and syncs the config.
func (s *Server) RemovePeer(publicKey string) error {
	if _, ok := s.peers[publicKey]; !ok {
		return fmt.Errorf("peer not found: %s", publicKey)
	}
	delete(s.peers, publicKey)
	if err := s.writeConfig(); err != nil {
		return err
	}
	return wgSyncConf(s.cfg.Interface, confPath(s.cfg.Interface))
}

// Down tears down the WireGuard interface.
func (s *Server) Down() error {
	return wgQuickDown(s.cfg.Interface)
}

func (s *Server) writeConfig() error {
	if err := validate.NoControlChars(s.cfg.TunnelIP); err != nil {
		return fmt.Errorf("server config TunnelIP: %w", err)
	}
	if err := validate.NoControlChars(s.privateKey); err != nil {
		return fmt.Errorf("server private key: %w", err)
	}
	for _, p := range s.peers {
		if err := validate.NoControlChars(p.Name); err != nil {
			return fmt.Errorf("peer Name: %w", err)
		}
		if err := validate.NoControlChars(p.PublicKey); err != nil {
			return fmt.Errorf("peer PublicKey: %w", err)
		}
		if err := validate.NoControlChars(p.PresharedKey); err != nil {
			return fmt.Errorf("peer PresharedKey: %w", err)
		}
		if err := validate.NoControlChars(p.TunnelIP); err != nil {
			return fmt.Errorf("peer TunnelIP: %w", err)
		}
		for _, a := range p.AllowedIPs {
			if err := validate.NoControlChars(a); err != nil {
				return fmt.Errorf("peer AllowedIPs: %w", err)
			}
		}
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s/24\n", s.cfg.TunnelIP))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", s.cfg.ListenPort))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", s.privateKey))
	if s.cfg.MTU > 0 {
		b.WriteString(fmt.Sprintf("MTU = %d\n", s.cfg.MTU))
	}
	b.WriteString("\n")

	for _, p := range s.peers {
		b.WriteString("[Peer]\n")
		if p.Name != "" {
			b.WriteString(fmt.Sprintf("# %s\n", p.Name))
		}
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", p.PublicKey))
		if p.PresharedKey != "" {
			b.WriteString(fmt.Sprintf("PresharedKey = %s\n", p.PresharedKey))
		}
		allowed := append([]string{p.TunnelIP + "/32"}, p.AllowedIPs...)
		b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(allowed, ", ")))
		b.WriteString("\n")
	}

	return os.WriteFile(confPath(s.cfg.Interface), []byte(b.String()), 0600)
}

// --- helpers ---

func loadOrGenPrivateKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("read private key: %w", err)
	}
	out, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", fmt.Errorf("wg genkey: %w", err)
	}
	key := strings.TrimSpace(string(out))
	if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
		return "", fmt.Errorf("save private key: %w", err)
	}
	return key, nil
}

func derivePubKey(privateKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg pubkey: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func interfaceExists(iface string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", iface))
	return err == nil
}

func wgQuickUp(iface string) error {
	out, err := exec.Command("wg-quick", "up", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up %s: %w — %s", iface, err, out)
	}
	return nil
}

func wgQuickDown(iface string) error {
	out, err := exec.Command("wg-quick", "down", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick down %s: %w — %s", iface, err, out)
	}
	return nil
}

func wgSyncConf(iface, cPath string) error {
	stripped, err := exec.Command("wg-quick", "strip", iface).Output()
	if err != nil {
		out, err2 := exec.Command("wg", "syncconf", iface, cPath).CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("wg syncconf %s: %w — %s", iface, err2, out)
		}
		return nil
	}
	tmpFile := cPath + ".strip"
	if err := os.WriteFile(tmpFile, stripped, 0600); err != nil {
		return fmt.Errorf("write stripped config: %w", err)
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("wg", "syncconf", iface, tmpFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg syncconf %s: %w — %s", iface, err, out)
	}
	return nil
}

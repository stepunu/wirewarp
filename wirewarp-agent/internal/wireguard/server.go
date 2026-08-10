package wireguard

import (
	"fmt"
	"net/netip"
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
	Name         string
	PublicKey    string
	PresharedKey string   // optional: emitted as PresharedKey when set
	TunnelIP     string   // assigned tunnel IP for this peer
	AllowedIPs   []string // subnets to route through this peer
}

// Server manages the WireGuard server-side interface on a VPS.
type Server struct {
	cfg               ServerConfig
	privateKey        string
	PublicKey         string
	peers             map[string]Peer // keyed by public key
	startupPeerRoutes []string
	peerConfigWriter  func(map[string]Peer) error
	peerConfigSyncer  func() error
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
	startupPeerRoutes, err := loadStartupPeerRoutes(confPath(cfg.Interface))
	if err != nil {
		return nil, fmt.Errorf("read existing peer routes: %w", err)
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
		cfg:               cfg,
		privateKey:        privateKey,
		PublicKey:         publicKey,
		peers:             make(map[string]Peer),
		startupPeerRoutes: startupPeerRoutes,
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
	next := clonePeers(s.peers)
	next[p.PublicKey] = p
	return s.commitPeers(next)
}

// RoutesToRemoveBeforePeerUpdate returns routes owned by the current version
// of p that the replacement no longer needs. Routes used by another peer are
// retained. Callers remove these routes before AddPeer so a failed sync cannot
// leave an obsolete LAN route active.
func (s *Server) RoutesToRemoveBeforePeerUpdate(p Peer) []string {
	current, ok := s.peers[p.PublicKey]
	if !ok {
		return nil
	}

	peersAfterUpdate := make(map[string]Peer, len(s.peers))
	for publicKey, peer := range s.peers {
		peersAfterUpdate[publicKey] = peer
	}
	peersAfterUpdate[p.PublicKey] = p
	return unusedPeerRoutes(current, peersAfterUpdate)
}

// RemovePeer removes a peer by public key and syncs the config.
func (s *Server) RemovePeer(publicKey string) error {
	if _, ok := s.peers[publicKey]; !ok {
		return fmt.Errorf("peer not found: %s", publicKey)
	}
	next := clonePeers(s.peers)
	delete(next, publicKey)
	return s.commitPeers(next)
}

// RoutesToRemoveBeforePeerRemoval returns routes owned by the peer that no
// remaining peer needs. The peer set is not changed.
func (s *Server) RoutesToRemoveBeforePeerRemoval(publicKey string) ([]string, error) {
	peer, ok := s.peers[publicKey]
	if !ok {
		return nil, fmt.Errorf("peer not found: %s", publicKey)
	}

	peersAfterRemoval := make(map[string]Peer, len(s.peers)-1)
	for candidateKey, candidate := range s.peers {
		if candidateKey != publicKey {
			peersAfterRemoval[candidateKey] = candidate
		}
	}
	return unusedPeerRoutes(peer, peersAfterRemoval), nil
}

// Down tears down the WireGuard interface.
func (s *Server) Down() error {
	return wgQuickDown(s.cfg.Interface)
}

func (s *Server) writeConfig() error {
	return s.writeConfigForPeers(s.peers)
}

func (s *Server) writeConfigForPeers(peers map[string]Peer) error {
	if err := validate.NoControlChars(s.cfg.TunnelIP); err != nil {
		return fmt.Errorf("server config TunnelIP: %w", err)
	}
	if err := validate.NoControlChars(s.privateKey); err != nil {
		return fmt.Errorf("server private key: %w", err)
	}
	for _, p := range peers {
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

	for _, p := range peers {
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

	return writeFileAtomic(confPath(s.cfg.Interface), []byte(b.String()), 0600)
}

func (s *Server) commitPeers(next map[string]Peer) error {
	if err := s.writePeerConfig(next); err != nil {
		return err
	}
	if err := s.syncPeerConfig(); err != nil {
		rollbackWriteErr := s.writePeerConfig(s.peers)
		var rollbackSyncErr error
		if rollbackWriteErr == nil {
			rollbackSyncErr = s.syncPeerConfig()
		}
		if rollbackWriteErr != nil || rollbackSyncErr != nil {
			return fmt.Errorf(
				"sync peer config: %w; rollback write: %v; rollback sync: %v",
				err, rollbackWriteErr, rollbackSyncErr,
			)
		}
		return fmt.Errorf("sync peer config: %w; previous peer config restored", err)
	}
	s.peers = next
	return nil
}

func (s *Server) writePeerConfig(peers map[string]Peer) error {
	if s.peerConfigWriter != nil {
		return s.peerConfigWriter(peers)
	}
	return s.writeConfigForPeers(peers)
}

func (s *Server) syncPeerConfig() error {
	if s.peerConfigSyncer != nil {
		return s.peerConfigSyncer()
	}
	return wgSyncConf(s.cfg.Interface, confPath(s.cfg.Interface))
}

func clonePeers(peers map[string]Peer) map[string]Peer {
	cloned := make(map[string]Peer, len(peers))
	for publicKey, peer := range peers {
		peer.AllowedIPs = append([]string(nil), peer.AllowedIPs...)
		cloned[publicKey] = peer
	}
	return cloned
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".wirewarp-config-*")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	defer os.Remove(tmpPath)
	if err := file.Chmod(perm); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func unusedPeerRoutes(previous Peer, peersAfterChange map[string]Peer) []string {
	var unused []string
	seen := make(map[string]struct{})
	previousTunnelIP := canonicalAllowedIP(previous.TunnelIP + "/32")
	for _, route := range previous.AllowedIPs {
		canonicalRoute := canonicalAllowedIP(route)
		if canonicalRoute == previousTunnelIP {
			continue
		}
		if _, duplicate := seen[canonicalRoute]; duplicate {
			continue
		}
		seen[canonicalRoute] = struct{}{}
		if peerRouteRequired(canonicalRoute, peersAfterChange) {
			continue
		}
		unused = append(unused, route)
	}
	return unused
}

func peerRouteRequired(canonicalRoute string, peers map[string]Peer) bool {
	for _, peer := range peers {
		peerTunnelIP := canonicalAllowedIP(peer.TunnelIP + "/32")
		for _, route := range peer.AllowedIPs {
			candidate := canonicalAllowedIP(route)
			if candidate != peerTunnelIP && candidate == canonicalRoute {
				return true
			}
		}
	}
	return false
}

func canonicalAllowedIP(value string) string {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked().String()
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.String()
	}
	return value
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

package wireguard

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/wirewarp/agent/internal/validate"
)

// PruneStalePeerRoutes removes routes owned by peers from the pre-restart
// WireGuard config. Routes inside the server tunnel network are retained.
func (s *Server) PruneStalePeerRoutes() error {
	return PruneStalePeerRoutes(s.startupPeerRoutes, s.cfg.Interface, s.cfg.TunnelNetwork)
}

// PruneStalePeerRoutes removes known peer-owned routes from one managed
// WireGuard interface. The caller supplies ownership data from the old config.
func PruneStalePeerRoutes(routes []string, iface, tunnelNetwork string) error {
	tunnel, err := parseIPv4Route(tunnelNetwork)
	if err != nil {
		return fmt.Errorf("tunnel network: %w", err)
	}
	var stale []string
	seen := make(map[string]struct{})
	for _, route := range routes {
		prefix, err := parseIPv4Route(route)
		if err != nil {
			return err
		}
		if prefix.Bits() >= tunnel.Bits() && tunnel.Contains(prefix.Addr()) {
			continue
		}
		destination := prefix.Masked().String()
		if _, duplicate := seen[destination]; duplicate {
			continue
		}
		seen[destination] = struct{}{}
		stale = append(stale, destination)
	}
	return RemovePeerRoutes(stale, iface)
}

// RemovePeerRoutes deletes exact routes from one managed WireGuard interface.
// Missing routes are already reconciled. All candidates are attempted before
// the first unexpected error is returned.
func RemovePeerRoutes(routes []string, iface string) error {
	if err := validate.Interface(iface); err != nil {
		return err
	}
	var firstErr error
	for _, subnet := range routes {
		cmd := exec.Command("ip", "route", "del", subnet, "dev", iface)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.CombinedOutput()
		if err == nil {
			log.Printf("[server] removed route %s dev %s", subnet, iface)
			continue
		}
		message := strings.TrimSpace(string(out))
		if strings.Contains(message, "No such process") ||
			strings.Contains(message, "Cannot find device") ||
			strings.Contains(message, "does not exist") {
			continue
		}
		log.Printf("[server] WARN: ip route del %s dev %s: %s", subnet, iface, message)
		if firstErr == nil {
			firstErr = fmt.Errorf("ip route del %s dev %s: %w: %s", subnet, iface, err, message)
		}
	}
	return firstErr
}

// AddPeerAndRoutes applies a peer update and its kernel routes as one
// retry-safe operation. A later route failure restores the prior peer and
// route state before it returns.
func (s *Server) AddPeerAndRoutes(peer Peer, iface string) error {
	oldPeer, hadOldPeer := s.peers[peer.PublicKey]
	oldRoutes := s.RoutesToRemoveBeforePeerUpdate(peer)
	if err := RemovePeerRoutes(oldRoutes, iface); err != nil {
		return peerMutationError(err, restorePeerRoutes(oldRoutes, iface))
	}
	if err := s.AddPeer(peer); err != nil {
		return peerMutationError(err, restorePeerRoutes(oldRoutes, iface))
	}

	for _, subnet := range peer.AllowedIPs {
		if subnet == peer.TunnelIP+"/32" {
			continue
		}
		if err := EnsurePeerRoute(subnet, iface); err != nil {
			rollbackErr := s.rollbackPeerUpdate(peer, oldPeer, hadOldPeer, oldRoutes, iface)
			return peerMutationError(err, rollbackErr)
		}
	}
	return nil
}

// RemovePeerAndRoutes removes a peer and routes that no remaining peer uses.
// A peer write or sync failure restores routes for the still-active peer.
func (s *Server) RemovePeerAndRoutes(publicKey, iface string) error {
	routes, err := s.RoutesToRemoveBeforePeerRemoval(publicKey)
	if err != nil {
		return err
	}
	if err := RemovePeerRoutes(routes, iface); err != nil {
		return peerMutationError(err, restorePeerRoutes(routes, iface))
	}
	if err := s.RemovePeer(publicKey); err != nil {
		return peerMutationError(err, restorePeerRoutes(routes, iface))
	}
	return nil
}

func (s *Server) rollbackPeerUpdate(peer, oldPeer Peer, hadOldPeer bool, oldRoutes []string, iface string) error {
	var newRoutes []string
	var err error
	if hadOldPeer {
		newRoutes = s.RoutesToRemoveBeforePeerUpdate(oldPeer)
		err = s.AddPeer(oldPeer)
	} else {
		newRoutes, err = s.RoutesToRemoveBeforePeerRemoval(peer.PublicKey)
		if err == nil {
			err = s.RemovePeer(peer.PublicKey)
		}
	}
	if err != nil {
		return fmt.Errorf("restore peer config: %w", err)
	}

	var failures []string
	if err := RemovePeerRoutes(newRoutes, iface); err != nil {
		failures = append(failures, err.Error())
	}
	if err := restorePeerRoutes(oldRoutes, iface); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func restorePeerRoutes(routes []string, iface string) error {
	var failures []string
	for _, route := range routes {
		if err := EnsurePeerRoute(route, iface); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func peerMutationError(originalErr, rollbackErr error) error {
	if rollbackErr != nil {
		return fmt.Errorf("%w; rollback failed: %v", originalErr, rollbackErr)
	}
	return fmt.Errorf("%w; previous peer route state restored", originalErr)
}

// EnsurePeerRoute adds one kernel route. A route that already exists is the
// desired state and is treated as success.
func EnsurePeerRoute(subnet, iface string) error {
	out, err := exec.Command("ip", "route", "add", subnet, "dev", iface).CombinedOutput()
	if err != nil {
		if !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("ip route add %s dev %s: %w: %s", subnet, iface, err, out)
		}
	} else {
		log.Printf("[server] added route %s dev %s", subnet, iface)
	}
	return nil
}

func loadStartupPeerRoutes(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseStartupPeerRoutes(string(data))
}

func parseStartupPeerRoutes(config string) ([]string, error) {
	inPeer := false
	var routes []string
	seen := make(map[string]struct{})
	for _, rawLine := range strings.Split(config, "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inPeer = strings.EqualFold(line, "[Peer]")
			continue
		}
		if !inPeer {
			continue
		}
		keyValue := strings.SplitN(line, "=", 2)
		if len(keyValue) != 2 || !strings.EqualFold(strings.TrimSpace(keyValue[0]), "AllowedIPs") {
			continue
		}
		for _, value := range strings.Split(keyValue[1], ",") {
			prefix, err := parseIPv4Route(value)
			if err != nil {
				return nil, fmt.Errorf("invalid peer AllowedIP %q: %w", strings.TrimSpace(value), err)
			}
			destination := prefix.Masked().String()
			if _, duplicate := seen[destination]; duplicate {
				continue
			}
			seen[destination] = struct{}{}
			routes = append(routes, destination)
		}
	}
	return routes, nil
}

func parseIPv4Route(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() {
		return prefix.Masked(), nil
	}
	if address, err := netip.ParseAddr(value); err == nil && address.Is4() {
		return netip.PrefixFrom(address, 32), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid IPv4 route %q", value)
}

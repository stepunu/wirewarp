package websocket

import (
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
)

// VpnPeerStat is the heartbeat-payload shape the control server expects.
// Mirrors what `wg show <iface> dump` exposes per peer; we strip the
// fields we don't want to surface and rename for json clarity.
type VpnPeerStat struct {
	Interface       string `json:"interface"`
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint,omitempty"`
	AllowedIPs      string `json:"allowed_ips,omitempty"`
	LastHandshake   int64  `json:"last_handshake_unix"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
	PersistKeepalive int    `json:"persistent_keepalive,omitempty"`
}

// vpnInterfacesFn is the live-interface provider injected by main.go via
// SetVpnInterfacesProvider. Stored as an atomic.Value so reads from the
// heartbeat goroutine don't race with the (one-time) write in main.
var vpnInterfacesFn atomic.Value // func() []string

// meshInterfacesFn is the tunnel-mesh-interface provider — the server
// agent's wg0 + every client attachment's wgN. Same pattern as
// vpnInterfacesFn but feeds the second collection path.
var meshInterfacesFn atomic.Value // func() []string

// SetVpnInterfacesProvider lets main.go publish a callable that returns
// the names of every WG VPN interface currently up on this agent.
func SetVpnInterfacesProvider(_ *Client, fn func() []string) {
	vpnInterfacesFn.Store(fn)
}

// SetMeshInterfacesProvider publishes the tunnel-mesh interface
// enumerator. On a server agent this returns `[wg0]`; on a gateway
// client it returns the WG interface for every active attachment.
func SetMeshInterfacesProvider(_ *Client, fn func() []string) {
	meshInterfacesFn.Store(fn)
}

// collectVpnPeerStats runs `wg show <iface> dump` for each live VPN
// interface and parses the per-peer rows. Used by the heartbeat to feed
// the dashboard's "last handshake" column. Errors are silently swallowed
// — a transient `wg` failure shouldn't break the heartbeat.
func collectVpnPeerStats() []VpnPeerStat {
	return collectPeerStats(vpnInterfacesFn)
}

// collectMeshPeerStats does the same for tunnel-mesh interfaces.
func collectMeshPeerStats() []VpnPeerStat {
	return collectPeerStats(meshInterfacesFn)
}

func collectPeerStats(provider atomic.Value) []VpnPeerStat {
	fnAny := provider.Load()
	if fnAny == nil {
		return nil
	}
	fn, ok := fnAny.(func() []string)
	if !ok || fn == nil {
		return nil
	}
	out := []VpnPeerStat{}
	for _, iface := range fn() {
		stats := parseWgDump(iface)
		out = append(out, stats...)
	}
	return out
}

func parseWgDump(iface string) []VpnPeerStat {
	out, err := exec.Command("wg", "show", iface, "dump").Output()
	if err != nil {
		return nil
	}
	var peers []VpnPeerStat
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 {
			// First row is the interface itself: private_key, public_key,
			// listen_port, fwmark. Skip — we surface the endpoint pubkey
			// out-of-band via vpn_endpoint_up's response.
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		// Per `wg show <iface> dump` (peer rows, tab-separated):
		//   public_key, preshared_key, endpoint, allowed_ips,
		//   latest_handshake, rx_bytes, tx_bytes, persistent_keepalive
		peer := VpnPeerStat{
			Interface:  iface,
			PublicKey:  fields[0],
			Endpoint:   strOrEmpty(fields[2]),
			AllowedIPs: strOrEmpty(fields[3]),
		}
		peer.LastHandshake = atoi64(fields[4])
		peer.RxBytes = atoi64(fields[5])
		peer.TxBytes = atoi64(fields[6])
		if len(fields) >= 8 {
			peer.PersistKeepalive = atoi(fields[7])
		}
		peers = append(peers, peer)
	}
	return peers
}

func strOrEmpty(s string) string {
	if s == "(none)" || s == "" {
		return ""
	}
	return s
}

func atoi64(s string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return v
}

func atoi(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}

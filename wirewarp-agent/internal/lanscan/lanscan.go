// Package lanscan discovers LAN hosts that are using the gateway as their
// egress router by walking the conntrack table and the kernel ARP cache.
//
// A "LAN egress flow" is one whose request-side src is in the gateway's LAN
// subnet and dst is outside. Any such flow on the gateway means a LAN host
// chose the gateway as its route for that destination — the very signal we
// want to surface in the dashboard.
//
// We try /proc/net/nf_conntrack first (zero-cost read), but on kernels
// built without CONFIG_NF_CONNTRACK_PROCFS that file is empty/missing —
// fall back to `conntrack -L` (netlink-based). Either way, the line format
// is identical: "<proto> <num> <ttl> <STATE> src=A dst=B sport=... ...".
package lanscan

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

// LanClient is one observed LAN host.
type LanClient struct {
	LANIP       string `json:"lan_ip"`
	MAC         string `json:"mac,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	BytesRecent int64  `json:"bytes_recent"`
}

// Scrape returns one entry per distinct LAN host that has at least one
// conntrack flow whose request-side src is in lanCIDR and dst is a PUBLIC
// (internet-routable) IPv4. Excludes the gateway's own LAN IP and any
// RFC1918/CGNAT/loopback/multicast/link-local destinations — those are
// intra-tunnel or LAN-internal traffic, not real egress through the
// gateway. Returns nil on any read error.
func Scrape(lanCIDR string, gatewayLanIP string) []LanClient {
	_, lanNet, err := net.ParseCIDR(lanCIDR)
	if err != nil {
		return nil
	}

	flows := readConntrack()
	if flows == nil {
		return nil
	}

	gwIP := net.ParseIP(gatewayLanIP)
	seen := make(map[string]struct{})
	for _, f := range flows {
		src := net.ParseIP(f.src)
		dst := net.ParseIP(f.dst)
		if src == nil || dst == nil {
			continue
		}
		if !lanNet.Contains(src) {
			continue
		}
		if !isPublicIPv4(dst) {
			continue // intra-LAN, intra-tunnel, or otherwise non-public — not real egress
		}
		if gwIP != nil && src.Equal(gwIP) {
			continue // gateway's own outbound
		}
		seen[src.String()] = struct{}{}
	}

	if len(seen) == 0 {
		return nil
	}
	arp := readARP()
	out := make([]LanClient, 0, len(seen))
	for ip := range seen {
		out = append(out, LanClient{LANIP: ip, MAC: arp[ip]})
	}
	return out
}

// isPublicIPv4 returns true if the address is internet-routable: not in
// any private (RFC1918), CGNAT (RFC6598), loopback, link-local, or
// multicast range. IPv6 returns false (caller is IPv4-only for now).
func isPublicIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() || v4.IsMulticast() {
		return false
	}
	// 100.64.0.0/10 — CGNAT, used by ISPs and some VPN tunnels.
	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	// 0.0.0.0/8 — "this network", invalid as dst.
	if v4[0] == 0 {
		return false
	}
	return true
}

type flowTuple struct {
	src string
	dst string
}

// readConntrack returns request-side (src, dst) for every active flow.
// Tries /proc/net/nf_conntrack first; on kernels with CONFIG_NF_CONNTRACK_PROCFS
// disabled the file is empty/missing, so we fall back to `conntrack -L`.
func readConntrack() []flowTuple {
	if rows := parseConntrackReader(openProc()); len(rows) > 0 {
		return rows
	}
	out, err := exec.Command("conntrack", "-L").Output()
	if err != nil {
		return nil
	}
	return parseConntrackReader(bytes.NewReader(out))
}

func openProc() io.Reader {
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return bytes.NewReader(nil)
	}
	// Best-effort: caller doesn't close, but the file descriptor is reaped
	// when this process's gc collects the os.File. We're leaking briefly,
	// not at scale (called every 30s heartbeat). For correctness use a
	// helper that closes; here we read everything into memory.
	defer f.Close()
	all, _ := io.ReadAll(f)
	return bytes.NewReader(all)
}

func parseConntrackReader(r io.Reader) []flowTuple {
	var out []flowTuple
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		// First "src=..." and "dst=..." in the line are the request side;
		// the second pair is the reply side. Stop at the first dst=.
		// `bytes`-based parsing keeps us off the regex hot path.
		var src, dst string
		idx := indexOf(line, []byte("src="))
		if idx < 0 {
			continue
		}
		end := idx + 4
		for end < len(line) && line[end] != ' ' {
			end++
		}
		src = string(line[idx+4 : end])
		idx = indexOfAfter(line, []byte("dst="), end)
		if idx < 0 {
			continue
		}
		end = idx + 4
		for end < len(line) && line[end] != ' ' {
			end++
		}
		dst = string(line[idx+4 : end])
		out = append(out, flowTuple{src: src, dst: dst})
	}
	return out
}

// readARP reads /proc/net/arp and returns IP→MAC. Stale (incomplete) entries
// are skipped. Best-effort: a missing entry just means we don't know the MAC.
func readARP() map[string]string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return map[string]string{}
	}
	defer f.Close()
	arp := make(map[string]string)
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(sc.Text())
		// IP address | HW type | Flags | HW address | Mask | Device
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		arp[ip] = mac
	}
	return arp
}

func indexOf(b, sub []byte) int {
	for i := 0; i <= len(b)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func indexOfAfter(b, sub []byte, start int) int {
	if start >= len(b) {
		return -1
	}
	rel := indexOf(b[start:], sub)
	if rel < 0 {
		return -1
	}
	return start + rel
}

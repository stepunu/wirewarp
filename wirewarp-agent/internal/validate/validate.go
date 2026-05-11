// Package validate provides input validators for fields that arrive over the
// control-server WebSocket and flow into wg-quick configs, iptables rules,
// `ip` invocations, or filesystem paths.
//
// Every exported validator returns nil on accept, error on reject. The
// returned error is suitable for surfacing as a command-result `output` value.
package validate

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	// wg-quick interface names emitted by the control server are wg0, wg1, …
	// or wg-vpn0, wg-vpn1, … (no other shapes are produced).
	reInterface = regexp.MustCompile(`^wg(-vpn)?[0-9]+$`)

	// Host network interface names. Linux IFNAMSIZ caps at 16 incl. NUL → 15.
	rePublicIface = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)

	// DNS hostname per RFC 1123 (labels of [A-Za-z0-9-], no leading/trailing -,
	// total length ≤ 253). The endpoint validator also accepts a bare IPv4.
	reHostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
)

// NoControlChars rejects strings containing \n, \r, or NUL. Used as a
// last-line defense for any field that ends up on its own line in a wg-quick
// config, iptables rule, or `ip` argument.
func NoControlChars(s string) error {
	if strings.ContainsAny(s, "\n\r\x00") {
		return fmt.Errorf("validate: contains control character")
	}
	return nil
}

// Interface validates a wg-quick interface name used as the basename of
// /etc/wireguard/<iface>.conf and .key.
func Interface(s string) error {
	if !reInterface.MatchString(s) {
		return fmt.Errorf("validate: interface %q: must match %s", s, reInterface)
	}
	return nil
}

// PublicIface validates a host network interface name (eth0, ens18, …).
func PublicIface(s string) error {
	if !rePublicIface.MatchString(s) {
		return fmt.Errorf("validate: public iface %q: bad shape", s)
	}
	return nil
}

// IPv4 accepts a bare IPv4 address.
func IPv4(s string) error {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("validate: not an IPv4 address: %q", s)
	}
	return nil
}

// IPv4CIDR accepts an IPv4 network in CIDR notation, e.g. 10.21.0.0/24.
func IPv4CIDR(s string) error {
	ip, _, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("validate: not an IPv4 CIDR: %q", s)
	}
	return nil
}

// IPv4OrCIDR accepts either an IPv4 address or an IPv4 CIDR.
func IPv4OrCIDR(s string) error {
	if IPv4(s) == nil {
		return nil
	}
	if IPv4CIDR(s) == nil {
		return nil
	}
	return fmt.Errorf("validate: not an IPv4 address or CIDR: %q", s)
}

// Endpoint accepts host:port where host is an IPv4 or a DNS hostname.
func Endpoint(s string) error {
	if err := NoControlChars(s); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("validate: endpoint %q: %v", s, err)
	}
	if host == "" {
		return fmt.Errorf("validate: endpoint %q: empty host", s)
	}
	if IPv4(host) != nil && !reHostname.MatchString(host) {
		return fmt.Errorf("validate: endpoint %q: bad host", s)
	}
	if len(host) > 253 {
		return fmt.Errorf("validate: endpoint %q: host too long", s)
	}
	// SplitHostPort already verifies port is numeric; range-check it.
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("validate: endpoint %q: bad port", s)
	}
	return nil
}

// WGKey accepts a base64-encoded 32-byte WireGuard key (44 chars incl. '=').
func WGKey(s string) error {
	if len(s) != 44 {
		return fmt.Errorf("validate: wg key %q: length %d, want 44", s, len(s))
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("validate: wg key: %v", err)
	}
	if len(dec) != 32 {
		return fmt.Errorf("validate: wg key: decoded length %d, want 32", len(dec))
	}
	return nil
}

// WGKeyOpt accepts empty or a valid wg key.
func WGKeyOpt(s string) error {
	if s == "" {
		return nil
	}
	return WGKey(s)
}

// Port validates a 1..65535 TCP/UDP port.
func Port(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("validate: port %d out of range", p)
	}
	return nil
}

// PeerName accepts an opaque human-readable label, with length and
// control-character limits. Empty is allowed.
func PeerName(s string) error {
	if len(s) > 128 {
		return fmt.Errorf("validate: peer name too long")
	}
	return NoControlChars(s)
}

// ControlServerURL accepts https:// URLs with a non-empty host. When
// allowHTTP is true, plain http:// is also accepted — used for homelab /
// bootstrap deployments where TLS termination (Traefik etc.) isn't up yet.
// The default (allowHTTP=false) stays strict because the WS channel carries
// the registration token and root-level command stream; the relaxed mode is
// strictly opt-in via the agent's --insecure flag and is persisted in
// agent.yaml so reconnects don't silently re-trip the check.
func ControlServerURL(s string, allowHTTP bool) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("validate: control-server URL: %v", err)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
	case u.Scheme == "http":
		return fmt.Errorf("validate: control-server URL must use https:// (got http://) — pass --insecure to opt in to plaintext (homelab/bootstrap only)")
	default:
		return fmt.Errorf("validate: control-server URL must use https:// (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("validate: control-server URL: empty host")
	}
	return nil
}

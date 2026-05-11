package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	"github.com/wirewarp/agent/internal/lanscan"
	"github.com/wirewarp/agent/internal/validate"
)

const (
	heartbeatInterval = 30 * time.Second
	// watcherInterval drives event-driven heartbeats: every tick the agent
	// re-enumerates IPs + LAN clients, diffs against the last *sent* state,
	// and pushes a fresh heartbeat immediately if anything changed. The 30s
	// heartbeat ticker stays as a backstop for missed pushes (or for cases
	// where bytes_recent counters drift but the watcher's identity-only diff
	// hasn't fired). 2s is the sweet spot — fast enough that a new IP shows
	// up on the dashboard within a tick, cheap enough that scraping
	// /proc/net/nf_conntrack at this rate is unmeasurable on a quiet box.
	watcherInterval = 2 * time.Second
	maxBackoff      = 60 * time.Second
	initialBackoff  = 1 * time.Second
)

type Client struct {
	cfg      *config.Config
	cfgPath  string
	exec     *executor.Executor
	sendFn   func(v any) error
	hostname string
	version  string
}

func New(cfg *config.Config, cfgPath string, version string) *Client {
	hostname, _ := os.Hostname()
	c := &Client{cfg: cfg, cfgPath: cfgPath, hostname: hostname, version: version}
	// Create executor with a send function that routes through the current connection
	c.exec = executor.New(func(result executor.Result) error {
		if c.sendFn == nil {
			return fmt.Errorf("not connected")
		}
		return c.sendFn(result)
	})
	return c
}

// Exec returns the executor so callers can register real handlers.
func (c *Client) Exec() *executor.Executor {
	return c.exec
}

// Run connects and reconnects forever with exponential backoff.
func (c *Client) Run(ctx context.Context) {
	backoff := initialBackoff
	for {
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("[ws] disconnected: %v — retrying in %s", err, backoff)
		}
		// No credentials at all — no point hammering the server.
		if c.cfg.AgentJWT == "" && c.cfg.AgentToken == "" {
			log.Printf("[ws] no valid credentials — reissue a JWT from the dashboard, then update agent_jwt in /etc/wirewarp/agent.yaml and restart the service")
			backoff = 5 * time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(backoff)):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (c *Client) connect(ctx context.Context) error {
	if err := validate.ControlServerURL(c.cfg.ControlServerURL, c.cfg.Insecure); err != nil {
		return err
	}
	conn, _, err := websocket.Dial(ctx, c.cfg.ControlServerURL+"/ws/agent", nil)
	if err != nil {
		return err
	}
	defer conn.CloseNow()

	send := func(v any) error {
		return wsjson.Write(ctx, conn, v)
	}
	c.sendFn = send
	defer func() { c.sendFn = nil }()

	if c.cfg.AgentJWT != "" {
		if err := send(map[string]string{"type": "auth", "jwt": c.cfg.AgentJWT}); err != nil {
			return err
		}
		var resp map[string]string
		if err := wsjson.Read(ctx, conn, &resp); err != nil {
			return err
		}
		if resp["type"] != "authenticated" {
			// JWT expired — clear it and re-register on the next attempt
			c.cfg.AgentJWT = ""
			_ = c.cfg.Save(c.cfgPath)
			return fmt.Errorf("auth rejected: %s", resp["message"])
		}
		log.Printf("[ws] authenticated as agent %s", c.cfg.AgentID)
	} else {
		if err := send(map[string]string{
			"type":       "register",
			"token":      c.cfg.AgentToken,
			"hostname":   c.hostname,
			"agent_type": c.cfg.Mode,
		}); err != nil {
			return err
		}
		var resp map[string]string
		if err := wsjson.Read(ctx, conn, &resp); err != nil {
			return err
		}
		if resp["type"] != "registered" {
			return fmt.Errorf("registration failed: %s", resp["message"])
		}
		c.cfg.AgentID = resp["agent_id"]
		c.cfg.AgentJWT = resp["jwt"]
		c.cfg.AgentToken = ""
		if err := c.cfg.Save(c.cfgPath); err != nil {
			log.Printf("[ws] warning: failed to save config: %v", err)
		}
		log.Printf("[ws] registered as agent %s", c.cfg.AgentID)
	}

	// Discover the canonical agent.public_ip once per connection via icanhazip
	// (works behind NAT). Local-interface enumeration runs on every heartbeat
	// so IPs added to the VPS while the agent is running are picked up within
	// ~30s without requiring a reconnect.
	publicIP := fetchPublicIP()
	if publicIP == "" {
		// No NAT-discovered IP — fall back to the first locally-bound public IP.
		if local := enumerateLocalPublicIPs(); len(local) > 0 {
			publicIP = local[0]
		}
	}

	heartbeat := func() map[string]any {
		h := map[string]any{
			"type":      "heartbeat",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   c.version,
		}
		if publicIP != "" {
			h["public_ip"] = publicIP
		}
		// Re-enumerate every heartbeat so newly-added IPs auto-register without
		// a reconnect. Cheap: just reads the kernel's interface table.
		if allIPs := mergeIPSets(publicIP, enumerateLocalPublicIPs()); len(allIPs) > 0 {
			h["public_ips"] = allIPs
		}
		// On gateway clients, scrape conntrack + ARP to find LAN hosts
		// using us as their egress route. Always include the field (even
		// if empty) so the server can run its TTL sweep — rows whose
		// last_seen ages past the cutoff get evicted, and the heartbeat
		// is the natural pacemaker for that.
		if lanCIDR, gwLANIP := gatewayLANInfo(c.cfg); lanCIDR != "" {
			hosts := lanscan.Scrape(lanCIDR, gwLANIP)
			if hosts == nil {
				hosts = []lanscan.LanClient{}
			}
			h["lan_clients"] = hosts
		}
		// On agents hosting a road-warrior VPN endpoint, scrape
		// `wg show <iface> dump` per peer so the dashboard can show
		// last-handshake / rx / tx. Empty slice when no endpoints.
		if peers := collectVpnPeerStats(); peers != nil {
			h["vpn_peers"] = peers
		}
		return h
	}

	// Send an initial heartbeat right away so public_ip is stored without waiting 30s.
	initial := heartbeat()
	if err := send(initial); err != nil {
		return err
	}
	lastIPs := extractIPs(initial)
	lastLAN := extractLANIDs(initial)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	watcher := time.NewTicker(watcherInterval)
	defer watcher.Stop()

	recvErr := make(chan error, 1)
	go func() {
		for {
			var raw json.RawMessage
			if err := wsjson.Read(ctx, conn, &raw); err != nil {
				recvErr <- err
				return
			}
			var cmd executor.Command
			if err := json.Unmarshal(raw, &cmd); err != nil {
				log.Printf("[ws] failed to unmarshal command: %v", err)
				continue
			}
			c.exec.Dispatch(cmd)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "shutting down")
			return nil
		case err := <-recvErr:
			return err
		case <-ticker.C:
			h := heartbeat()
			if err := send(h); err != nil {
				return err
			}
			lastIPs = extractIPs(h)
			lastLAN = extractLANIDs(h)
		case <-watcher.C:
			h := heartbeat()
			ips := extractIPs(h)
			lan := extractLANIDs(h)
			if !equalSorted(ips, lastIPs) || !equalSorted(lan, lastLAN) {
				if err := send(h); err != nil {
					return err
				}
				lastIPs = ips
				lastLAN = lan
			}
		}
	}
}

// extractIPs reads `public_ips` out of a heartbeat for diff comparison.
// Returns a sorted copy so equalSorted() works.
func extractIPs(h map[string]any) []string {
	v, _ := h["public_ips"].([]string)
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}

// extractLANIDs returns a sorted slice of "lan_ip|mac|hostname" identity
// keys from a heartbeat. Excludes bytes_recent on purpose — that counter
// changes on every scan, so diffing on it would defeat the watcher's
// "only push on change" goal. The 30s heartbeat backstop covers
// bytes_recent updates.
func extractLANIDs(h map[string]any) []string {
	v, _ := h["lan_clients"].([]lanscan.LanClient)
	out := make([]string, 0, len(v))
	for _, lc := range v {
		out = append(out, lc.LANIP+"|"+lc.MAC+"|"+lc.Hostname)
	}
	sort.Strings(out)
	return out
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}


// fetchPublicIP returns the machine's public IPv4 address.
// Returns empty string on failure — non-fatal, agent still connects.
func fetchPublicIP() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ipv4.icanhazip.com", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
}

// enumerateLocalPublicIPs returns every routable IPv4 address bound to a
// non-loopback interface on this machine. Filters out RFC1918 private
// (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10), link-local, and loopback.
// Used so the control server can register every IP a multi-homed VPS holds.
func enumerateLocalPublicIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []string
	seen := map[string]bool{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() {
				continue
			}
			// 100.64.0.0/10 — CGNAT
			if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
				continue
			}
			s := v4.String()
			if !seen[s] {
				seen[s] = true
				ips = append(ips, s)
			}
		}
	}
	return ips
}

// mergeIPSets combines a single string and a slice into a deduplicated slice,
// preserving the single string's leading position so it stays the canonical
// agent.public_ip.
func mergeIPSets(primary string, others []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(others)+1)
	if primary != "" {
		seen[primary] = true
		out = append(out, primary)
	}
	for _, ip := range others {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// gatewayLANInfo returns (LANNetwork, LANIP) for the first gateway-mode
// attachment, or ("", "") if this agent is not a gateway. All gateway
// attachments share the same LAN since they all live on the same homelab.
func gatewayLANInfo(cfg *config.Config) (string, string) {
	if cfg == nil || cfg.Mode != "client" {
		return "", ""
	}
	for _, a := range cfg.Attachments {
		if a.IsGateway && a.LANNetwork != "" {
			return a.LANNetwork, a.LANIP
		}
	}
	return "", ""
}

func jitter(d time.Duration) time.Duration {
	delta := float64(d) * 0.25
	return d + time.Duration((rand.Float64()*2-1)*delta)
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

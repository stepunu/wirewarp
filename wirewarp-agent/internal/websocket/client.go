package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
)

const (
	heartbeatInterval = 30 * time.Second
	maxBackoff        = 60 * time.Second
	initialBackoff    = 1 * time.Second
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

	// Fetch public IP once per connection and report it immediately.
	publicIP := fetchPublicIP()

	heartbeat := func() map[string]string {
		h := map[string]string{
			"type":      "heartbeat",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   c.version,
		}
		if publicIP != "" {
			h["public_ip"] = publicIP
		}
		return h
	}

	// Send an initial heartbeat right away so public_ip is stored without waiting 30s.
	if err := send(heartbeat()); err != nil {
		return err
	}

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

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
			if err := send(heartbeat()); err != nil {
				return err
			}
		}
	}
}


// fetchPublicIP returns the machine's public IPv4 address.
// Returns empty string on failure — non-fatal, agent still connects.
func fetchPublicIP() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://icanhazip.com", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
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
